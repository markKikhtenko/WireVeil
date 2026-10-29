#!/usr/bin/env python3
"""Batch Mihomo/OpenClash subscription diagnostics.

The public report produced by this module is deliberately lossy: it keeps
provenance and diagnostic facts but never serialises proxy credentials.  Full
proxy dictionaries are retained only in memory for the explicit private YAML
export.
"""

from __future__ import annotations

import concurrent.futures
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

import yaml


SCHEMA_VERSION = 2
SOURCE_STORE_VERSION = 1
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_SOURCES = 200
MAX_NODES = 20_000
MAX_VALIDATION_CHECKS = 128
BASE_WORKERS_DEFAULT = 16
BASE_WORKERS_ALLOWED = (8, 16, 24)
SERVICE_WORKERS_MAX = 8
ENDPOINT_CONCURRENCY_MAX = 8
SUPPORTED_PROTOCOLS = frozenset(
    {"vless", "trojan", "ss", "vmess", "hysteria", "hysteria2", "tuic"}
)
BASE_TESTS = (
    ("gstatic", "https://www.gstatic.com/generate_204", "204"),
    ("cloudflare", "https://cp.cloudflare.com/generate_204", "204"),
)
DEFAULT_SERVICES = (
    "ChatGPT",
    "Instagram",
    "Spotify",
    "Telegram Web",
    "YouTube",
)


class MihomoCheckError(RuntimeError):
    """A safe, user-presentable checker failure."""

    def __init__(self, code: str, summary: str):
        super().__init__(summary)
        self.code = code
        self.summary = sanitize_text(summary)


@dataclass(frozen=True)
class ServiceDefinition:
    name: str
    key: str
    url: str
    expected: str


SERVICE_DEFINITIONS = (
    ServiceDefinition("ChatGPT", "chatgpt", "https://chatgpt.com/", "200-499"),
    ServiceDefinition("Instagram", "instagram", "https://www.instagram.com/", "200-399"),
    ServiceDefinition("Spotify", "spotify", "https://open.spotify.com/", "200-399"),
    ServiceDefinition("Telegram Web", "telegram", "https://web.telegram.org/", "200-399"),
    ServiceDefinition("YouTube", "youtube", "https://www.youtube.com/generate_204", "204"),
    ServiceDefinition("GitHub", "github", "https://github.com/", "200-399"),
    ServiceDefinition("Discord", "discord", "https://discord.com/app", "200-399"),
)
SERVICE_BY_NAME = {service.name: service for service in SERVICE_DEFINITIONS}
_ENDPOINT_LIMITERS: dict[str, threading.BoundedSemaphore] = {}
_ENDPOINT_LIMITERS_LOCK = threading.Lock()


def _endpoint_limiter(host: str) -> threading.BoundedSemaphore:
    with _ENDPOINT_LIMITERS_LOCK:
        return _ENDPOINT_LIMITERS.setdefault(
            host,
            threading.BoundedSemaphore(ENDPOINT_CONCURRENCY_MAX),
        )


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    name: str
    kind: str
    value: str
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def display(self) -> str:
        if self.kind == "url":
            return redact_url(self.value)
        if self.kind == "file":
            return sanitize_text(Path(self.value).name)
        return "Вставленный текст (содержимое скрыто)"


@dataclass(frozen=True)
class SourceIssue:
    error_code: str
    error_summary: str
    entry_index: int | None = None


@dataclass
class ParsedSource:
    spec: SourceSpec
    fetch_status: str = "not_started"
    parse_status: str = "not_started"
    total_entries: int = 0
    nodes: list["NodeRecord"] = field(default_factory=list)
    issues: list[SourceIssue] = field(default_factory=list)
    original_document: object | None = None
    checked_at: str | None = None
    download_bytes: int | None = None
    protocol_counts: dict[str, int] = field(default_factory=dict)

    @property
    def error_code(self) -> str | None:
        return self.issues[0].error_code if self.issues else None

    @property
    def error_summary(self) -> str | None:
        return self.issues[0].error_summary if self.issues else None


@dataclass
class NodeRecord:
    node_id: str
    runtime_name: str
    protocol: str
    server: str
    port: int | None
    proxy: dict[str, object] = field(repr=False)
    source_ids: list[str] = field(default_factory=list)
    source_original_names: dict[str, str] = field(default_factory=dict)
    supported: bool = True
    import_error_code: str | None = None
    import_error_summary: str | None = None


@dataclass(frozen=True)
class DelayResult:
    success: bool
    latency_ms: int | None = None
    error_code: str | None = None
    error_summary: str | None = None
    error_category: str | None = None
    controller_http_status: int | None = None


@dataclass(frozen=True)
class ServiceResult:
    status: str
    latency_ms: int | None = None
    http_status: int | None = None
    error_code: str | None = None
    error_summary: str | None = None
    error_category: str | None = None
    controller_http_status: int | None = None


@dataclass
class NodeResult:
    node: NodeRecord
    overall_status: str = "not_tested"
    base_successes: int = 0
    base_attempts: int = 0
    base_latency_ms: int | None = None
    base_error_code: str | None = None
    base_error_summary: str | None = None
    services: dict[str, ServiceResult] = field(default_factory=dict)
    error_code: str | None = None
    error_summary: str | None = None
    error_category: str | None = None
    base_endpoint_results: dict[str, list[DelayResult]] = field(default_factory=dict)


@dataclass
class BatchReport:
    generated_at: str
    engine_version: str
    direct_baseline: str
    selected_services: tuple[str, ...]
    attempts: int
    timeout_ms: int
    sources: list[ParsedSource]
    node_results: list[NodeResult]
    sampling: dict[str, object] = field(default_factory=dict)
    requested_workers: int = BASE_WORKERS_DEFAULT
    effective_workers: int = BASE_WORKERS_DEFAULT
    adaptive_events: list[dict[str, object]] = field(default_factory=list)
    mihomo_stderr_summary: str | None = None


@dataclass(frozen=True)
class ProgressUpdate:
    """Credential-safe progress event emitted by the batch pipeline."""

    stage: str
    processed: int
    total: int
    stage_elapsed_seconds: float
    total_elapsed_seconds: float
    overall_percent: float
    message: str
    rate_per_minute: float | None = None
    eta_low_seconds: float | None = None
    eta_high_seconds: float | None = None


STAGE_LABELS = {
    "loading": "Загрузка",
    "parsing": "Парсинг",
    "deduplication": "Дедупликация",
    "validation": "Валидация конфигураций",
    "runtime": "Запуск ядра",
    "https": "HTTPS-тестирование",
    "services": "Проверки сервисов",
    "completion": "Завершение",
}
STAGE_RANGES = {
    "loading": (0.0, 8.0),
    "parsing": (8.0, 18.0),
    "deduplication": (18.0, 23.0),
    "validation": (23.0, 40.0),
    "runtime": (40.0, 45.0),
    "https": (45.0, 78.0),
    "services": (78.0, 98.0),
    "completion": (98.0, 100.0),
}


class _ProgressReporter:
    """Throttle high-volume updates while retaining stage boundaries and counts."""

    def __init__(self, callback: Callable[[ProgressUpdate], None] | None):
        self.callback = callback
        self.started = time.monotonic()
        self.stage_started = self.started
        self.stage: str | None = None
        self.last_emit = 0.0
        self.last_processed = -1
        self._lock = threading.Lock()

    def emit(
        self,
        stage: str,
        processed: int,
        total: int,
        message: str,
        *,
        force: bool = False,
    ) -> None:
        if self.callback is None:
            return
        now = time.monotonic()
        with self._lock:
            changed_stage = stage != self.stage
            if changed_stage:
                self.stage = stage
                self.stage_started = now
                self.last_processed = -1
            processed = max(0, int(processed))
            total = max(0, int(total))
            interval = max(1, total // 100) if total else 1
            should_emit = (
                force
                or changed_stage
                or processed >= total
                or processed - self.last_processed >= interval
                or now - self.last_emit >= 0.5
            )
            if not should_emit:
                return
            start, end = STAGE_RANGES[stage]
            fraction = min(1.0, processed / total) if total else (1.0 if processed else 0.0)
            stage_elapsed = max(0.0, now - self.stage_started)
            rate_per_minute: float | None = None
            eta_low_seconds: float | None = None
            eta_high_seconds: float | None = None
            if stage in {"https", "services"} and processed >= 8 and stage_elapsed >= 1.0:
                rate_per_minute = (processed / stage_elapsed) * 60.0
                remaining = max(0, total - processed)
                estimate = (remaining / rate_per_minute) * 60.0 if rate_per_minute else 0.0
                # A range is intentionally shown instead of false precision while
                # node and service timeouts can vary by a full timeout interval.
                eta_low_seconds = estimate * 0.75
                eta_high_seconds = estimate * 1.35
            update = ProgressUpdate(
                stage=stage,
                processed=processed,
                total=total,
                stage_elapsed_seconds=round(stage_elapsed, 3),
                total_elapsed_seconds=round(now - self.started, 3),
                overall_percent=round(start + ((end - start) * fraction), 2),
                message=sanitize_text(message, 300),
                rate_per_minute=round(rate_per_minute, 1) if rate_per_minute else None,
                eta_low_seconds=round(eta_low_seconds, 1) if eta_low_seconds is not None else None,
                eta_high_seconds=round(eta_high_seconds, 1) if eta_high_seconds is not None else None,
            )
            self.last_emit = now
            self.last_processed = processed
        self.callback(update)


def new_source_id() -> str:
    return f"src-{uuid.uuid4().hex[:12]}"


def subscription_urls_from_text(text: str) -> list[str] | None:
    """Return a line-oriented HTTP(S) URL list, or None for ordinary text/YAML."""
    urls: list[str] = []
    for raw_line in text.splitlines():
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError:
            return None
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if any(character.isspace() for character in value):
            return None
        urls.append(value)
    return urls or None


def canonical_source_url(url: str) -> str:
    """Canonical form used only for duplicate detection, never for display."""
    try:
        parsed = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return url.strip()
    hostname = (parsed.hostname or "").casefold()
    try:
        port = parsed.port
    except ValueError:
        return url.strip()
    netloc = hostname
    if port and not (
        (parsed.scheme.casefold() == "https" and port == 443)
        or (parsed.scheme.casefold() == "http" and port == 80)
    ):
        netloc = f"{hostname}:{port}"
    return urllib.parse.urlunsplit(
        (parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, "")
    )


def source_name_from_url(url: str) -> str:
    """Build a useful label without exposing query strings or subscription tokens."""
    try:
        parsed = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return "Подписка"
    host = (parsed.hostname or "Подписка").casefold()
    parts = [urllib.parse.unquote(item) for item in parsed.path.split("/") if item]
    filename = sanitize_text(parts[-1], 80) if parts else "subscription.yaml"
    owner_repo: str | None = None
    if host == "raw.githubusercontent.com" and len(parts) >= 4:
        owner_repo = f"{parts[0]}/{parts[1]}"
    elif host in {"github.com", "www.github.com"} and len(parts) >= 2:
        owner_repo = f"{parts[0]}/{parts[1]}"
    elif host.endswith(".github.io"):
        owner = host.removesuffix(".github.io")
        repo = parts[0] if len(parts) >= 2 else owner + ".github.io"
        owner_repo = f"{owner}/{repo}"
    if owner_repo:
        return sanitize_text(f"{owner_repo} — {filename}", 160)
    return sanitize_text(f"{host} — {filename}", 160)


def _manifest_source_specs(path: Path, text: str) -> list[SourceSpec]:
    """Read a CSV manifest that explicitly declares a subscription_url column."""
    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error as exc:
        raise MihomoCheckError("CSV_PARSE_ERROR", "Не удалось разобрать CSV-каталог") from exc
    if not reader.fieldnames:
        raise MihomoCheckError("CSV_SUBSCRIPTION_URL_REQUIRED", "CSV не содержит заголовок")
    headers = {str(name).strip().casefold(): str(name) for name in reader.fieldnames if name}
    url_header = headers.get("subscription_url")
    if url_header is None:
        raise MihomoCheckError(
            "CSV_SUBSCRIPTION_URL_REQUIRED",
            "CSV-каталог должен содержать явную колонку subscription_url",
        )
    name_headers = tuple(
        headers[key]
        for key in ("source_name", "name", "label", "title")
        if key in headers
    )
    result: list[SourceSpec] = []
    try:
        rows = list(reader)
    except csv.Error as exc:
        raise MihomoCheckError("CSV_PARSE_ERROR", "Не удалось разобрать строки CSV-каталога") from exc
    for position, row in enumerate(rows, start=2):
        url = str(row.get(url_header) or "").strip()
        if not url or url.startswith("#"):
            continue
        if subscription_urls_from_text(url) is None:
            raise MihomoCheckError(
                "CSV_INVALID_SUBSCRIPTION_URL",
                f"Некорректный subscription_url в строке {position}",
            )
        explicit_name = next(
            (str(row.get(header) or "").strip() for header in name_headers if str(row.get(header) or "").strip()),
            "",
        )
        metadata = {
            str(key).strip(): str(value).strip()
            for key, value in row.items()
            if key and key != url_header and value is not None and str(value).strip()
        }
        metadata.setdefault("catalog_file", path.name)
        metadata.setdefault("catalog_row", str(position))
        result.append(
            SourceSpec(
                new_source_id(),
                explicit_name or source_name_from_url(url),
                "url",
                url,
                metadata,
            )
        )
    if not result:
        raise MihomoCheckError("CSV_EMPTY", "CSV-каталог не содержит URL подписок")
    return result


def source_specs_from_file(path: Path) -> list[SourceSpec]:
    """Expand TXT/CSV manifests, otherwise keep one local subscription source."""
    path = Path(path)
    file_source = SourceSpec(new_source_id(), path.stem, "file", str(path))
    suffix = path.suffix.casefold()
    if suffix not in {".txt", ".csv"}:
        return [file_source]
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise MihomoCheckError("SOURCE_TOO_LARGE", "Файл превышает лимит 5 МБ.")
        text = path.read_text(encoding="utf-8-sig")
    except MihomoCheckError:
        raise
    except UnicodeError:
        return [file_source]
    except OSError as exc:
        raise MihomoCheckError("SOURCE_READ_FAILED", f"Не удалось прочитать файл: {exc}") from exc

    if suffix == ".csv":
        return _manifest_source_specs(path, text)

    urls = subscription_urls_from_text(text)
    if urls is None:
        return [file_source]

    result: list[SourceSpec] = []
    for position, url in enumerate(urls, start=1):
        result.append(
            SourceSpec(
                new_source_id(),
                source_name_from_url(url),
                "url",
                url,
                {"import_file": path.name, "import_line": str(position)},
            )
        )
    return result


_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_URL_RE = re.compile(r"https?://[^\s\]\[<>'\"]+", re.IGNORECASE)
_LONG_SECRET_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_\-+/=]{24,}(?![A-Za-z0-9])")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*(?:PRIVATE|SECRET)[^-]*-----.*?-----END [^-]+-----",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)\b(password|passwd|uuid|private[-_ ]?key|token|secret|authorization|auth)\b"
    r"(\s*[:=]\s*|\s+)([^,;\s}\]]+|\"[^\"]*\"|'[^']*')"
)


def redact_url(value: str) -> str:
    """Return a stable display form without path/query credentials."""
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        host = parsed.hostname or "<invalid>"
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme.lower()}://{host}{port}/<redacted>"
    except (ValueError, TypeError):
        return "<redacted-url>"


def sanitize_text(value: object, limit: int = 500) -> str:
    """Strip common credential shapes from untrusted labels and errors."""
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = _PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
    text = _SENSITIVE_FIELD_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", text)
    text = _URL_RE.sub(lambda match: redact_url(match.group(0)), text)
    text = _UUID_RE.sub("<redacted-uuid>", text)
    text = _LONG_SECRET_RE.sub("<redacted-token>", text)
    return text[:limit]


def canonical_proxy(proxy: Mapping[str, object]) -> str:
    """Canonicalise every connection parameter except the cosmetic name."""
    def normalise(value: object) -> object:
        if isinstance(value, Mapping):
            return {
                str(key): normalise(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        if isinstance(value, (list, tuple)):
            return [normalise(item) for item in value]
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return str(value)

    payload = normalise({key: value for key, value in proxy.items() if key != "name"})
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda value: str(value),
    )


def proxy_node_id(proxy: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_proxy(proxy).encode("utf-8")).hexdigest()


def _safe_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _node_from_proxy(proxy: Mapping[str, object], spec: SourceSpec, index: int) -> NodeRecord:
    copied = dict(proxy)
    node_id = proxy_node_id(copied)
    protocol = str(copied.get("type", "")).strip().lower()
    server = str(copied.get("server", "")).strip()
    port = _safe_port(copied.get("port"))
    original_name = sanitize_text(copied.get("name") or f"Узел {index + 1}", 160)
    supported = protocol in SUPPORTED_PROTOCOLS
    code = None
    summary = None
    if not protocol:
        supported = False
        code, summary = "INVALID_NODE", "Не задан тип прокси"
    elif not supported:
        code, summary = "UNSUPPORTED_PROTOCOL", f"Протокол {sanitize_text(protocol, 40)} не поддерживается"
    elif not server or port is None:
        supported = False
        code, summary = "INVALID_NODE", "Не заданы корректные server и port"
    return NodeRecord(
        node_id=node_id,
        runtime_name=f"wv-{node_id[:16]}",
        protocol=protocol or "unknown",
        server=server,
        port=port,
        proxy=copied,
        source_ids=[spec.source_id],
        source_original_names={spec.source_id: original_name},
        supported=supported,
        import_error_code=code,
        import_error_summary=summary,
    )


def parse_source_text(spec: SourceSpec, text: str) -> ParsedSource:
    result = ParsedSource(spec=spec, fetch_status="ok")
    result.download_bytes = len(text.encode("utf-8", errors="ignore"))
    if not text.strip():
        result.parse_status = "failed"
        result.issues.append(SourceIssue("PARSE_ERROR", "Источник пуст"))
        return result
    if len(text.encode("utf-8", errors="ignore")) > MAX_SOURCE_BYTES:
        result.parse_status = "failed"
        result.issues.append(SourceIssue("SOURCE_TOO_LARGE", "Источник превышает лимит 5 МБ"))
        return result
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        result.parse_status = "failed"
        mark = getattr(exc, "problem_mark", None)
        location = (
            f" (строка {int(mark.line) + 1}, столбец {int(mark.column) + 1})"
            if mark is not None
            else ""
        )
        result.issues.append(SourceIssue("PARSE_ERROR", f"Некорректный YAML{location}"))
        return result
    result.original_document = document
    if not isinstance(document, dict):
        result.parse_status = "unsupported"
        result.issues.append(
            SourceIssue(
                "UNSUPPORTED_FORMAT",
                "Требуется Mihomo/Clash YAML с корневым списком proxies",
            )
        )
        return result
    proxies = document.get("proxies")
    if proxies is None and document.get("proxy-providers"):
        result.parse_status = "unsupported"
        result.issues.append(
            SourceIssue(
                "EXTERNAL_PROVIDER_NOT_EXPANDED",
                "Внешние proxy-providers без встроенного proxies не разворачиваются",
            )
        )
        return result
    if not isinstance(proxies, list):
        result.parse_status = "unsupported"
        result.issues.append(
            SourceIssue(
                "UNSUPPORTED_FORMAT",
                "Требуется Mihomo/Clash YAML с корневым списком proxies",
            )
        )
        return result
    if len(proxies) > MAX_NODES:
        result.parse_status = "failed"
        result.issues.append(SourceIssue("TOO_MANY_NODES", "Источник содержит более 20000 узлов"))
        return result
    result.total_entries = len(proxies)
    for index, proxy in enumerate(proxies):
        if not isinstance(proxy, dict):
            result.issues.append(SourceIssue("INVALID_NODE", "Запись прокси не является объектом", index))
            continue
        if not all(isinstance(key, str) for key in proxy):
            result.issues.append(SourceIssue("INVALID_NODE", "Ключи параметров прокси должны быть строками", index))
            continue
        node = _node_from_proxy(proxy, spec, index)
        result.nodes.append(node)
        result.protocol_counts[node.protocol] = result.protocol_counts.get(node.protocol, 0) + 1
        if not node.supported:
            result.issues.append(
                SourceIssue(node.import_error_code or "INVALID_NODE", node.import_error_summary or "Некорректный узел", index)
            )
    result.parse_status = "ok" if not result.issues else "partial"
    return result


def _is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_subscription_url(url: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise MihomoCheckError("UNSAFE_SOURCE_URL", "Некорректный URL источника") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise MihomoCheckError("UNSAFE_SOURCE_URL", "Разрешены только URL http/https")
    if parsed.username or parsed.password:
        raise MihomoCheckError("UNSAFE_SOURCE_URL", "Учётные данные в authority URL запрещены")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except ValueError as exc:
        raise MihomoCheckError("UNSAFE_SOURCE_URL", "Некорректный порт URL источника") from exc
    except OSError as exc:
        raise MihomoCheckError("DNS_ERROR", "Не удалось разрешить адрес источника") from exc
    if not addresses or any(not _is_public_ip(item[4][0]) for item in addresses):
        raise MihomoCheckError(
            "UNSAFE_SOURCE_URL",
            "Источник разрешается в локальный, служебный или небезопасный адрес",
        )


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        validate_subscription_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_source_url(url: str, timeout: float = 15.0) -> str:
    validate_subscription_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SafeRedirectHandler())
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "WireVeilChecker/1.0", "Accept": "application/yaml,text/yaml,text/plain,*/*"},
    )
    try:
        host = (urllib.parse.urlsplit(url).hostname or "unknown").casefold()
        with _endpoint_limiter("source:" + host):
            with opener.open(request, timeout=timeout) as response:
                size_header = response.headers.get("Content-Length")
                if size_header and int(size_header) > MAX_SOURCE_BYTES:
                    raise MihomoCheckError("SOURCE_TOO_LARGE", "Источник превышает лимит 5 МБ")
                raw = response.read(MAX_SOURCE_BYTES + 1)
    except MihomoCheckError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise MihomoCheckError("SOURCE_FETCH_FAILED", sanitize_text(exc)) from exc
    if len(raw) > MAX_SOURCE_BYTES:
        raise MihomoCheckError("SOURCE_TOO_LARGE", "Источник превышает лимит 5 МБ")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MihomoCheckError("PARSE_ERROR", "Источник не является UTF-8 текстом") from exc


def read_source_text(spec: SourceSpec, *, fetch_timeout: float = 15.0) -> str:
    """Load source bytes without parsing so the two stages can be observed separately."""
    if spec.kind == "url":
        return fetch_source_url(spec.value, timeout=fetch_timeout)
    if spec.kind == "file":
        path = Path(spec.value)
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise MihomoCheckError("SOURCE_TOO_LARGE", "Источник превышает лимит 5 МБ")
        return path.read_text(encoding="utf-8-sig")
    if spec.kind == "text":
        return spec.value
    raise MihomoCheckError("UNSUPPORTED_FORMAT", "Неизвестный тип источника")


def load_source(spec: SourceSpec, *, fetch_timeout: float = 15.0) -> ParsedSource:
    try:
        text = read_source_text(spec, fetch_timeout=fetch_timeout)
    except MihomoCheckError as exc:
        return ParsedSource(
            spec=spec,
            fetch_status="failed",
            parse_status="not_started",
            issues=[SourceIssue(exc.code, exc.summary)],
        )
    except (OSError, UnicodeError) as exc:
        return ParsedSource(
            spec=spec,
            fetch_status="failed",
            parse_status="not_started",
            issues=[SourceIssue("SOURCE_FETCH_FAILED", sanitize_text(exc))],
        )
    return parse_source_text(spec, text)


def merge_nodes(
    parsed_sources: Sequence[ParsedSource],
    *,
    cancel_event: threading.Event | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> list[NodeRecord]:
    merged: dict[str, NodeRecord] = {}
    total = sum(len(parsed.nodes) for parsed in parsed_sources)
    processed = 0
    for parsed in parsed_sources:
        for candidate in parsed.nodes:
            if cancel_event is not None and cancel_event.is_set():
                return list(merged.values())
            current = merged.get(candidate.node_id)
            if current is None:
                merged[candidate.node_id] = candidate
            else:
                if candidate.source_ids[0] not in current.source_ids:
                    current.source_ids.append(candidate.source_ids[0])
                current.source_original_names.update(candidate.source_original_names)
            processed += 1
            if progress_callback is not None:
                progress_callback(processed, total)
    return list(merged.values())


def representative_sample(
    nodes: Sequence[NodeRecord],
    *,
    limit: int | None,
    seed: str,
    per_source_limit: int | None = None,
) -> tuple[list[NodeRecord], dict[str, object]]:
    """Select unique nodes round-robin across sources and protocols.

    The score is deterministic for a given seed and canonical node id.  That
    makes diagnostics reproducible without always privileging the first feed.
    """
    supported = [node for node in nodes if node.supported]
    source_ids = sorted({source_id for node in supported for source_id in node.source_ids})
    effective_limit = len(supported) if limit is None else min(limit, len(supported))
    if per_source_limit is not None:
        effective_limit = min(
            effective_limit if limit is not None else len(supported),
            per_source_limit * max(1, len(source_ids)),
        )

    def score(node: NodeRecord) -> str:
        return hashlib.sha256(f"{seed}:{node.node_id}".encode("utf-8")).hexdigest()

    buckets: dict[str, dict[str, list[NodeRecord]]] = {}
    for source_id in source_ids:
        source_nodes = [node for node in supported if source_id in node.source_ids]
        for node in source_nodes:
            buckets.setdefault(source_id, {}).setdefault(node.protocol, []).append(node)
    for protocol_buckets in buckets.values():
        for candidates in protocol_buckets.values():
            candidates.sort(key=score)

    selected: list[NodeRecord] = []
    selected_ids: set[str] = set()
    assigned_by_source = {source_id: 0 for source_id in source_ids}
    protocol_cursor = {source_id: 0 for source_id in source_ids}
    candidate_cursor: dict[tuple[str, str], int] = {}

    while len(selected) < effective_limit:
        made_progress = False
        for source_id in source_ids:
            if len(selected) >= effective_limit:
                break
            if per_source_limit is not None and assigned_by_source[source_id] >= per_source_limit:
                continue
            protocols = sorted(buckets.get(source_id, {}))
            if not protocols:
                continue
            for offset in range(len(protocols)):
                protocol_index = (protocol_cursor[source_id] + offset) % len(protocols)
                protocol = protocols[protocol_index]
                candidates = buckets[source_id][protocol]
                cursor_key = (source_id, protocol)
                cursor = candidate_cursor.get(cursor_key, 0)
                while cursor < len(candidates) and candidates[cursor].node_id in selected_ids:
                    cursor += 1
                candidate_cursor[cursor_key] = cursor
                if cursor >= len(candidates):
                    continue
                node = candidates[cursor]
                candidate_cursor[cursor_key] = cursor + 1
                protocol_cursor[source_id] = (protocol_index + 1) % len(protocols)
                selected.append(node)
                selected_ids.add(node.node_id)
                assigned_by_source[source_id] += 1
                made_progress = True
                break
        if not made_progress:
            break

    if len(selected) < effective_limit and per_source_limit is None:
        remaining = sorted(
            (node for node in supported if node.node_id not in selected_ids),
            key=lambda node: (node.protocol, score(node)),
        )
        selected.extend(remaining[: effective_limit - len(selected)])
        selected_ids.update(node.node_id for node in selected)

    per_source_selected = {
        source_id: sum(source_id in node.source_ids for node in selected)
        for source_id in source_ids
    }
    per_protocol_selected: dict[str, int] = {}
    for node in selected:
        per_protocol_selected[node.protocol] = per_protocol_selected.get(node.protocol, 0) + 1
    metadata: dict[str, object] = {
        "strategy": "source_protocol_round_robin_v1" if limit is not None or per_source_limit is not None else "full",
        "seed": sanitize_text(seed, 80),
        "requested_limit": limit,
        "per_source_limit": per_source_limit,
        "eligible_nodes": len(supported),
        "selected_nodes": len(selected),
        "per_source_selected": per_source_selected,
        "per_protocol_selected": per_protocol_selected,
    }
    return selected, metadata


def _runtime_config(nodes: Sequence[NodeRecord], controller_port: int, secret: str) -> dict[str, object]:
    proxies: list[dict[str, object]] = []
    runtime_names: list[str] = []
    for node in nodes:
        proxy = dict(node.proxy)
        proxy["name"] = node.runtime_name
        proxies.append(proxy)
        runtime_names.append(node.runtime_name)
    return {
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "external-controller": f"127.0.0.1:{controller_port}",
        "secret": secret,
        "proxies": proxies,
        "proxy-groups": [{"name": "WIREVEIL", "type": "select", "proxies": runtime_names or ["DIRECT"]}],
        "rules": ["MATCH,WIREVEIL"],
    }


def _hidden_process_options() -> dict[str, object]:
    if os.name != "nt":
        return {}
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _terminate_process(process: subprocess.Popen[str]) -> None:
    """Best-effort termination for a child process created by this checker."""
    try:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except (OSError, subprocess.SubprocessError):
        pass


def _check_config(
    binary: Path,
    config_path: Path,
    timeout: float = 30.0,
    *,
    cancel_event: threading.Event | None = None,
    process_callback: Callable[[subprocess.Popen[str] | None], None] | None = None,
) -> tuple[bool, str]:
    process: subprocess.Popen[str] | None = None
    if cancel_event is not None and cancel_event.is_set():
        return False, "CANCELLED"
    try:
        process = subprocess.Popen(
            [str(binary), "-d", str(config_path.parent), "-t", "-f", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_hidden_process_options(),
        )
        if process_callback is not None:
            process_callback(process)
        deadline = time.monotonic() + timeout
        while True:
            if cancel_event is not None and cancel_event.is_set():
                _terminate_process(process)
                return False, "CANCELLED"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(process)
                return False, "TIMEOUT"
            try:
                stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                detail = sanitize_text((stdout or "") + " " + (stderr or ""), 800)
                return process.returncode == 0, detail
            except subprocess.TimeoutExpired:
                continue
    except OSError as exc:
        return False, sanitize_text(exc)
    finally:
        if process_callback is not None and process is not None:
            process_callback(None)


def _write_private_yaml(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(
        yaml.safe_dump(dict(payload), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass


def validate_runtime_nodes(
    binary: Path,
    nodes: Sequence[NodeRecord],
    *,
    cancel_event: threading.Event | None = None,
    process_callback: Callable[[subprocess.Popen[str] | None], None] | None = None,
    progress_callback: Callable[[int, int, int, str], None] | None = None,
    max_checks: int = MAX_VALIDATION_CHECKS,
) -> tuple[list[NodeRecord], list[NodeResult]]:
    """Locate config-rejected nodes by recursively splitting failed batches.

    A single invalid node in a large subscription takes O(log n) Mihomo checks.
    A hard check budget prevents a generally broken configuration from spawning
    thousands of child processes. Unresolved nodes remain visible as not tested.
    """
    if not binary.is_file():
        raise MihomoCheckError("MIHOMO_NOT_FOUND", f"Не найден Mihomo: {binary.name}")
    if not nodes:
        return [], []
    if max_checks < 1:
        raise ValueError("max_checks must be positive")

    all_nodes = list(nodes)
    position = {node.node_id: index for index, node in enumerate(all_nodes)}
    accepted: list[NodeRecord] = []
    results: list[NodeResult] = []

    def add_unresolved(items: Sequence[NodeRecord], code: str, summary: str) -> None:
        existing = {item.node.node_id for item in results}
        existing.update(item.node_id for item in accepted)
        for item in items:
            if item.node_id in existing:
                continue
            results.append(
                NodeResult(
                    node=item,
                    overall_status="not_tested",
                    error_code=code,
                    error_summary=summary,
                    error_category=error_category_for_code(code),
                )
            )
            existing.add(item.node_id)

    def notify(checks: int, message: str) -> None:
        if progress_callback is not None:
            progress_callback(len(accepted) + len(results), len(all_nodes), checks, message)

    with tempfile.TemporaryDirectory(prefix="wireveil-mihomo-validate-") as name:
        root = Path(name)
        pending: list[list[NodeRecord]] = [all_nodes]
        checks = 0
        checked_base_config = False
        while pending:
            if cancel_event is not None and cancel_event.is_set():
                add_unresolved(
                    [item for batch in pending for item in batch],
                    "CANCELLED",
                    "Валидация остановлена пользователем",
                )
                notify(checks, "Валидация остановлена; необработанные узлы сохранены")
                break
            batch = pending.pop()
            if checks >= max_checks:
                add_unresolved(
                    [*batch, *(item for queued in pending for item in queued)],
                    "MIHOMO_VALIDATION_LIMIT",
                    "Достигнут безопасный предел проверок конфигурации",
                )
                notify(checks, "Достигнут предел запусков валидации; остаток не тестировался")
                break

            checks += 1
            path = root / f"batch-{checks}.yaml"
            _write_private_yaml(
                path,
                _runtime_config(batch, _free_local_port(), secrets.token_urlsafe(32)),
            )
            if cancel_event is not None and cancel_event.is_set():
                checks -= 1
                add_unresolved(
                    [*batch, *(item for queued in pending for item in queued)],
                    "CANCELLED",
                    "Валидация остановлена пользователем",
                )
                notify(checks, "Валидация остановлена после подготовки пакета")
                break
            notify(checks, f"Проверка пакета из {len(batch)} узлов; запусков Mihomo: {checks}")
            valid, detail = _check_config(
                binary,
                path,
                cancel_event=cancel_event,
                process_callback=process_callback,
            )
            if cancel_event is not None and cancel_event.is_set():
                add_unresolved(
                    [*batch, *(item for queued in pending for item in queued)],
                    "CANCELLED",
                    "Валидация остановлена пользователем",
                )
                notify(checks, "Дочерний процесс валидации остановлен")
                break
            if valid:
                accepted.extend(batch)
                notify(checks, f"Пакет из {len(batch)} узлов принят")
                continue

            if detail == "TIMEOUT":
                add_unresolved(
                    [*batch, *(item for queued in pending for item in queued)],
                    "MIHOMO_CONFIG_TIMEOUT",
                    "Mihomo не завершил проверку конфигурации за отведённое время",
                )
                notify(checks, "Валидация конфигурации превысила тайм-аут")
                break

            if not checked_base_config:
                checked_base_config = True
                if checks >= max_checks:
                    add_unresolved(
                        [*batch, *(item for queued in pending for item in queued)],
                        "MIHOMO_VALIDATION_LIMIT",
                        "Достигнут безопасный предел проверок конфигурации",
                    )
                    break
                checks += 1
                base_path = root / "base.yaml"
                _write_private_yaml(
                    base_path,
                    _runtime_config((), _free_local_port(), secrets.token_urlsafe(32)),
                )
                base_valid, _base_detail = _check_config(
                    binary,
                    base_path,
                    cancel_event=cancel_event,
                    process_callback=process_callback,
                )
                if cancel_event is not None and cancel_event.is_set():
                    add_unresolved(
                        [*batch, *(item for queued in pending for item in queued)],
                        "CANCELLED",
                        "Валидация остановлена пользователем",
                    )
                    break
                if not base_valid:
                    add_unresolved(
                        [*batch, *(item for queued in pending for item in queued)],
                        "MIHOMO_COMMON_CONFIG_REJECTED",
                        "Mihomo отклонил базовую конфигурацию без узлов",
                    )
                    notify(checks, "Базовая конфигурация отклонена; деление пакета остановлено")
                    break

            if len(batch) == 1:
                results.append(
                    NodeResult(
                        node=batch[0],
                        overall_status="not_tested",
                        error_code="MIHOMO_CONFIG_REJECTED",
                        error_summary="Mihomo отклонил параметры этого узла",
                        error_category="invalid_configuration",
                    )
                )
                notify(checks, "Локализован узел с отклонённой конфигурацией")
                continue

            middle = len(batch) // 2
            # Stack is LIFO: enqueue the right half first to preserve source order.
            pending.append(batch[middle:])
            pending.append(batch[:middle])
            notify(checks, f"Невалидный пакет из {len(batch)} узлов разделён пополам")

    accepted.sort(key=lambda item: position[item.node_id])
    results.sort(key=lambda item: position[item.node.node_id])
    return accepted, results


class MihomoRuntime:
    """A single isolated Mihomo process shared by all node probes."""

    def __init__(
        self,
        binary: Path,
        nodes: Sequence[NodeRecord],
        *,
        cancel_event: threading.Event | None = None,
        validation_process_callback: Callable[[subprocess.Popen[str] | None], None] | None = None,
    ):
        self.binary = binary
        self.nodes = tuple(nodes)
        self.cancel_event = cancel_event
        self.validation_process_callback = validation_process_callback
        self.port = _free_local_port()
        self.secret = secrets.token_urlsafe(32)
        self.process: subprocess.Popen[str] | None = None
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._log_handle: io.TextIOWrapper | None = None
        self._log_path: Path | None = None
        self._stop_lock = threading.Lock()
        self.version = "unknown"
        self.log_summary: str | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _request(self, path: str, timeout: float = 2.0) -> bytes:
        request = urllib.request.Request(
            self.base_url + path,
            headers={"Authorization": f"Bearer {self.secret}"},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
            return response.read(64 * 1024)

    def start(self) -> None:
        if not self.binary.is_file():
            raise MihomoCheckError("MIHOMO_NOT_FOUND", f"Не найден Mihomo: {self.binary.name}")
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise MihomoCheckError("CANCELLED", "Запуск Mihomo отменён")
        self._temporary = tempfile.TemporaryDirectory(prefix="wireveil-mihomo-")
        root = Path(self._temporary.name)
        config_path = root / "config.yaml"
        log_path = root / "mihomo.log"
        self._log_path = log_path
        _write_private_yaml(config_path, _runtime_config(self.nodes, self.port, self.secret))
        valid, detail = _check_config(
            self.binary,
            config_path,
            cancel_event=self.cancel_event,
            process_callback=self.validation_process_callback,
        )
        if not valid:
            self.stop()
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise MihomoCheckError("CANCELLED", "Запуск Mihomo отменён")
            if detail == "TIMEOUT":
                raise MihomoCheckError(
                    "MIHOMO_CONFIG_TIMEOUT",
                    "Mihomo не завершил проверку конфигурации за отведённое время",
                )
            raise MihomoCheckError("MIHOMO_CONFIG_REJECTED", detail or "Mihomo отклонил конфигурацию")
        if self.cancel_event is not None and self.cancel_event.is_set():
            self.stop()
            raise MihomoCheckError("CANCELLED", "Запуск Mihomo отменён")
        self._log_handle = log_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(
                [str(self.binary), "-d", str(root), "-f", str(config_path)],
                stdout=self._log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                **_hidden_process_options(),
            )
        except OSError as exc:
            self.stop()
            raise MihomoCheckError("MIHOMO_START_FAILED", sanitize_text(exc)) from exc
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.cancel_event is not None and self.cancel_event.is_set():
                self.stop()
                raise MihomoCheckError("CANCELLED", "Запуск Mihomo отменён")
            process = self.process
            if process is None or process.poll() is not None:
                self.stop()
                raise MihomoCheckError("MIHOMO_START_FAILED", "Процесс Mihomo завершился при запуске")
            try:
                payload = json.loads(self._request("/version").decode("utf-8"))
                version = payload.get("version") if isinstance(payload, dict) else None
                self.version = sanitize_text(version, 160) if version else "unknown"
                return
            except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
                time.sleep(0.1)
        self.stop()
        raise MihomoCheckError("MIHOMO_START_FAILED", "Локальный API Mihomo не запустился")

    def stop(self) -> None:
        with self._stop_lock:
            process = self.process
            self.process = None
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if self._log_handle is not None:
                self._log_handle.close()
                self._log_handle = None
            if self._log_path is not None and self._log_path.is_file():
                try:
                    raw_log = self._log_path.read_text(encoding="utf-8", errors="replace")[-50_000:]
                    self.log_summary = sanitize_text(raw_log, 8_000) or None
                except OSError:
                    self.log_summary = None
            self._log_path = None
            if self._temporary is not None:
                self._temporary.cleanup()
                self._temporary = None

    def __enter__(self) -> "MihomoRuntime":
        self.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.stop()


def error_category_for_code(code: str | None) -> str | None:
    if not code:
        return None
    if code.startswith("CONTROLLER_") or code.startswith("MIHOMO_START"):
        return "controller_api"
    if code in {"TIMEOUT", "DNS_ERROR", "PROXY_CONNECT_FAILED", "TLS_ERROR", "HTTPS_CHECK_FAILED", "UNSTABLE_BASE_HTTPS"}:
        return "network"
    if code.startswith("MIHOMO_") or code in {"INVALID_NODE", "PARSE_ERROR"}:
        return "invalid_configuration"
    if code in {"UNSUPPORTED_PROTOCOL", "UNSUPPORTED_FORMAT", "EXTERNAL_PROVIDER_NOT_EXPANDED"}:
        return "unsupported"
    if code in {"SITE_HTTP_STATUS", "SITE_PARTIAL"}:
        return "target_service"
    if code in {"SAMPLE_LIMIT", "QUICK_CHECK_LIMIT", "CANCELLED", "NOT_TESTED"}:
        return "not_tested"
    return "other"


def classify_probe_error(exc: BaseException) -> tuple[str, str]:
    lowered = str(exc).lower()
    detail = sanitize_text(exc)
    if isinstance(exc, TimeoutError) or "timeout" in lowered or "deadline" in lowered:
        return "TIMEOUT", "Истекло время HTTPS-проверки"
    if "tls" in lowered or "certificate" in lowered or "x509" in lowered:
        return "TLS_ERROR", "Ошибка TLS при HTTPS-проверке"
    if "dns" in lowered or "no such host" in lowered or "name resolution" in lowered:
        return "DNS_ERROR", "Ошибка DNS при HTTPS-проверке"
    if "connection refused" in lowered or "connect" in lowered:
        return "PROXY_CONNECT_FAILED", "Прокси не установил HTTPS-соединение"
    return "HTTPS_CHECK_FAILED", detail or "HTTPS-проверка завершилась ошибкой"


def api_delay(
    runtime: MihomoRuntime,
    node: NodeRecord,
    *,
    url: str,
    timeout_ms: int,
    expected: str,
) -> DelayResult:
    query = urllib.parse.urlencode({"url": url, "timeout": timeout_ms, "expected": expected})
    path = f"/proxies/{urllib.parse.quote(node.runtime_name, safe='')}/delay?{query}"
    host = (urllib.parse.urlsplit(url).hostname or "unknown").casefold()
    limiter = _endpoint_limiter(host)
    try:
        with limiter:
            payload = json.loads(
                runtime._request(path, timeout=(timeout_ms / 1000) + 3).decode("utf-8")
            )
        delay = int(payload["delay"])
        if delay < 0:
            raise ValueError("invalid delay")
        return DelayResult(True, delay)
    except urllib.error.HTTPError as exc:
        status = int(getattr(exc, "code", 0) or 0)
        code = "CONTROLLER_API_503" if status == 503 else "CONTROLLER_API_ERROR"
        summary = (
            "Локальный API Mihomo не смог выполнить upstream-проверку (HTTP 503)"
            if status == 503
            else f"Локальный API Mihomo вернул HTTP {status or 'ошибку'}"
        )
        return DelayResult(
            False,
            error_code=code,
            error_summary=summary,
            error_category="controller_api",
            controller_http_status=status or None,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError, urllib.error.URLError) as exc:
        code, summary = classify_probe_error(exc)
        return DelayResult(
            False,
            error_code=code,
            error_summary=summary,
            error_category=error_category_for_code(code),
        )


def _probe_base_node(
    runtime: MihomoRuntime,
    node: NodeRecord,
    *,
    attempts: int,
    timeout_ms: int,
    cancel_event: threading.Event,
    minimum_successes: int | None = None,
) -> NodeResult:
    result = NodeResult(node=node, base_attempts=attempts)
    required_successes = attempts if minimum_successes is None else max(1, minimum_successes)
    if cancel_event.is_set():
        result.error_code = "CANCELLED"
        result.error_summary = "Проверка отменена"
        return result
    delays: list[int] = []
    base_errors: list[DelayResult] = []
    for attempt in range(attempts):
        if cancel_event.is_set():
            result.base_successes = len(delays)
            if delays:
                result.base_latency_ms = round(statistics.median(delays))
            result.overall_status = "not_tested"
            result.error_code = "CANCELLED"
            result.error_summary = "Проверка отменена"
            return result
        endpoint_key, url, expected = BASE_TESTS[attempt % len(BASE_TESTS)]
        probe = api_delay(runtime, node, url=url, timeout_ms=timeout_ms, expected=expected)
        result.base_endpoint_results.setdefault(endpoint_key, []).append(probe)
        if probe.success and probe.latency_ms is not None:
            delays.append(probe.latency_ms)
        else:
            base_errors.append(probe)
    result.base_successes = len(delays)
    if delays:
        result.base_latency_ms = round(statistics.median(delays))
    if len(delays) != attempts:
        first = base_errors[0] if base_errors else DelayResult(False, error_code="HTTPS_CHECK_FAILED")
        if len(delays) >= required_successes:
            result.base_error_code = "UNSTABLE_BASE_HTTPS"
            result.base_error_summary = f"Нестабильный базовый HTTPS: {len(delays)}/{attempts}"
            result.error_category = "network"
        else:
            result.overall_status = "failed"
            result.base_error_code = first.error_code or "HTTPS_CHECK_FAILED"
            result.base_error_summary = first.error_summary or "Не все HTTPS-прогоны успешны"
            result.error_code = result.base_error_code
            result.error_summary = result.base_error_summary
            result.error_category = first.error_category or error_category_for_code(result.error_code)
            return result
    return result


def _probe_services_node(
    runtime: MihomoRuntime,
    result: NodeResult,
    *,
    services: Sequence[ServiceDefinition],
    timeout_ms: int,
    cancel_event: threading.Event,
    service_step_callback: Callable[[], None] | None = None,
) -> NodeResult:
    failed_services: list[str] = []
    for service in services:
        if cancel_event.is_set():
            result.overall_status = "not_tested"
            result.error_code = "CANCELLED"
            result.error_summary = "Проверка отменена"
            return result
        probe = api_delay(
            runtime,
            result.node,
            url=service.url,
            timeout_ms=timeout_ms,
            expected=service.expected,
        )
        if probe.success:
            result.services[service.name] = ServiceResult("reachable", probe.latency_ms)
        else:
            failed_services.append(service.name)
            result.services[service.name] = ServiceResult(
                "failed",
                error_code=probe.error_code,
                error_summary=probe.error_summary,
                error_category=probe.error_category or error_category_for_code(probe.error_code),
                controller_http_status=probe.controller_http_status,
            )
        if service_step_callback is not None:
            service_step_callback()
    if failed_services:
        result.overall_status = "partial"
        result.error_code = "SITE_PARTIAL"
        result.error_summary = sanitize_text("Недоступны: " + ", ".join(failed_services))
        result.error_category = "target_service"
    elif result.base_successes < result.base_attempts:
        result.overall_status = "partial"
        result.error_code = "UNSTABLE_BASE_HTTPS"
        result.error_summary = f"Нестабильный базовый HTTPS: {result.base_successes}/{result.base_attempts}"
        result.error_category = "network"
    else:
        result.overall_status = "good"
    return result


def _probe_node(
    runtime: MihomoRuntime,
    node: NodeRecord,
    *,
    services: Sequence[ServiceDefinition],
    attempts: int,
    timeout_ms: int,
    cancel_event: threading.Event,
) -> NodeResult:
    """Compatibility wrapper for a complete single-node probe."""
    result = _probe_base_node(
        runtime,
        node,
        attempts=attempts,
        timeout_ms=timeout_ms,
        cancel_event=cancel_event,
    )
    if result.base_successes != attempts or cancel_event.is_set():
        return result
    return _probe_services_node(
        runtime,
        result,
        services=services,
        timeout_ms=timeout_ms,
        cancel_event=cancel_event,
    )


def _run_base_probes_adaptive(
    runtime: MihomoRuntime,
    nodes: Sequence[NodeRecord],
    *,
    attempts: int,
    timeout_ms: int,
    workers: int,
    minimum_successes: int,
    cancel_event: threading.Event,
    progress_callback: Callable[[int, int, int], None] | None = None,
) -> tuple[list[NodeResult], int, list[dict[str, object]]]:
    """Run a bounded queue and reduce concurrency after an early failure storm."""
    if not nodes:
        return [], workers, []
    effective_workers = min(workers, len(nodes))
    current_limit = effective_workers
    adaptive_events: list[dict[str, object]] = []
    results: list[NodeResult] = []
    timeout_like = 0
    observed = 0
    iterator = iter(nodes)
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, effective_workers),
        thread_name_prefix="wireveil-mihomo-https",
    )
    active: dict[concurrent.futures.Future[NodeResult], NodeRecord] = {}

    def submit_one() -> bool:
        if cancel_event.is_set():
            return False
        try:
            node = next(iterator)
        except StopIteration:
            return False
        future = executor.submit(
            _probe_base_node,
            runtime,
            node,
            attempts=attempts,
            timeout_ms=timeout_ms,
            cancel_event=cancel_event,
            minimum_successes=minimum_successes,
        )
        active[future] = node
        return True

    try:
        while len(active) < current_limit and submit_one():
            pass
        while active:
            completed, _pending = concurrent.futures.wait(
                tuple(active), return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in completed:
                node = active.pop(future)
                if future.cancelled():
                    continue
                try:
                    result = future.result()
                except Exception as exc:  # isolate one worker failure
                    code, summary = classify_probe_error(exc)
                    result = NodeResult(
                        node,
                        overall_status="failed",
                        error_code=code,
                        error_summary=summary,
                        error_category=error_category_for_code(code),
                    )
                results.append(result)
                observed += 1
                failure_codes = {
                    item.error_code
                    for endpoint_results in result.base_endpoint_results.values()
                    for item in endpoint_results
                    if not item.success
                }
                if failure_codes & {"TIMEOUT", "PROXY_CONNECT_FAILED", "CONTROLLER_API_503"}:
                    timeout_like += 1
                if progress_callback is not None:
                    progress_callback(len(results), len(nodes), current_limit)

            decision_window = min(16, len(nodes))
            if (
                current_limit > 8
                and observed >= max(8, decision_window)
                and timeout_like / max(1, observed) >= 0.50
            ):
                previous = current_limit
                current_limit = 8
                adaptive_events.append(
                    {
                        "event": "concurrency_reduced",
                        "from": previous,
                        "to": 8,
                        "reason": "timeout_or_controller_error_storm",
                        "observed": observed,
                        "affected": timeout_like,
                    }
                )
            if cancel_event.is_set():
                for future in active:
                    future.cancel()
            while len(active) < current_limit and submit_one():
                pass
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    return results, current_limit, adaptive_events


def _run_service_probes_bounded(
    runtime: MihomoRuntime,
    base_results: Sequence[NodeResult],
    *,
    services: Sequence[ServiceDefinition],
    timeout_ms: int,
    cancel_event: threading.Event,
    service_step_callback: Callable[[], None] | None = None,
) -> list[NodeResult]:
    """Keep at most eight node-level service tasks queued at a time."""
    if not base_results:
        return []
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=min(SERVICE_WORKERS_MAX, len(base_results)),
        thread_name_prefix="wireveil-mihomo-services",
    )
    iterator = iter(base_results)
    active: dict[concurrent.futures.Future[NodeResult], NodeResult] = {}
    completed_results: list[NodeResult] = []

    def submit_one() -> bool:
        if cancel_event.is_set():
            return False
        try:
            result = next(iterator)
        except StopIteration:
            return False
        future = executor.submit(
            _probe_services_node,
            runtime,
            result,
            services=services,
            timeout_ms=timeout_ms,
            cancel_event=cancel_event,
            service_step_callback=service_step_callback,
        )
        active[future] = result
        return True

    try:
        while len(active) < SERVICE_WORKERS_MAX and submit_one():
            pass
        while active:
            done, _pending = concurrent.futures.wait(
                tuple(active), return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                original = active.pop(future)
                if future.cancelled():
                    continue
                try:
                    result = future.result()
                except Exception as exc:
                    code, summary = classify_probe_error(exc)
                    original.overall_status = "failed"
                    original.error_code = code
                    original.error_summary = summary
                    original.error_category = error_category_for_code(code)
                    result = original
                completed_results.append(result)
            if cancel_event.is_set():
                for future in active:
                    future.cancel()
            while len(active) < SERVICE_WORKERS_MAX and submit_one():
                pass
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    return completed_results


def _direct_baseline(timeout_ms: int) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(BASE_TESTS[0][1], headers={"User-Agent": "WireVeilChecker/1.0"})
    try:
        with opener.open(request, timeout=timeout_ms / 1000) as response:
            return "ok" if int(response.getcode()) == 204 else "failed"
    except (OSError, ValueError, urllib.error.URLError):
        return "failed"


class BatchRunner:
    """Cancellable orchestrator used by the Tk UI and integration tests."""

    def __init__(self) -> None:
        self.cancel_event = threading.Event()
        self._runtime: MihomoRuntime | None = None
        self._validation_process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

    def _set_validation_process(self, process: subprocess.Popen[str] | None) -> None:
        with self._lock:
            self._validation_process = process
            should_stop = process is not None and self.cancel_event.is_set()
        if should_stop and process is not None:
            _terminate_process(process)

    def stop(self) -> None:
        self.cancel_event.set()
        with self._lock:
            runtime = self._runtime
            validation_process = self._validation_process
        if validation_process is not None:
            _terminate_process(validation_process)
        if runtime is not None:
            runtime.stop()

    def run(
        self,
        *,
        binary: Path,
        source_specs: Sequence[SourceSpec],
        selected_services: Sequence[str] = DEFAULT_SERVICES,
        attempts: int = 2,
        timeout_ms: int = 8_000,
        workers: int = BASE_WORKERS_DEFAULT,
        node_limit: int | None = None,
        per_source_limit: int | None = None,
        sampling_seed: str = "wireveil-default",
        base_policy: str = "strict",
        source_callback: Callable[[ParsedSource], None] | None = None,
        node_callback: Callable[[int, int, NodeResult], None] | None = None,
        progress_callback: Callable[[ProgressUpdate], None] | None = None,
    ) -> BatchReport:
        if not 1 <= len(source_specs) <= MAX_SOURCES:
            raise MihomoCheckError("INVALID_SOURCE_COUNT", "Добавьте от 1 до 200 источников")
        if not 2 <= attempts <= 5:
            raise MihomoCheckError("INVALID_SETTINGS", "Число HTTPS-прогонов должно быть от 2 до 5")
        if not 1_000 <= timeout_ms <= 60_000:
            raise MihomoCheckError("INVALID_SETTINGS", "Тайм-аут должен быть от 1 до 60 секунд")
        if not 1 <= workers <= 24:
            raise MihomoCheckError("INVALID_SETTINGS", "Параллельность должна быть от 1 до 24")
        if node_limit is not None and not 1 <= node_limit <= MAX_NODES:
            raise MihomoCheckError("INVALID_SETTINGS", "Лимит узлов должен быть от 1 до 20000")
        if per_source_limit is not None and not 1 <= per_source_limit <= MAX_NODES:
            raise MihomoCheckError("INVALID_SETTINGS", "Лимит на источник должен быть от 1 до 20000")
        if base_policy not in {"strict", "one_ok"}:
            raise MihomoCheckError("INVALID_SETTINGS", "Неизвестная политика базового HTTPS")
        try:
            services = tuple(SERVICE_BY_NAME[name] for name in dict.fromkeys(selected_services))
        except KeyError as exc:
            raise MihomoCheckError("INVALID_SETTINGS", f"Неизвестный сервис: {exc.args[0]}") from exc

        reporter = _ProgressReporter(progress_callback)
        effective_workers = workers
        adaptive_events: list[dict[str, object]] = []
        total_sources = len(source_specs)
        loaded_sources: list[str | ParsedSource | None] = [None] * total_sources
        reporter.emit("loading", 0, total_sources, "Подготовка загрузки источников", force=True)

        def load_one(spec: SourceSpec) -> str | ParsedSource:
            if self.cancel_event.is_set():
                return ParsedSource(
                    spec=spec,
                    fetch_status="cancelled",
                    parse_status="not_started",
                    issues=[SourceIssue("CANCELLED", "Загрузка отменена")],
                )
            try:
                return read_source_text(spec)
            except MihomoCheckError as exc:
                return ParsedSource(
                    spec=spec,
                    fetch_status="failed",
                    parse_status="not_started",
                    issues=[SourceIssue(exc.code, exc.summary)],
                )
            except (OSError, UnicodeError) as exc:
                return ParsedSource(
                    spec=spec,
                    fetch_status="failed",
                    parse_status="not_started",
                    issues=[SourceIssue("SOURCE_FETCH_FAILED", sanitize_text(exc))],
                )
            except Exception as exc:
                return ParsedSource(
                    spec=spec,
                    fetch_status="failed",
                    parse_status="not_started",
                    issues=[SourceIssue("SOURCE_FETCH_FAILED", sanitize_text(exc))],
                )

        load_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, total_sources),
            thread_name_prefix="wireveil-source",
        )
        load_futures = {
            load_pool.submit(load_one, spec): position
            for position, spec in enumerate(source_specs)
        }
        loaded_count = 0
        try:
            for future in concurrent.futures.as_completed(load_futures):
                position = load_futures[future]
                loaded_sources[position] = future.result()
                loaded_count += 1
                reporter.emit(
                    "loading",
                    loaded_count,
                    total_sources,
                    f"Источников загружено или обработано: {loaded_count} из {total_sources}",
                    force=total_sources <= 20,
                )
                if self.cancel_event.is_set():
                    for pending in load_futures:
                        pending.cancel()
        finally:
            load_pool.shutdown(wait=True, cancel_futures=True)
        for position, loaded in enumerate(loaded_sources):
            if loaded is None:
                loaded_sources[position] = ParsedSource(
                    spec=source_specs[position],
                    fetch_status="cancelled",
                    parse_status="not_started",
                    issues=[SourceIssue("CANCELLED", "Загрузка отменена")],
                )

        parsed_sources: list[ParsedSource] = []
        reporter.emit("parsing", 0, total_sources, "Разбор YAML и параметров узлов", force=True)
        for index, (spec, loaded) in enumerate(zip(source_specs, loaded_sources), start=1):
            assert loaded is not None
            if isinstance(loaded, ParsedSource):
                parsed = loaded
            elif self.cancel_event.is_set():
                parsed = ParsedSource(
                    spec=spec,
                    fetch_status="cancelled",
                    parse_status="not_started",
                    issues=[SourceIssue("CANCELLED", "Парсинг отменён")],
                )
            else:
                parsed = parse_source_text(spec, loaded)
            parsed.checked_at = datetime.now().astimezone().isoformat(timespec="seconds")
            parsed_sources.append(parsed)
            if source_callback is not None:
                source_callback(parsed)
            reporter.emit(
                "parsing",
                index,
                total_sources,
                (
                    f"Источник {index}/{total_sources}: {parsed.fetch_status}/{parsed.parse_status}, "
                    f"записей {parsed.total_entries}, код {parsed.error_code or 'OK'}; "
                    f"всего записей {sum(item.total_entries for item in parsed_sources)}"
                ),
                force=total_sources <= 20,
            )

        candidate_count = sum(len(parsed.nodes) for parsed in parsed_sources)
        reporter.emit(
            "deduplication",
            0,
            candidate_count,
            f"Сопоставление {candidate_count} записей узлов",
            force=True,
        )
        dedup_state = {"done": 0}

        def dedup_progress(done: int, total: int) -> None:
            dedup_state["done"] = done
            if done == total or done == 1 or done % 250 == 0:
                reporter.emit(
                    "deduplication",
                    done,
                    total,
                    f"Обработано записей: {done} из {total}",
                )

        nodes = merge_nodes(
            parsed_sources,
            # If cancellation happened during parsing, finish this cheap pass so
            # already parsed nodes remain available in the partial report.
            cancel_event=None if self.cancel_event.is_set() else self.cancel_event,
            progress_callback=dedup_progress,
        )
        dedup_done = dedup_state["done"] if candidate_count else 0
        reporter.emit(
            "deduplication",
            dedup_done,
            candidate_count,
            (
                f"Дедупликация остановлена после {dedup_done} записей; сохранено уникальных: {len(nodes)}"
                if self.cancel_event.is_set()
                else f"Уникальных узлов: {len(nodes)}; удалено дублей: {max(0, candidate_count - len(nodes))}"
            ),
            force=True,
        )
        if len(nodes) > MAX_NODES:
            raise MihomoCheckError("TOO_MANY_NODES", "Суммарный пул содержит более 20000 уникальных узлов")

        node_results: list[NodeResult] = []
        completed_ids: set[str] = set()

        def add_result(result: NodeResult) -> None:
            if result.node.node_id in completed_ids:
                return
            completed_ids.add(result.node.node_id)
            node_results.append(result)
            if node_callback is not None:
                node_callback(len(node_results), len(nodes), result)

        for node in nodes:
            if not node.supported:
                add_result(
                    NodeResult(
                        node=node,
                        overall_status="unsupported",
                        error_code=node.import_error_code,
                        error_summary=node.import_error_summary,
                        error_category="unsupported" if node.import_error_code == "UNSUPPORTED_PROTOCOL" else "invalid_configuration",
                    )
                )

        selected_nodes, sampling = representative_sample(
            nodes,
            limit=node_limit,
            seed=sampling_seed,
            per_source_limit=per_source_limit,
        )
        selected_ids = {node.node_id for node in selected_nodes}
        for node in nodes:
            if not node.supported or node.node_id in selected_ids:
                continue
            add_result(
                NodeResult(
                    node=node,
                    overall_status="not_tested",
                    error_code="SAMPLE_LIMIT",
                    error_summary="Узел не вошёл в репрезентативную выборку",
                    error_category="not_tested",
                )
            )

        supported = list(selected_nodes)
        direct_baseline = "skipped"
        engine_version = "unknown"
        runtime_log_summary: str | None = None
        validation_total = len(supported)
        validation_processed = 0
        validation_results: list[NodeResult] = []
        reporter.emit(
            "validation",
            0,
            validation_total,
            f"Пакетная валидация {validation_total} поддерживаемых узлов",
            force=True,
        )
        if supported and not self.cancel_event.is_set():
            supported, validation_results = validate_runtime_nodes(
                binary,
                supported,
                cancel_event=self.cancel_event,
                process_callback=self._set_validation_process,
                progress_callback=lambda done, total, checks, message: reporter.emit(
                    "validation",
                    done,
                    total,
                    f"{message}; проверок конфигурации: {checks}",
                    force=True,
                ),
            )
            for result in validation_results:
                add_result(result)
            validation_processed = len(supported) + len(validation_results)
        reporter.emit(
            "validation",
            validation_processed,
            validation_total,
            (
                f"Валидация завершена; принято {len(supported)}, невалидно "
                f"{sum(item.error_category == 'invalid_configuration' for item in validation_results)}, "
                f"не проверено {sum(item.overall_status == 'not_tested' for item in validation_results)}"
            ),
            force=True,
        )

        if supported and not self.cancel_event.is_set():
            reporter.emit(
                "runtime", 0, 1, f"Запуск локального Mihomo с {len(supported)} узлами", force=True
            )
            runtime = MihomoRuntime(
                binary,
                supported,
                cancel_event=self.cancel_event,
                validation_process_callback=self._set_validation_process,
            )
            with self._lock:
                self._runtime = runtime
            try:
                try:
                    runtime.start()
                except MihomoCheckError as exc:
                    for node in supported:
                        add_result(
                            NodeResult(
                                node,
                                overall_status="not_tested",
                                error_code=exc.code,
                                error_summary=exc.summary,
                            )
                        )
                    reporter.emit("runtime", 1, 1, f"Mihomo не запущен: {exc.code}", force=True)
                    reporter.emit("https", 1, 1, "HTTPS-тестирование не запускалось", force=True)
                    reporter.emit("services", 1, 1, "Проверки сервисов не запускались", force=True)
                else:
                    engine_version = runtime.version
                    reporter.emit("runtime", 1, 1, "Локальный API Mihomo готов", force=True)
                    reporter.emit(
                        "https",
                        0,
                        len(supported),
                        "Проверка прямого HTTPS baseline и базового трафика узлов",
                        force=True,
                    )
                    if not self.cancel_event.is_set():
                        direct_baseline = _direct_baseline(timeout_ms)

                    probe_nodes = [] if self.cancel_event.is_set() else supported
                    base_passed: dict[str, NodeResult] = {}
                    minimum_successes = attempts if base_policy == "strict" else 1

                    def base_progress(done: int, total: int, concurrency: int) -> None:
                        reporter.emit(
                            "https",
                            done,
                            total,
                            f"Базовый HTTPS обработан: {done} из {total}; параллельность {concurrency}",
                        )

                    base_results, effective_workers, adaptive_events = _run_base_probes_adaptive(
                        runtime,
                        probe_nodes,
                        attempts=attempts,
                        timeout_ms=timeout_ms,
                        workers=workers,
                        minimum_successes=minimum_successes,
                        cancel_event=self.cancel_event,
                        progress_callback=base_progress,
                    )
                    if adaptive_events:
                        reporter.emit(
                            "https",
                            len(base_results),
                            len(supported),
                            "Параллельность автоматически снижена до 8 из-за шквала тайм-аутов/API 503",
                            force=True,
                        )
                    for result in base_results:
                        if result.base_successes >= minimum_successes and not self.cancel_event.is_set():
                            base_passed[result.node.node_id] = result
                        else:
                            if self.cancel_event.is_set() and result.error_code is None:
                                result.overall_status = "not_tested"
                                result.error_code = "CANCELLED"
                                result.error_summary = "Проверка остановлена пользователем"
                                result.error_category = "not_tested"
                            add_result(result)

                    for node in supported:
                        if node.node_id in completed_ids or node.node_id in base_passed:
                            continue
                        add_result(
                            NodeResult(
                                node,
                                overall_status="not_tested",
                                error_code="CANCELLED" if self.cancel_event.is_set() else "HTTPS_CHECK_FAILED",
                                error_summary="Проверка остановлена пользователем" if self.cancel_event.is_set() else "HTTPS-проверка не завершена",
                            )
                        )
                    reporter.emit(
                        "https",
                        len(supported),
                        len(supported),
                        f"Базовый HTTPS завершён; прошли: {len(base_passed)}",
                        force=True,
                    )

                    if self.cancel_event.is_set():
                        for result in base_passed.values():
                            result.overall_status = "not_tested"
                            result.error_code = "CANCELLED"
                            result.error_summary = "Проверка сервисов отменена"
                            add_result(result)
                    elif not services:
                        reporter.emit("services", 0, 0, "Проверки сервисов не выбраны", force=True)
                        for result in base_passed.values():
                            if result.base_successes < result.base_attempts:
                                result.overall_status = "partial"
                                result.error_code = "UNSTABLE_BASE_HTTPS"
                                result.error_summary = f"Нестабильный базовый HTTPS: {result.base_successes}/{result.base_attempts}"
                                result.error_category = "network"
                            else:
                                result.overall_status = "good"
                            add_result(result)
                        reporter.emit("services", 1, 1, "Узлы отмечены по базовому HTTPS", force=True)
                    elif base_passed:
                        service_total = len(base_passed) * len(services)
                        service_state = {"done": 0}
                        service_lock = threading.Lock()

                        def service_step() -> None:
                            with service_lock:
                                service_state["done"] += 1
                                done = service_state["done"]
                            reporter.emit(
                                "services",
                                done,
                                service_total,
                                f"Сервисных HTTPS-запросов: {done} из {service_total}",
                            )

                        reporter.emit(
                            "services",
                            0,
                            service_total,
                            f"Проверка {len(services)} сервисов для {len(base_passed)} узлов",
                            force=True,
                        )
                        service_results = _run_service_probes_bounded(
                            runtime,
                            list(base_passed.values()),
                            services=services,
                            timeout_ms=timeout_ms,
                            cancel_event=self.cancel_event,
                            service_step_callback=service_step,
                        )
                        for result in service_results:
                            add_result(result)
                        for result in base_passed.values():
                            if result.node.node_id in completed_ids:
                                continue
                            result.overall_status = "not_tested"
                            result.error_code = "CANCELLED"
                            result.error_summary = "Проверка сервисов отменена"
                            add_result(result)
                        reporter.emit(
                            "services",
                            service_state["done"],
                            service_total,
                            "Проверки выбранных сервисов завершены" if not self.cancel_event.is_set() else "Проверки сервисов остановлены",
                            force=True,
                        )
                    else:
                        reporter.emit("services", 1, 1, "Нет узлов для сервисных проверок", force=True)
            finally:
                runtime.stop()
                runtime_log_summary = getattr(runtime, "log_summary", None)
                with self._lock:
                    self._runtime = None
        elif supported:
            for node in supported:
                add_result(
                    NodeResult(
                        node,
                        overall_status="not_tested",
                        error_code="CANCELLED",
                        error_summary="Проверка отменена",
                    )
                )
            reporter.emit("runtime", 1, 1, "Запуск ядра отменён", force=True)
            reporter.emit("https", 1, 1, "HTTPS-тестирование отменено", force=True)
            reporter.emit("services", 1, 1, "Проверки сервисов отменены", force=True)
        else:
            reporter.emit("runtime", 1, 1, "Нет принятых узлов для запуска", force=True)
            reporter.emit("https", 1, 1, "Нет узлов для HTTPS-тестирования", force=True)
            reporter.emit("services", 1, 1, "Нет узлов для сервисных проверок", force=True)

        for node in nodes:
            if node.node_id not in completed_ids:
                add_result(
                    NodeResult(
                        node,
                        overall_status="not_tested",
                        error_code="CANCELLED" if self.cancel_event.is_set() else "NOT_TESTED",
                        error_summary="Проверка остановлена пользователем" if self.cancel_event.is_set() else "Проверка не выполнялась",
                    )
                )
        node_results.sort(key=lambda item: item.node.node_id)
        report = BatchReport(
            generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            engine_version=engine_version,
            direct_baseline=direct_baseline,
            selected_services=tuple(service.name for service in services),
            attempts=attempts,
            timeout_ms=timeout_ms,
            sources=parsed_sources,
            node_results=node_results,
            sampling={
                **sampling,
                "base_policy": base_policy,
            },
            requested_workers=workers,
            effective_workers=effective_workers,
            adaptive_events=adaptive_events,
            mihomo_stderr_summary=runtime_log_summary,
        )
        reporter.emit(
            "completion",
            1,
            1,
            "Частичные результаты сохранены после остановки" if self.cancel_event.is_set() else "Пакетная проверка завершена",
            force=True,
        )
        return report


def _source_counts(report: BatchReport, source_id: str) -> dict[str, int]:
    counts = {"good": 0, "partial": 0, "failed": 0, "unsupported": 0, "not_tested": 0}
    for result in report.node_results:
        if source_id in result.node.source_ids:
            counts[result.overall_status] = counts.get(result.overall_status, 0) + 1
    return counts


def source_age_days(metadata: Mapping[str, str], reference: str | None = None) -> int | None:
    value = next(
        (metadata.get(key) for key in ("last_repo_push", "last_updated", "updated_at") if metadata.get(key)),
        None,
    )
    if not value:
        return None
    try:
        checked = datetime.fromisoformat((reference or datetime.now().astimezone().isoformat()).replace("Z", "+00:00"))
        updated = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if checked.tzinfo is not None and updated.tzinfo is None:
            updated = updated.replace(tzinfo=checked.tzinfo)
        if checked.tzinfo is None and updated.tzinfo is not None:
            checked = checked.replace(tzinfo=updated.tzinfo)
        return max(0, (checked - updated).days)
    except (TypeError, ValueError):
        return None


def report_payload(report: BatchReport) -> dict[str, object]:
    sources: list[dict[str, object]] = []
    for parsed in report.sources:
        counts = _source_counts(report, parsed.spec.source_id)
        sources.append(
            {
                "source_id": parsed.spec.source_id,
                "name": sanitize_text(parsed.spec.name, 160),
                "kind": parsed.spec.kind,
                "source_display": parsed.spec.display,
                "provenance": {
                    sanitize_text(key, 80): sanitize_text(value, 300)
                    for key, value in parsed.spec.metadata.items()
                },
                "age_days": source_age_days(parsed.spec.metadata, report.generated_at),
                "fetch_status": parsed.fetch_status,
                "parse_status": parsed.parse_status,
                "download_bytes": parsed.download_bytes,
                "total_entries": parsed.total_entries,
                "protocol_counts": dict(sorted(parsed.protocol_counts.items())),
                "unique_nodes": len({node.node_id for node in parsed.nodes}),
                "good_nodes": counts["good"],
                "partial_nodes": counts["partial"],
                "failed_nodes": counts["failed"],
                "unsupported_nodes": counts["unsupported"],
                "not_tested_nodes": counts["not_tested"],
                "error_code": parsed.error_code,
                "error_summary": sanitize_text(parsed.error_summary) if parsed.error_summary else None,
                "entry_errors": [
                    {
                        "entry_index": issue.entry_index,
                        "error_code": issue.error_code,
                        "error_summary": sanitize_text(issue.error_summary),
                    }
                    for issue in parsed.issues
                ],
                "checked_at": parsed.checked_at,
            }
        )
    nodes: list[dict[str, object]] = []
    for result in report.node_results:
        node = result.node
        endpoint_results: dict[str, object] = {}
        for endpoint_key, attempts in result.base_endpoint_results.items():
            latencies = [item.latency_ms for item in attempts if item.success and item.latency_ms is not None]
            first_error = next((item for item in attempts if not item.success), None)
            endpoint_results[endpoint_key] = {
                "successes": len(latencies),
                "attempts": len(attempts),
                "latency_ms": round(statistics.median(latencies)) if latencies else None,
                "error_code": first_error.error_code if first_error else None,
                "error_category": first_error.error_category if first_error else None,
                "controller_http_status": first_error.controller_http_status if first_error else None,
                "error_summary": sanitize_text(first_error.error_summary) if first_error and first_error.error_summary else None,
            }
        nodes.append(
            {
                "node_id": node.node_id,
                "source_ids": list(node.source_ids),
                "source_original_names": {
                    key: sanitize_text(value, 160) for key, value in node.source_original_names.items()
                },
                "protocol": sanitize_text(node.protocol, 40),
                "server": sanitize_text(node.server, 253),
                "port": node.port,
                "overall_status": result.overall_status,
                "base_https": {
                    "successes": result.base_successes,
                    "attempts": result.base_attempts,
                    "latency_ms": result.base_latency_ms,
                    "error_code": result.base_error_code,
                    "error_category": error_category_for_code(result.base_error_code),
                    "error_summary": sanitize_text(result.base_error_summary) if result.base_error_summary else None,
                    "endpoints": endpoint_results,
                },
                "services": {
                    name: {
                        "status": service.status,
                        "latency_ms": service.latency_ms,
                        "http_status": service.http_status,
                        "error_code": service.error_code,
                        "error_category": service.error_category or error_category_for_code(service.error_code),
                        "controller_http_status": service.controller_http_status,
                        "error_summary": sanitize_text(service.error_summary) if service.error_summary else None,
                    }
                    for name, service in result.services.items()
                },
                "error_code": result.error_code,
                "error_category": result.error_category or error_category_for_code(result.error_code),
                "error_summary": sanitize_text(result.error_summary) if result.error_summary else None,
            }
        )
    statuses = [item.overall_status for item in report.node_results]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": report.generated_at,
        "engine": {
            "name": "mihomo",
            "version": sanitize_text(report.engine_version, 160),
            "runtime_location": "Windows-local",
        },
        "test_environment": {
            "network_note": "Проверено из текущей сети ПК, не из GitHub Actions / облака",
            "direct_baseline": report.direct_baseline,
            "selected_services": list(report.selected_services),
            "attempts": report.attempts,
            "timeout_ms": report.timeout_ms,
            "base_workers_requested": report.requested_workers,
            "base_workers_effective": report.effective_workers,
            "service_workers_limit": SERVICE_WORKERS_MAX,
            "adaptive_events": report.adaptive_events,
        },
        "sampling": report.sampling,
        "capability_matrix": {
            "runtime_tested_protocols": sorted(SUPPORTED_PROTOCOLS),
            "classified_only": ["anytls", "http", "socks5", "ssr", "wireguard"],
            "note": "classified_only protocols are reported as unsupported and are not probed",
        },
        "mihomo_stderr_summary": sanitize_text(report.mihomo_stderr_summary, 8_000) if report.mihomo_stderr_summary else None,
        "sources": sources,
        "nodes": nodes,
        "totals": {
            "sources": len(report.sources),
            "unique_nodes": len(report.node_results),
            "source_node_entries": sum(len(item.node.source_ids) for item in report.node_results),
            "good": statuses.count("good"),
            "partial": statuses.count("partial"),
            "failed": statuses.count("failed"),
            "unsupported": statuses.count("unsupported"),
            "not_tested": statuses.count("not_tested"),
        },
    }


def summary_markdown(report: BatchReport) -> str:
    payload = report_payload(report)
    totals = payload["totals"]
    assert isinstance(totals, dict)
    lines = [
        "# WireVeil Mihomo diagnostic summary",
        "",
        f"- Сформирован: {report.generated_at}",
        f"- Движок: {sanitize_text(report.engine_version, 160)}",
        f"- Источников: {totals['sources']}",
        f"- Уникальных узлов: {totals['unique_nodes']} (записей по источникам: {totals['source_node_entries']})",
        f"- Статусы: good {totals['good']}, partial {totals['partial']}, failed {totals['failed']}, unsupported {totals['unsupported']}, not_tested {totals['not_tested']}",
        f"- Прямой HTTPS baseline: {report.direct_baseline}",
        f"- Выбранные сервисы: {', '.join(report.selected_services) or 'нет'}",
        f"- Семплирование: {report.sampling.get('strategy', 'не указано')}, seed `{sanitize_text(report.sampling.get('seed', '—'), 80)}`; выбрано {report.sampling.get('selected_nodes', '—')}",
        f"- Параллельность HTTPS: запрошено {report.requested_workers}, фактически {report.effective_workers}; сервисы не более {SERVICE_WORKERS_MAX}",
        "",
        "## Источники",
        "",
        "| ID | Имя | Загрузка / разбор | Байт | Протоколы | Всего | Good | Partial | Failed | Unsupported | Not tested | Ошибка |",
        "|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for parsed in report.sources:
        counts = _source_counts(report, parsed.spec.source_id)
        safe_name = sanitize_text(parsed.spec.name, 120).replace("|", "\\|")
        error = sanitize_text(parsed.error_code or "—", 80)
        lines.append(
            f"| {parsed.spec.source_id} | {safe_name} | {parsed.fetch_status} / {parsed.parse_status} | "
            f"{parsed.download_bytes or 0} | {sanitize_text(', '.join(f'{key}:{value}' for key, value in sorted(parsed.protocol_counts.items())), 200)} | "
            f"{parsed.total_entries} | {counts['good']} | {counts['partial']} | {counts['failed']} | "
            f"{counts['unsupported']} | {counts['not_tested']} | {error} |"
        )
    error_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for result in report.node_results:
        if result.error_code:
            error_counts[result.error_code] = error_counts.get(result.error_code, 0) + 1
            category = result.error_category or error_category_for_code(result.error_code) or "other"
            category_counts[category] = category_counts.get(category, 0) + 1
    lines.extend(["", "## Наиболее частые ошибки", ""])
    if error_counts:
        for code, count in sorted(error_counts.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- `{code}`: {count}")
    else:
        lines.append("- Ошибок узлов не зафиксировано.")
    lines.extend(["", "## Категории причин", ""])
    for category, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- `{category}`: {count}")
    lines.extend(
        [
            "",
            "## Диагностические замечания",
            "",
            "- Предположение: `SOURCE_FETCH_FAILED` обычно означает сетевой сбой, DNS, блокировку или истёкший URL подписки.",
            "- Предположение: `MIHOMO_CONFIG_REJECTED` означает, что конкретные параметры узла не приняты этой версией Mihomo.",
            "- `partial` подтверждает базовый HTTPS, но не доступность всех выбранных доменов.",
            "- Проверка URL сервиса не гарантирует вход в аккаунт, работу мобильного приложения, CDN, видео, UDP или QUIC.",
            "- Этот архив обезличен. Для исправления приватных конфигураций нужен исходный YAML или отдельный приватный экспорт, который нельзя отправлять посторонним.",
            "",
        ]
    )
    return "\n".join(lines)


def nodes_csv(report: BatchReport) -> str:
    output = io.StringIO(newline="")
    service_names = list(report.selected_services)
    header = [
        "source_id", "source_name", "node_id", "node_name", "protocol", "endpoint",
        "overall_status", "https_latency_ms", "https_successes", "https_attempts",
        "gstatic_status", "gstatic_latency_ms", "cloudflare_status", "cloudflare_latency_ms",
    ]
    for name in service_names:
        key = SERVICE_BY_NAME[name].key
        header.extend((f"{key}_status", f"{key}_latency_ms"))
    header.extend(("error_category", "error_code", "error_summary"))
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(header)
    source_names = {parsed.spec.source_id: sanitize_text(parsed.spec.name, 160) for parsed in report.sources}

    def safe_cell(value: object) -> object:
        if not isinstance(value, str):
            return value
        text = sanitize_text(value)
        if text.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    for result in report.node_results:
        node = result.node
        for source_id in node.source_ids:
            row: list[object] = [
                source_id,
                source_names.get(source_id, ""),
                node.node_id,
                sanitize_text(node.source_original_names.get(source_id, ""), 160),
                sanitize_text(node.protocol, 40),
                f"{sanitize_text(node.server, 253)}:{node.port or ''}",
                result.overall_status,
                result.base_latency_ms if result.base_latency_ms is not None else "",
                result.base_successes,
                result.base_attempts,
            ]
            for endpoint_key in ("gstatic", "cloudflare"):
                attempts = result.base_endpoint_results.get(endpoint_key, [])
                successes = [item for item in attempts if item.success]
                latency = next((item.latency_ms for item in successes if item.latency_ms is not None), "")
                row.extend((f"{len(successes)}/{len(attempts)}" if attempts else "not_tested", latency))
            for name in service_names:
                service = result.services.get(name)
                row.extend((service.status if service else "not_tested", service.latency_ms if service and service.latency_ms is not None else ""))
            row.extend((
                result.error_category or error_category_for_code(result.error_code) or "",
                result.error_code or "",
                sanitize_text(result.error_summary or ""),
            ))
            writer.writerow([safe_cell(value) for value in row])
    return "\ufeff" + output.getvalue()


def export_report_zip(report: BatchReport, path: Path) -> Path:
    if path.suffix.lower() != ".zip":
        path = path.with_suffix(".zip")
    payload = json.dumps(report_payload(report), ensure_ascii=False, indent=2) + "\n"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", payload.encode("utf-8"))
        archive.writestr("summary.md", summary_markdown(report).encode("utf-8"))
        archive.writestr("nodes.csv", nodes_csv(report).encode("utf-8"))
    return path


def _unique_export_name(name: str, used: set[str]) -> str:
    base = name.strip() or "WireVeil node"
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base} [{suffix}]"
        suffix += 1
    used.add(candidate)
    return candidate


def export_private_yaml(
    report: BatchReport,
    path: Path,
    *,
    source_id: str | None = None,
    statuses: Iterable[str] = ("good",),
) -> Path:
    allowed = set(statuses)
    used_names: set[str] = set()
    proxies: list[dict[str, object]] = []
    for result in report.node_results:
        if result.overall_status not in allowed:
            continue
        if source_id is not None and source_id not in result.node.source_ids:
            continue
        proxy = dict(result.node.proxy)
        original = str(proxy.get("name") or "WireVeil node")
        proxy["name"] = _unique_export_name(original, used_names)
        proxies.append(proxy)
    if not proxies:
        raise MihomoCheckError("NO_MATCHING_NODES", "Нет узлов с выбранным статусом для экспорта")
    _write_private_yaml(path, {"proxies": proxies})
    return path


def export_private_yaml_by_source(report: BatchReport, directory: Path, statuses: Iterable[str] = ("good",)) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    exported: list[Path] = []
    allowed = set(statuses)
    for index, parsed in enumerate(report.sources, start=1):
        if not any(
            parsed.spec.source_id in result.node.source_ids
            and result.overall_status in allowed
            for result in report.node_results
        ):
            continue
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", parsed.spec.name).strip(".-") or f"source-{index}"
        path = directory / f"{index:03d}-{safe_stem}.yaml"
        export_private_yaml(report, path, source_id=parsed.spec.source_id, statuses=allowed)
        exported.append(path)
    return exported


def save_source_specs(path: Path, sources: Sequence[SourceSpec]) -> None:
    payload = {
        "version": SOURCE_STORE_VERSION,
        "warning": "Contains private subscription URLs, paths, or pasted YAML. Do not share.",
        "sources": [
            {
                "source_id": item.source_id,
                "name": item.name,
                "kind": item.kind,
                "value": item.value,
                "metadata": dict(item.metadata),
            }
            for item in sources
        ],
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(path)


def load_source_specs(path: Path) -> list[SourceSpec]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
        return []
    sources: list[SourceSpec] = []
    seen_ids: set[str] = set()
    for raw in payload["sources"][:MAX_SOURCES]:
        if not isinstance(raw, dict):
            continue
        values = tuple(raw.get(key) for key in ("source_id", "name", "kind", "value"))
        if (
            not all(isinstance(value, str) for value in values)
            or values[2] not in {"url", "file", "text"}
            or re.fullmatch(r"src-[0-9a-f]{12}", values[0]) is None
            or values[0] in seen_ids
        ):
            continue
        seen_ids.add(values[0])
        raw_metadata = raw.get("metadata")
        metadata = (
            {
                str(key): str(value)
                for key, value in raw_metadata.items()
                if isinstance(key, str) and isinstance(value, (str, int, float, bool))
            }
            if isinstance(raw_metadata, dict)
            else {}
        )
        sources.append(SourceSpec(*values, metadata))
    return sources
