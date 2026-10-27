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


SCHEMA_VERSION = 1
SOURCE_STORE_VERSION = 1
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_SOURCES = 200
MAX_NODES = 20_000
MAX_VALIDATION_CHECKS = 128
SUPPORTED_PROTOCOLS = frozenset(
    {"vless", "trojan", "ss", "vmess", "hysteria", "hysteria2", "tuic"}
)
BASE_TESTS = (
    ("https://www.gstatic.com/generate_204", "204"),
    ("https://cp.cloudflare.com/generate_204", "204"),
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


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    name: str
    kind: str
    value: str

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


@dataclass(frozen=True)
class ServiceResult:
    status: str
    latency_ms: int | None = None
    http_status: int | None = None
    error_code: str | None = None
    error_summary: str | None = None


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
            update = ProgressUpdate(
                stage=stage,
                processed=processed,
                total=total,
                stage_elapsed_seconds=round(now - self.stage_started, 3),
                total_elapsed_seconds=round(now - self.started, 3),
                overall_percent=round(start + ((end - start) * fraction), 2),
                message=sanitize_text(message, 300),
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


def source_specs_from_file(path: Path) -> list[SourceSpec]:
    """Expand a TXT URL list into URL sources, otherwise keep one file source."""
    path = Path(path)
    file_source = SourceSpec(new_source_id(), path.stem, "file", str(path))
    if path.suffix.casefold() != ".txt":
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

    urls = subscription_urls_from_text(text)
    if urls is None:
        return [file_source]

    result: list[SourceSpec] = []
    for position, url in enumerate(urls, start=1):
        try:
            hostname = urllib.parse.urlsplit(url).hostname or "Подписка"
        except ValueError:
            hostname = "Подписка"
        result.append(
            SourceSpec(
                new_source_id(),
                f"{path.stem} [{position}] · {hostname}",
                "url",
                url,
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
                        overall_status="unsupported",
                        error_code="MIHOMO_CONFIG_REJECTED",
                        error_summary="Mihomo отклонил параметры этого узла",
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
        self._stop_lock = threading.Lock()
        self.version = "unknown"

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
            if self._temporary is not None:
                self._temporary.cleanup()
                self._temporary = None

    def __enter__(self) -> "MihomoRuntime":
        self.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.stop()


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
    try:
        payload = json.loads(runtime._request(path, timeout=(timeout_ms / 1000) + 3).decode("utf-8"))
        delay = int(payload["delay"])
        if delay < 0:
            raise ValueError("invalid delay")
        return DelayResult(True, delay)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        code, summary = classify_probe_error(exc)
        return DelayResult(False, error_code=code, error_summary=summary)


def _probe_base_node(
    runtime: MihomoRuntime,
    node: NodeRecord,
    *,
    attempts: int,
    timeout_ms: int,
    cancel_event: threading.Event,
) -> NodeResult:
    result = NodeResult(node=node, base_attempts=attempts)
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
        url, expected = BASE_TESTS[attempt % len(BASE_TESTS)]
        probe = api_delay(runtime, node, url=url, timeout_ms=timeout_ms, expected=expected)
        if probe.success and probe.latency_ms is not None:
            delays.append(probe.latency_ms)
        else:
            base_errors.append(probe)
    result.base_successes = len(delays)
    if delays:
        result.base_latency_ms = round(statistics.median(delays))
    if len(delays) != attempts:
        first = base_errors[0] if base_errors else DelayResult(False, error_code="HTTPS_CHECK_FAILED")
        result.overall_status = "failed"
        result.base_error_code = first.error_code or "HTTPS_CHECK_FAILED"
        result.base_error_summary = first.error_summary or "Не все HTTPS-прогоны успешны"
        result.error_code = result.base_error_code
        result.error_summary = result.base_error_summary
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
            )
        if service_step_callback is not None:
            service_step_callback()
    if failed_services:
        result.overall_status = "partial"
        result.error_code = "SITE_PARTIAL"
        result.error_summary = sanitize_text("Недоступны: " + ", ".join(failed_services))
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


def _direct_baseline(timeout_ms: int) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(BASE_TESTS[0][0], headers={"User-Agent": "WireVeilChecker/1.0"})
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
        workers: int = 8,
        node_limit: int | None = None,
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
        if not 1 <= workers <= 32:
            raise MihomoCheckError("INVALID_SETTINGS", "Параллельность должна быть от 1 до 32")
        if node_limit is not None and not 1 <= node_limit <= MAX_NODES:
            raise MihomoCheckError("INVALID_SETTINGS", "Лимит узлов должен быть от 1 до 20000")
        try:
            services = tuple(SERVICE_BY_NAME[name] for name in dict.fromkeys(selected_services))
        except KeyError as exc:
            raise MihomoCheckError("INVALID_SETTINGS", f"Неизвестный сервис: {exc.args[0]}") from exc

        reporter = _ProgressReporter(progress_callback)
        total_sources = len(source_specs)
        loaded_sources: list[str | ParsedSource] = []
        reporter.emit("loading", 0, total_sources, "Подготовка загрузки источников", force=True)
        for index, spec in enumerate(source_specs, start=1):
            if self.cancel_event.is_set():
                loaded: str | ParsedSource = ParsedSource(
                    spec=spec,
                    fetch_status="cancelled",
                    parse_status="not_started",
                    issues=[SourceIssue("CANCELLED", "Загрузка отменена")],
                )
            else:
                try:
                    loaded = read_source_text(spec)
                except MihomoCheckError as exc:
                    loaded = ParsedSource(
                        spec=spec,
                        fetch_status="failed",
                        parse_status="not_started",
                        issues=[SourceIssue(exc.code, exc.summary)],
                    )
                except (OSError, UnicodeError) as exc:
                    loaded = ParsedSource(
                        spec=spec,
                        fetch_status="failed",
                        parse_status="not_started",
                        issues=[SourceIssue("SOURCE_FETCH_FAILED", sanitize_text(exc))],
                    )
            loaded_sources.append(loaded)
            reporter.emit(
                "loading",
                index,
                total_sources,
                f"Источников загружено или обработано: {index} из {total_sources}",
                force=total_sources <= 20,
            )

        parsed_sources: list[ParsedSource] = []
        reporter.emit("parsing", 0, total_sources, "Разбор YAML и параметров узлов", force=True)
        for index, (spec, loaded) in enumerate(zip(source_specs, loaded_sources), start=1):
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

        selected_nodes = nodes if node_limit is None else nodes[:node_limit]
        for node in nodes[len(selected_nodes):]:
            add_result(
                NodeResult(
                    node=node,
                    overall_status="not_tested",
                    error_code="QUICK_CHECK_LIMIT",
                    error_summary=f"Узел не входит в лимит быстрой проверки {node_limit}",
                )
            )

        supported: list[NodeRecord] = []
        for node in selected_nodes:
            if node.supported:
                supported.append(node)
            else:
                add_result(
                    NodeResult(
                        node=node,
                        overall_status="unsupported",
                        error_code=node.import_error_code,
                        error_summary=node.import_error_summary,
                    )
                )
        direct_baseline = "skipped"
        engine_version = "unknown"
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
                f"Валидация завершена; принято {len(supported)}, отклонено "
                f"{sum(item.overall_status == 'unsupported' for item in validation_results)}, "
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
                    executor = concurrent.futures.ThreadPoolExecutor(
                        max_workers=max(1, min(workers, len(probe_nodes))),
                        thread_name_prefix="wireveil-mihomo-https",
                    )
                    futures = {
                        executor.submit(
                            _probe_base_node,
                            runtime,
                            node,
                            attempts=attempts,
                            timeout_ms=timeout_ms,
                            cancel_event=self.cancel_event,
                        ): node
                        for node in probe_nodes
                    }
                    base_done = 0
                    try:
                        for future in concurrent.futures.as_completed(futures):
                            node = futures[future]
                            if future.cancelled():
                                continue
                            try:
                                result = future.result()
                            except Exception as exc:  # keep one bad node from aborting the batch
                                code, summary = classify_probe_error(exc)
                                result = NodeResult(node, overall_status="failed", error_code=code, error_summary=summary)
                            base_done += 1
                            if result.base_successes == attempts and not self.cancel_event.is_set():
                                base_passed[node.node_id] = result
                            else:
                                if self.cancel_event.is_set() and result.error_code is None:
                                    result.overall_status = "not_tested"
                                    result.error_code = "CANCELLED"
                                    result.error_summary = "Проверка остановлена пользователем"
                                add_result(result)
                            reporter.emit(
                                "https",
                                base_done,
                                len(supported),
                                f"Базовый HTTPS обработан: {base_done} из {len(supported)}",
                            )
                            if self.cancel_event.is_set():
                                for pending in futures:
                                    pending.cancel()
                    finally:
                        executor.shutdown(wait=True, cancel_futures=True)

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
                        service_executor = concurrent.futures.ThreadPoolExecutor(
                            max_workers=min(workers, len(base_passed)),
                            thread_name_prefix="wireveil-mihomo-services",
                        )
                        service_futures = {
                            service_executor.submit(
                                _probe_services_node,
                                runtime,
                                result,
                                services=services,
                                timeout_ms=timeout_ms,
                                cancel_event=self.cancel_event,
                                service_step_callback=service_step,
                            ): result
                            for result in base_passed.values()
                        }
                        try:
                            for future in concurrent.futures.as_completed(service_futures):
                                original = service_futures[future]
                                if future.cancelled():
                                    continue
                                try:
                                    result = future.result()
                                except Exception as exc:
                                    code, summary = classify_probe_error(exc)
                                    original.overall_status = "failed"
                                    original.error_code = code
                                    original.error_summary = summary
                                    result = original
                                add_result(result)
                                if self.cancel_event.is_set():
                                    for pending in service_futures:
                                        pending.cancel()
                        finally:
                            service_executor.shutdown(wait=True, cancel_futures=True)
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
                "fetch_status": parsed.fetch_status,
                "parse_status": parsed.parse_status,
                "total_entries": parsed.total_entries,
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
                    "error_summary": sanitize_text(result.base_error_summary) if result.base_error_summary else None,
                },
                "services": {
                    name: {
                        "status": service.status,
                        "latency_ms": service.latency_ms,
                        "http_status": service.http_status,
                        "error_code": service.error_code,
                        "error_summary": sanitize_text(service.error_summary) if service.error_summary else None,
                    }
                    for name, service in result.services.items()
                },
                "error_code": result.error_code,
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
        },
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
        "",
        "## Источники",
        "",
        "| ID | Имя | Загрузка / разбор | Всего | Good | Partial | Failed | Ошибка |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for parsed in report.sources:
        counts = _source_counts(report, parsed.spec.source_id)
        safe_name = sanitize_text(parsed.spec.name, 120).replace("|", "\\|")
        error = sanitize_text(parsed.error_code or "—", 80)
        lines.append(
            f"| {parsed.spec.source_id} | {safe_name} | {parsed.fetch_status} / {parsed.parse_status} | "
            f"{parsed.total_entries} | {counts['good']} | {counts['partial']} | {counts['failed']} | {error} |"
        )
    error_counts: dict[str, int] = {}
    for result in report.node_results:
        if result.error_code:
            error_counts[result.error_code] = error_counts.get(result.error_code, 0) + 1
    lines.extend(["", "## Наиболее частые ошибки", ""])
    if error_counts:
        for code, count in sorted(error_counts.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- `{code}`: {count}")
    else:
        lines.append("- Ошибок узлов не зафиксировано.")
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
    ]
    for name in service_names:
        key = SERVICE_BY_NAME[name].key
        header.extend((f"{key}_status", f"{key}_latency_ms"))
    header.extend(("error_code", "error_summary"))
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
            for name in service_names:
                service = result.services.get(name)
                row.extend((service.status if service else "not_tested", service.latency_ms if service and service.latency_ms is not None else ""))
            row.extend((result.error_code or "", sanitize_text(result.error_summary or "")))
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
            {"source_id": item.source_id, "name": item.name, "kind": item.kind, "value": item.value}
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
        sources.append(SourceSpec(*values))
    return sources
