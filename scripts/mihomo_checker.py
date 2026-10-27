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


def new_source_id() -> str:
    return f"src-{uuid.uuid4().hex[:12]}"


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


def load_source(spec: SourceSpec, *, fetch_timeout: float = 15.0) -> ParsedSource:
    try:
        if spec.kind == "url":
            text = fetch_source_url(spec.value, timeout=fetch_timeout)
        elif spec.kind == "file":
            path = Path(spec.value)
            if path.stat().st_size > MAX_SOURCE_BYTES:
                raise MihomoCheckError("SOURCE_TOO_LARGE", "Источник превышает лимит 5 МБ")
            text = path.read_text(encoding="utf-8-sig")
        elif spec.kind == "text":
            text = spec.value
        else:
            raise MihomoCheckError("UNSUPPORTED_FORMAT", "Неизвестный тип источника")
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


def merge_nodes(parsed_sources: Sequence[ParsedSource]) -> list[NodeRecord]:
    merged: dict[str, NodeRecord] = {}
    for parsed in parsed_sources:
        for candidate in parsed.nodes:
            current = merged.get(candidate.node_id)
            if current is None:
                merged[candidate.node_id] = candidate
                continue
            if candidate.source_ids[0] not in current.source_ids:
                current.source_ids.append(candidate.source_ids[0])
            current.source_original_names.update(candidate.source_original_names)
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


def _check_config(binary: Path, config_path: Path, timeout: float = 30.0) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            [str(binary), "-d", str(config_path.parent), "-t", "-f", str(config_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            **_hidden_process_options(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, sanitize_text(exc)
    detail = sanitize_text((completed.stdout or "") + " " + (completed.stderr or ""), 800)
    return completed.returncode == 0, detail


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
    binary: Path, nodes: Sequence[NodeRecord]
) -> tuple[list[NodeRecord], list[NodeResult]]:
    """Exclude config-rejected nodes without sacrificing the rest of a batch."""
    if not binary.is_file():
        raise MihomoCheckError("MIHOMO_NOT_FOUND", f"Не найден Mihomo: {binary.name}")
    if not nodes:
        return [], []
    with tempfile.TemporaryDirectory(prefix="wireveil-mihomo-validate-") as name:
        root = Path(name)
        combined = root / "combined.yaml"
        _write_private_yaml(combined, _runtime_config(nodes, _free_local_port(), secrets.token_urlsafe(32)))
        valid, _detail = _check_config(binary, combined)
        if valid:
            return list(nodes), []
        accepted: list[NodeRecord] = []
        rejected: list[NodeResult] = []
        for index, node in enumerate(nodes):
            single = root / f"node-{index}.yaml"
            _write_private_yaml(single, _runtime_config((node,), _free_local_port(), secrets.token_urlsafe(32)))
            node_valid, _node_detail = _check_config(binary, single)
            if node_valid:
                accepted.append(node)
            else:
                rejected.append(
                    NodeResult(
                        node=node,
                        overall_status="unsupported",
                        error_code="MIHOMO_CONFIG_REJECTED",
                        error_summary="Mihomo отклонил параметры этого узла",
                    )
                )
        if accepted:
            accepted_path = root / "accepted.yaml"
            _write_private_yaml(
                accepted_path,
                _runtime_config(accepted, _free_local_port(), secrets.token_urlsafe(32)),
            )
            accepted_valid, accepted_detail = _check_config(binary, accepted_path)
            if not accepted_valid:
                raise MihomoCheckError(
                    "MIHOMO_CONFIG_REJECTED",
                    accepted_detail or "Mihomo отклонил объединённую конфигурацию",
                )
        return accepted, rejected


class MihomoRuntime:
    """A single isolated Mihomo process shared by all node probes."""

    def __init__(self, binary: Path, nodes: Sequence[NodeRecord]):
        self.binary = binary
        self.nodes = tuple(nodes)
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
        self._temporary = tempfile.TemporaryDirectory(prefix="wireveil-mihomo-")
        root = Path(self._temporary.name)
        config_path = root / "config.yaml"
        log_path = root / "mihomo.log"
        _write_private_yaml(config_path, _runtime_config(self.nodes, self.port, self.secret))
        valid, detail = _check_config(self.binary, config_path)
        if not valid:
            self.stop()
            raise MihomoCheckError("MIHOMO_CONFIG_REJECTED", detail or "Mihomo отклонил конфигурацию")
        try:
            completed = subprocess.run(
                [str(self.binary), "-v"],
                capture_output=True,
                text=True,
                timeout=8,
                **_hidden_process_options(),
            )
            self.version = sanitize_text((completed.stdout or completed.stderr).strip(), 160) or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            self.version = "unknown"
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
            process = self.process
            if process is None or process.poll() is not None:
                self.stop()
                raise MihomoCheckError("MIHOMO_START_FAILED", "Процесс Mihomo завершился при запуске")
            try:
                self._request("/version")
                return
            except (OSError, urllib.error.URLError):
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


def _probe_node(
    runtime: MihomoRuntime,
    node: NodeRecord,
    *,
    services: Sequence[ServiceDefinition],
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
    failed_services: list[str] = []
    for service in services:
        if cancel_event.is_set():
            result.overall_status = "not_tested"
            result.error_code = "CANCELLED"
            result.error_summary = "Проверка отменена"
            return result
        probe = api_delay(runtime, node, url=service.url, timeout_ms=timeout_ms, expected=service.expected)
        if probe.success:
            result.services[service.name] = ServiceResult("reachable", probe.latency_ms)
        else:
            failed_services.append(service.name)
            result.services[service.name] = ServiceResult(
                "failed",
                error_code=probe.error_code,
                error_summary=probe.error_summary,
            )
    if failed_services:
        result.overall_status = "partial"
        result.error_code = "SITE_PARTIAL"
        result.error_summary = sanitize_text("Недоступны: " + ", ".join(failed_services))
    else:
        result.overall_status = "good"
    return result


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
        self._lock = threading.Lock()

    def stop(self) -> None:
        self.cancel_event.set()
        with self._lock:
            runtime = self._runtime
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
        source_callback: Callable[[ParsedSource], None] | None = None,
        node_callback: Callable[[int, int, NodeResult], None] | None = None,
    ) -> BatchReport:
        if not 1 <= len(source_specs) <= MAX_SOURCES:
            raise MihomoCheckError("INVALID_SOURCE_COUNT", "Добавьте от 1 до 200 источников")
        if not 2 <= attempts <= 5:
            raise MihomoCheckError("INVALID_SETTINGS", "Число HTTPS-прогонов должно быть от 2 до 5")
        if not 1_000 <= timeout_ms <= 60_000:
            raise MihomoCheckError("INVALID_SETTINGS", "Тайм-аут должен быть от 1 до 60 секунд")
        if not 1 <= workers <= 32:
            raise MihomoCheckError("INVALID_SETTINGS", "Параллельность должна быть от 1 до 32")
        try:
            services = tuple(SERVICE_BY_NAME[name] for name in dict.fromkeys(selected_services))
        except KeyError as exc:
            raise MihomoCheckError("INVALID_SETTINGS", f"Неизвестный сервис: {exc.args[0]}") from exc

        self.cancel_event.clear()
        parsed_sources: list[ParsedSource] = []
        for spec in source_specs:
            if self.cancel_event.is_set():
                parsed = ParsedSource(
                    spec=spec,
                    fetch_status="cancelled",
                    parse_status="not_started",
                    issues=[SourceIssue("CANCELLED", "Проверка отменена")],
                )
            else:
                parsed = load_source(spec)
            parsed.checked_at = datetime.now().astimezone().isoformat(timespec="seconds")
            parsed_sources.append(parsed)
            if source_callback is not None:
                source_callback(parsed)

        nodes = merge_nodes(parsed_sources)
        if len(nodes) > MAX_NODES:
            raise MihomoCheckError("TOO_MANY_NODES", "Суммарный пул содержит более 20000 уникальных узлов")
        node_results: list[NodeResult] = []
        supported: list[NodeRecord] = []
        for node in nodes:
            if node.supported:
                supported.append(node)
            else:
                node_results.append(
                    NodeResult(
                        node=node,
                        overall_status="unsupported",
                        error_code=node.import_error_code,
                        error_summary=node.import_error_summary,
                    )
                )
        direct_baseline = (
            _direct_baseline(timeout_ms)
            if supported and not self.cancel_event.is_set()
            else "skipped"
        )
        engine_version = "unknown"
        if supported and not self.cancel_event.is_set():
            supported, config_rejected = validate_runtime_nodes(binary, supported)
            node_results.extend(config_rejected)
        if supported and not self.cancel_event.is_set():
            runtime = MihomoRuntime(binary, supported)
            with self._lock:
                self._runtime = runtime
            try:
                try:
                    runtime.start()
                except MihomoCheckError as exc:
                    node_results.extend(
                        NodeResult(
                            node,
                            overall_status="not_tested",
                            error_code=exc.code,
                            error_summary=exc.summary,
                        )
                        for node in supported
                    )
                else:
                    engine_version = runtime.version
                    executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(supported)))
                    futures = {
                        executor.submit(
                            _probe_node,
                            runtime,
                            node,
                            services=services,
                            attempts=attempts,
                            timeout_ms=timeout_ms,
                            cancel_event=self.cancel_event,
                        ): node
                        for node in supported
                    }
                    completed = 0
                    try:
                        for future in concurrent.futures.as_completed(futures):
                            completed += 1
                            try:
                                result = future.result()
                            except Exception as exc:  # keep one bad node from aborting the batch
                                code, summary = classify_probe_error(exc)
                                result = NodeResult(futures[future], overall_status="failed", error_code=code, error_summary=summary)
                            node_results.append(result)
                            if node_callback is not None:
                                node_callback(completed, len(supported), result)
                    finally:
                        executor.shutdown(wait=not self.cancel_event.is_set(), cancel_futures=True)
            finally:
                runtime.stop()
                with self._lock:
                    self._runtime = None
        elif supported:
            node_results.extend(
                NodeResult(node, error_code="CANCELLED", error_summary="Проверка отменена")
                for node in supported
            )
        node_results.sort(key=lambda item: item.node.node_id)
        return BatchReport(
            generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            engine_version=engine_version,
            direct_baseline=direct_baseline,
            selected_services=tuple(service.name for service in services),
            attempts=attempts,
            timeout_ms=timeout_ms,
            sources=parsed_sources,
            node_results=node_results,
        )


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
