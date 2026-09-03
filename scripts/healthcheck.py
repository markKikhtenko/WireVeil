#!/usr/bin/env python3
"""Publish a subscription containing only end-to-end tested proxy URIs.

The checker converts supported share links to sing-box outbounds, starts one
temporary sing-box instance, and asks its local Clash API to fetch HTTPS probe
URLs through every outbound. A key is active only after a real tunneled HTTP
request succeeds; ICMP reachability is deliberately not used.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import html
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import build


INPUT_PATH = ROOT / "subscription.txt"
OUTPUT_PATH = ROOT / "active.txt"
STATS_PATH = ROOT / "active-stats.json"
README_START = "<!-- WIREVEIL_HEALTH_START -->"
README_END = "<!-- WIREVEIL_HEALTH_END -->"
DEFAULT_PROBE_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)
UTLS_FINGERPRINTS = {
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
}


class HealthCheckError(RuntimeError):
    pass


class UnsupportedConfig(HealthCheckError):
    pass


@dataclasses.dataclass(frozen=True)
class ProbeTarget:
    index: int
    tag: str
    uri: str
    protocol: str
    outbound: dict


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    target: ProbeTarget
    active: bool
    delay_ms: int | None = None
    error: str | None = None


def _query(uri: str) -> dict[str, list[str]]:
    query_text = html.unescape(urllib.parse.urlsplit(uri).query)
    result: dict[str, list[str]] = {}
    for key, value in urllib.parse.parse_qsl(query_text, keep_blank_values=True):
        result.setdefault(key.lower(), []).append(value)
    return result


def _first(values: Mapping[str, Sequence[str]], *keys: str) -> str:
    for key in keys:
        candidates = values.get(key.lower())
        if candidates:
            return str(candidates[0])
    return ""


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _list_value(value: str) -> list[str]:
    return [item for item in re.split(r"[,\s]+", value.strip()) if item]


def _positive_number(value: str, field: str) -> int | float:
    try:
        number = float(value)
    except ValueError as exc:
        raise UnsupportedConfig(f"invalid {field}") from exc
    if number <= 0:
        raise UnsupportedConfig(f"invalid {field}")
    return int(number) if number.is_integer() else number


def _tls_from_query(
    query: Mapping[str, Sequence[str]],
    *,
    enabled: bool,
    reality: bool = False,
) -> dict | None:
    if not enabled:
        return None
    tls: dict[str, object] = {"enabled": True, "handshake_timeout": "8s"}
    server_name = _first(query, "sni", "server_name", "servername", "peer")
    if server_name:
        tls["server_name"] = server_name
    if _truthy(_first(query, "allowinsecure", "allow_insecure", "insecure")):
        tls["insecure"] = True
    if _truthy(_first(query, "disable_sni", "disablesni")):
        tls["disable_sni"] = True
    alpn = _list_value(_first(query, "alpn"))
    if alpn:
        tls["alpn"] = alpn
    fingerprint = _first(query, "fp", "fingerprint").lower()
    if fingerprint in UTLS_FINGERPRINTS:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if reality:
        public_key = _first(query, "pbk", "publickey")
        if not public_key:
            raise UnsupportedConfig("Reality public key is missing")
        reality_options: dict[str, object] = {
            "enabled": True,
            "public_key": public_key,
        }
        short_id = _first(query, "sid", "shortid")
        if short_id:
            reality_options["short_id"] = short_id
        tls["reality"] = reality_options
    return tls


def _transport(
    network: str,
    values: Mapping[str, Sequence[str]],
    *,
    header_type: str = "",
) -> dict | None:
    normalized = {"raw": "tcp", "websocket": "ws", "h2": "http"}.get(
        network.lower() or "tcp", network.lower() or "tcp"
    )
    if normalized == "tcp" and header_type.lower() == "http":
        normalized = "http"
    if normalized == "tcp":
        return None
    path = _first(values, "path")
    host = _first(values, "host")
    if normalized == "ws":
        transport: dict[str, object] = {"type": "ws"}
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        early_data = _first(values, "ed", "max_early_data")
        if early_data:
            try:
                transport["max_early_data"] = max(0, int(early_data))
            except ValueError as exc:
                raise UnsupportedConfig("invalid WebSocket early data") from exc
            header = _first(values, "eh", "early_data_header_name")
            if header:
                transport["early_data_header_name"] = header
        return transport
    if normalized == "grpc":
        transport = {"type": "grpc"}
        service_name = _first(values, "servicename", "service_name", "path").lstrip("/")
        if service_name:
            transport["service_name"] = service_name
        return transport
    if normalized in {"http", "h2"}:
        transport = {"type": "http"}
        hosts = _list_value(host)
        if hosts:
            transport["host"] = hosts
        if path:
            transport["path"] = path
        return transport
    if normalized == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if host:
            transport["host"] = host
        if path:
            transport["path"] = path
        return transport
    raise UnsupportedConfig(f"sing-box does not support {normalized} transport")


def _add_optional(outbound: dict, key: str, value: object) -> None:
    if value not in (None, "", [], {}):
        outbound[key] = value


def _vless_outbound(uri: str, tag: str) -> dict:
    parsed = urllib.parse.urlsplit(uri)
    query = _query(uri)
    security = (_first(query, "security") or "none").lower()
    if security == "false":
        security = "none"
    outbound: dict[str, object] = {
        "type": "vless",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": urllib.parse.unquote(parsed.username or ""),
    }
    flow = _first(query, "flow").lower()
    if flow:
        outbound["flow"] = "xtls-rprx-vision" if flow.endswith("-udp443") else flow
    packet_encoding = _first(query, "packetencoding", "packet-encoding")
    if packet_encoding in {"xudp", "packetaddr"}:
        outbound["packet_encoding"] = packet_encoding
    tls = _tls_from_query(
        query,
        enabled=security in {"tls", "reality", "xtls"},
        reality=security == "reality",
    )
    _add_optional(outbound, "tls", tls)
    transport = _transport(
        _first(query, "type", "network") or "tcp",
        query,
        header_type=_first(query, "headertype"),
    )
    _add_optional(outbound, "transport", transport)
    return outbound


def _trojan_outbound(uri: str, tag: str) -> dict:
    parsed = urllib.parse.urlsplit(uri)
    query = _query(uri)
    security = (_first(query, "security") or "tls").lower()
    if security == "false":
        security = "none"
    outbound: dict[str, object] = {
        "type": "trojan",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": urllib.parse.unquote(parsed.username or ""),
    }
    tls = _tls_from_query(
        query,
        enabled=security not in {"none"},
        reality=security == "reality",
    )
    _add_optional(outbound, "tls", tls)
    transport = _transport(
        _first(query, "type", "network") or "tcp",
        query,
        header_type=_first(query, "headertype"),
    )
    _add_optional(outbound, "transport", transport)
    return outbound


def _shadowsocks_outbound(uri: str, tag: str, parsed_uri: build.ParsedURI) -> dict:
    query = _query(uri)
    outbound: dict[str, object] = {
        "type": "shadowsocks",
        "tag": tag,
        "server": parsed_uri.server,
        "server_port": parsed_uri.port,
        "method": parsed_uri.identity[3],
        "password": parsed_uri.identity[4],
    }
    plugin_value = _first(query, "plugin")
    if plugin_value:
        plugin, separator, options = plugin_value.partition(";")
        if plugin not in {"obfs-local", "v2ray-plugin"}:
            raise UnsupportedConfig(f"unsupported Shadowsocks plugin {plugin}")
        outbound["plugin"] = plugin
        if separator and options:
            outbound["plugin_opts"] = options
    return outbound


def _decode_vmess(uri: str) -> dict:
    payload = uri[len("vmess://") :].split("#", 1)[0]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))


def _vmess_outbound(uri: str, tag: str) -> dict:
    data = _decode_vmess(uri)
    server = str(data.get("add", ""))
    outbound: dict[str, object] = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": int(data["port"]),
        "uuid": str(data["id"]),
        "security": str(data.get("scy") or data.get("security") or "auto").lower(),
        "alter_id": int(data.get("aid") or 0),
    }
    query = {
        str(key).lower(): [str(value)]
        for key, value in data.items()
        if value not in (None, "")
    }
    tls_value = str(data.get("tls") or "").lower()
    tls = _tls_from_query(query, enabled=tls_value in {"tls", "1", "true"})
    _add_optional(outbound, "tls", tls)
    transport = _transport(
        str(data.get("net") or "tcp"),
        query,
        header_type=str(data.get("type") or ""),
    )
    _add_optional(outbound, "transport", transport)
    return outbound


def _hysteria2_outbound(uri: str, tag: str) -> dict:
    parsed = urllib.parse.urlsplit(uri)
    query = _query(uri)
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    authentication = f"{username}:{password}" if username and password else username or password
    outbound: dict[str, object] = {
        "type": "hysteria2",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": authentication,
        "tls": _tls_from_query(query, enabled=True),
    }
    obfs_type = _first(query, "obfs").lower()
    if obfs_type and obfs_type != "none":
        if obfs_type not in {"salamander", "gecko"}:
            raise UnsupportedConfig(f"unsupported Hysteria2 obfs {obfs_type}")
        obfs_password = _first(query, "obfs-password", "obfspassword")
        if not obfs_password:
            raise UnsupportedConfig("Hysteria2 obfs password is missing")
        outbound["obfs"] = {"type": obfs_type, "password": obfs_password}
    for source_key, output_key in (("upmbps", "up_mbps"), ("downmbps", "down_mbps")):
        value = _first(query, source_key)
        if value:
            outbound[output_key] = _positive_number(value, source_key)
    return outbound


def _tuic_outbound(uri: str, tag: str) -> dict:
    parsed = urllib.parse.urlsplit(uri)
    query = _query(uri)
    version = _first(query, "version")
    if version and version not in {"5", "v5"}:
        raise UnsupportedConfig(f"unsupported TUIC version {version}")
    congestion = (
        _first(query, "congestion_control", "congestion_controller") or "cubic"
    ).lower()
    if congestion == "reno":
        congestion = "new_reno"
    if congestion not in {"cubic", "new_reno", "bbr"}:
        raise UnsupportedConfig(f"unsupported TUIC congestion control {congestion}")
    relay_mode = _first(
        query, "udp_relay_mode", "udp-relay-mode", "udp_relay-mode"
    ).lower()
    if relay_mode and relay_mode not in {"native", "quic"}:
        raise UnsupportedConfig(f"unsupported TUIC UDP relay mode {relay_mode}")
    outbound: dict[str, object] = {
        "type": "tuic",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": urllib.parse.unquote(parsed.username or ""),
        "password": urllib.parse.unquote(parsed.password or ""),
        "congestion_control": congestion,
        "tls": _tls_from_query(query, enabled=True),
    }
    _add_optional(outbound, "udp_relay_mode", relay_mode)
    if _truthy(_first(query, "zero_rtt_handshake", "zero-rtt-handshake")):
        outbound["zero_rtt_handshake"] = True
    return outbound


def uri_to_outbound(uri: str, tag: str) -> tuple[str, dict]:
    parsed_uri = build.parse_uri(uri)
    converters = {
        "vless": lambda: _vless_outbound(uri, tag),
        "trojan": lambda: _trojan_outbound(uri, tag),
        "shadowsocks": lambda: _shadowsocks_outbound(uri, tag, parsed_uri),
        "vmess": lambda: _vmess_outbound(uri, tag),
        "hysteria2": lambda: _hysteria2_outbound(uri, tag),
        "tuic": lambda: _tuic_outbound(uri, tag),
    }
    converter = converters.get(parsed_uri.protocol)
    if converter is None:
        raise UnsupportedConfig(f"health-check does not support {parsed_uri.protocol}")
    return parsed_uri.protocol, converter()


def collect_targets(lines: Sequence[str]) -> tuple[list[ProbeTarget], Counter]:
    targets: list[ProbeTarget] = []
    unsupported: Counter = Counter()
    for index, uri in enumerate(lines):
        tag = f"wv-{index:04d}"
        try:
            protocol, outbound = uri_to_outbound(uri, tag)
        except (build.ValidationError, HealthCheckError, ValueError, TypeError, KeyError):
            try:
                protocol = build.parse_uri(uri).protocol
            except build.ValidationError:
                protocol = "invalid"
            unsupported[protocol] += 1
            continue
        targets.append(ProbeTarget(index, tag, uri, protocol, outbound))
    return targets, unsupported


def sing_box_config(targets: Sequence[ProbeTarget], controller: str) -> dict:
    if not targets:
        raise HealthCheckError("no sing-box-compatible candidates")
    tags = [target.tag for target in targets]
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "outbounds": [
            *(target.outbound for target in targets),
            {"type": "selector", "tag": "wireveil-health", "outbounds": tags},
        ],
        "route": {"default_domain_resolver": "local"},
        "experimental": {
            "clash_api": {
                "external_controller": controller,
                "secret": "wireveil-healthcheck",
            }
        },
    }


def _run_config_check(binary: Path, config_path: Path) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            [str(binary), "check", "-c", str(config_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=45,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HealthCheckError(f"cannot validate sing-box config: {exc}") from exc
    detail = (completed.stderr or completed.stdout).strip()
    return completed.returncode == 0, detail


def validate_targets(
    binary: Path,
    targets: Sequence[ProbeTarget],
    directory: Path,
) -> tuple[list[ProbeTarget], Counter]:
    valid: list[ProbeTarget] = []
    rejected: Counter = Counter()
    batches: list[list[ProbeTarget]] = [list(targets)]
    config_path = directory / "check.json"
    while batches:
        batch = batches.pop()
        config_path.write_text(
            json.dumps(sing_box_config(batch, "127.0.0.1:19090"), ensure_ascii=False),
            encoding="utf-8",
        )
        passed, _detail = _run_config_check(binary, config_path)
        if passed:
            valid.extend(batch)
        elif len(batch) == 1:
            rejected[batch[0].protocol] += 1
        else:
            middle = len(batch) // 2
            batches.extend((batch[:middle], batch[middle:]))
    return sorted(valid, key=lambda target: target.index), rejected


def _free_controller() -> tuple[str, int]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return "127.0.0.1", int(listener.getsockname()[1])


def _api_request(url: str, *, timeout: float) -> dict:
    request = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer wireveil-healthcheck"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def _wait_for_api(process: subprocess.Popen, controller: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://{controller}/proxies"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise HealthCheckError("sing-box stopped before its health API became ready")
        try:
            _api_request(url, timeout=1.0)
            return
        except (OSError, ValueError, urllib.error.URLError):
            time.sleep(0.2)
    raise HealthCheckError("sing-box health API did not become ready")


def _probe_target(
    target: ProbeTarget,
    *,
    controller: str,
    probe_urls: Sequence[str],
    timeout_ms: int,
) -> ProbeResult:
    best_delay: int | None = None
    last_error: str | None = None
    for probe_url in probe_urls:
        query = urllib.parse.urlencode({"url": probe_url, "timeout": timeout_ms})
        endpoint = (
            f"http://{controller}/proxies/"
            f"{urllib.parse.quote(target.tag, safe='')}/delay?{query}"
        )
        try:
            payload = _api_request(endpoint, timeout=(timeout_ms / 1000) + 3)
            delay = int(payload.get("delay", 0))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace").strip()
            except OSError:
                body = ""
            last_error = f"HTTP {exc.code}: {body[:300]}" if body else f"HTTP {exc.code}"
            continue
        except (OSError, ValueError, TypeError, urllib.error.URLError) as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
            continue
        if delay > 0:
            best_delay = delay if best_delay is None else min(best_delay, delay)
            break
    return ProbeResult(target, best_delay is not None, best_delay, last_error)


def run_probes(
    binary: Path,
    targets: Sequence[ProbeTarget],
    *,
    probe_urls: Sequence[str],
    timeout_ms: int,
    workers: int,
    directory: Path,
) -> tuple[list[ProbeResult], str]:
    host, port = _free_controller()
    controller = f"{host}:{port}"
    config_path = directory / "healthcheck.json"
    log_path = directory / "sing-box.log"
    config_path.write_text(
        json.dumps(sing_box_config(targets, controller), ensure_ascii=False),
        encoding="utf-8",
    )
    passed, detail = _run_config_check(binary, config_path)
    if not passed:
        raise HealthCheckError(f"combined sing-box config is invalid: {detail[-1000:]}")

    version = subprocess.run(
        [str(binary), "version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    ).stdout.splitlines()[0]
    with log_path.open("w", encoding="utf-8") as log_handle:
        try:
            process = subprocess.Popen(
                [str(binary), "run", "-c", str(config_path)],
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            raise HealthCheckError(f"cannot start sing-box: {exc}") from exc
        try:
            _wait_for_api(process, controller)
            results: list[ProbeResult] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(
                        _probe_target,
                        target,
                        controller=controller,
                        probe_urls=probe_urls,
                        timeout_ms=timeout_ms,
                    )
                    for target in targets
                ]
                for completed, future in enumerate(
                    concurrent.futures.as_completed(futures), start=1
                ):
                    results.append(future.result())
                    if completed % 100 == 0:
                        print(
                            f"Health-check progress: {completed}/{len(targets)}",
                            flush=True,
                        )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    return sorted(results, key=lambda result: result.target.index), version


def _mix_active(results: Sequence[ProbeResult]) -> list[ProbeResult]:
    endpoint_winners: dict[tuple[str, str, int], ProbeResult] = {}
    active = sorted(
        (result for result in results if result.active),
        key=lambda item: (
            item.delay_ms if item.delay_ms is not None else sys.maxsize,
            item.target.index,
        ),
    )
    for result in active:
        parsed = build.parse_uri(result.target.uri)
        endpoint_winners.setdefault(build.endpoint_identity(parsed), result)

    groups: dict[str, list[ProbeResult]] = {
        protocol: [] for protocol in build.PROTOCOL_FILES
    }
    for result in endpoint_winners.values():
        groups[result.target.protocol].append(result)
    for group in groups.values():
        group.sort(
            key=lambda item: (
                item.delay_ms if item.delay_ms is not None else sys.maxsize,
                item.target.index,
            )
        )
    active_protocols = [protocol for protocol in build.PROTOCOL_FILES if groups[protocol]]
    offsets = {protocol: 0 for protocol in active_protocols}
    mixed: list[ProbeResult] = []
    while True:
        added = False
        for protocol in active_protocols:
            offset = offsets[protocol]
            if offset < len(groups[protocol]):
                mixed.append(groups[protocol][offset])
                offsets[protocol] += 1
                added = True
        if not added:
            return mixed


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    return f"{size / 1024:.1f} KiB"


def _update_readme(template: str, stats: dict) -> str:
    output = stats["output_file"]
    dynamic = (
        f"{README_START}\n"
        f"Последняя проверка реального подключения: **{stats['checked_at']['msk']}** "
        f"(UTC: {stats['checked_at']['utc']}). Проверено через "
        f"`{stats['engine']['version']}`: **"
        f"{stats['passing_keys_before_endpoint_deduplication']} из "
        f"{stats['candidate_keys']}** конфигураций передали HTTPS-трафик; после "
        f"endpoint-дедупликации опубликовано **{stats['active_keys']}**.\n\n"
        "| Подписка | RAW-ссылка | Ключей | Размер |\n"
        "|---|---|---:|---:|\n"
        "| Только активные и проверенные | "
        "[RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/active.txt) | "
        f"{output['keys']} | {_format_size(output['bytes'])} |\n"
        f"{README_END}"
    )
    pattern = re.compile(re.escape(README_START) + r".*?" + re.escape(README_END), re.S)
    if not pattern.search(template):
        raise HealthCheckError("README.md has no WireVeil health markers")
    return pattern.sub(dynamic, template)


def publish_results(
    results: Sequence[ProbeResult],
    *,
    candidate_lines: Sequence[str],
    conversion_unsupported: Mapping[str, int],
    runtime_rejected: Mapping[str, int],
    engine_version: str,
    probe_urls: Sequence[str],
    root: Path = ROOT,
    min_active: int = 1,
    now: dt.datetime | None = None,
) -> dict:
    mixed = _mix_active(results)
    if len(mixed) < min_active:
        raise HealthCheckError(
            f"health safety threshold failed: {len(mixed)} active keys, "
            f"minimum is {min_active}"
        )
    active_lines = [result.target.uri for result in mixed]
    content = "".join(f"{line}\n" for line in active_lines).encode("utf-8")
    if len(active_lines) != len(set(active_lines)):
        raise HealthCheckError("active subscription contains exact duplicates")
    for line in active_lines:
        build.parse_uri(line)

    checked_at = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    checked_at = checked_at.replace(microsecond=0)
    moscow = checked_at.astimezone(dt.timezone(dt.timedelta(hours=3), name="MSK"))
    delays = sorted(result.delay_ms for result in mixed if result.delay_ms is not None)
    unsupported = Counter(conversion_unsupported)
    unsupported.update(runtime_rejected)
    active_by_protocol = Counter(result.target.protocol for result in mixed)
    inactive_reasons = Counter(
        result.error or "unknown" for result in results if not result.active
    )
    tested_count = len(results)
    passing_count = sum(result.active for result in results)
    endpoint_duplicates = passing_count - len(active_lines)
    stats = {
        "schema_version": 1,
        "checked_at": {
            "utc": checked_at.isoformat().replace("+00:00", "Z"),
            "msk": moscow.isoformat(),
        },
        "engine": {"name": "sing-box", "version": engine_version},
        "probe_urls": list(probe_urls),
        "candidate_keys": len(candidate_lines),
        "tested_keys": tested_count,
        "passing_keys_before_endpoint_deduplication": passing_count,
        "active_keys": len(active_lines),
        "active_endpoint_duplicates_removed": endpoint_duplicates,
        "inactive_keys": tested_count - passing_count,
        "inactive_reasons": dict(inactive_reasons.most_common(20)),
        "unsupported_keys": sum(unsupported.values()),
        "unsupported_by_protocol": dict(sorted(unsupported.items())),
        "active_by_protocol": {
            protocol: int(active_by_protocol.get(protocol, 0))
            for protocol in build.PROTOCOL_FILES
        },
        "latency_ms": {
            "minimum": min(delays),
            "median": round(statistics.median(delays)),
            "p95": delays[min(len(delays) - 1, int(len(delays) * 0.95))],
            "maximum": max(delays),
        },
        "candidate_subscription_sha256": _sha256_bytes(
            "".join(f"{line}\n" for line in candidate_lines).encode("utf-8")
        ),
        "output_file": {
            "name": "active.txt",
            "keys": len(active_lines),
            "bytes": len(content),
            "sha256": _sha256_bytes(content),
        },
    }

    try:
        readme = (root / "README.md").read_text(encoding="utf-8")
    except OSError as exc:
        raise HealthCheckError(f"cannot read README.md: {exc}") from exc
    updated_readme = _update_readme(readme, stats)
    with tempfile.TemporaryDirectory(prefix=".wireveil-health-", dir=root) as name:
        staging = Path(name)
        (staging / "active.txt").write_bytes(content)
        (staging / "active-stats.json").write_text(
            json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (staging / "README.md").write_text(
            updated_readme, encoding="utf-8", newline="\n"
        )
        build.validate_txt(staging / "active.txt")
        json.loads((staging / "active-stats.json").read_text(encoding="utf-8"))
        for filename in ("active.txt", "active-stats.json", "README.md"):
            os.replace(staging / filename, root / filename)
    return stats


def healthcheck(
    *,
    binary: Path,
    input_path: Path = INPUT_PATH,
    root: Path = ROOT,
    expected_keys: int | None = None,
    min_active: int = 10,
    timeout_ms: int = 8000,
    workers: int = 64,
    probe_urls: Sequence[str] = DEFAULT_PROBE_URLS,
) -> dict:
    if not binary.is_file():
        raise HealthCheckError(f"sing-box binary not found: {binary}")
    lines = build.validate_txt(input_path)
    if expected_keys is not None and len(lines) != expected_keys:
        raise HealthCheckError(
            f"candidate subscription has {len(lines)} keys, expected {expected_keys}"
        )
    targets, conversion_unsupported = collect_targets(lines)
    with tempfile.TemporaryDirectory(prefix="wireveil-probe-") as name:
        directory = Path(name)
        targets, runtime_rejected = validate_targets(binary, targets, directory)
        print(
            f"Health-check: {len(lines)} candidates, {len(targets)} runtime-valid, "
            f"{sum(conversion_unsupported.values()) + sum(runtime_rejected.values())} unsupported",
            flush=True,
        )
        results, version = run_probes(
            binary,
            targets,
            probe_urls=probe_urls,
            timeout_ms=timeout_ms,
            workers=workers,
            directory=directory,
        )
    stats = publish_results(
        results,
        candidate_lines=lines,
        conversion_unsupported=conversion_unsupported,
        runtime_rejected=runtime_rejected,
        engine_version=version,
        probe_urls=probe_urls,
        root=root,
        min_active=min_active,
    )
    print(
        f"Health-check complete: {stats['active_keys']}/{stats['candidate_keys']} "
        f"keys passed a tunneled HTTPS request"
    )
    for protocol, count in stats["active_by_protocol"].items():
        print(f"  {protocol}: {count}")
    return stats


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--input", type=Path, default=INPUT_PATH)
    parser.add_argument(
        "--expected-keys",
        type=int,
        default=None,
        help="optional exact candidate count; by default every input key is tested",
    )
    parser.add_argument("--min-active", type=int, default=10)
    parser.add_argument("--timeout-ms", type=int, default=8000)
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--probe-url", action="append", dest="probe_urls")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        healthcheck(
            binary=args.sing_box,
            input_path=args.input,
            expected_keys=args.expected_keys,
            min_active=args.min_active,
            timeout_ms=args.timeout_ms,
            workers=args.workers,
            probe_urls=args.probe_urls or DEFAULT_PROBE_URLS,
        )
    except (HealthCheckError, build.BuildError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
