"""Local Mihomo subscription output and LAN HTTP serving helpers."""

from __future__ import annotations

import collections
import contextlib
import ipaddress
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping

import yaml

from scripts import mihomo_checker


DEFAULT_PORT = 18080
TOKEN_BYTES = 16
GROUP_AUTO = "AUTO"
GROUP_MANUAL = "MANUAL"
GROUP_PROXY = "PROXY"
GROUP_NAMES = (GROUP_AUTO, GROUP_MANUAL, GROUP_PROXY)
RESERVED_OUTBOUND_NAMES = {*GROUP_NAMES, "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
AUTO_TEST_URL = "https://cp.cloudflare.com/generate_204"


def new_subscription_token() -> str:
    """Return an unguessable URL component that is safe to persist locally."""
    return secrets.token_hex(TOKEN_BYTES)


def valid_subscription_token(value: object) -> bool:
    if not isinstance(value, str) or len(value) != TOKEN_BYTES * 2:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _unique_proxy_name(value: object, used: set[str]) -> str:
    base = str(value or "WireVeil node").strip() or "WireVeil node"
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base} [{suffix}]"
        suffix += 1
    used.add(candidate)
    return candidate


def _empty_build_summary(report: mihomo_checker.BatchReport) -> str:
    """Explain an empty router build without exposing source names or URLs."""
    candidate_count = len(report.node_results)
    if candidate_count == 0:
        failed = sum(source.fetch_status == "failed" for source in report.sources)
        unsupported = sum(source.parse_status == "unsupported" for source in report.sources)
        parse_failed = sum(source.parse_status == "failed" for source in report.sources)
        empty = sum(
            source.fetch_status == "ok" and not source.nodes
            for source in report.sources
        )
        details: list[str] = []
        if failed:
            details.append(f"не загрузились: {failed}")
        if unsupported:
            details.append(f"формат не поддерживается: {unsupported}")
        if parse_failed:
            details.append(f"ошибка разбора: {parse_failed}")
        if empty and not (unsupported or parse_failed):
            details.append(f"без распознанных узлов: {empty}")
        suffix = f" ({'; '.join(details)})" if details else ""
        return (
            "В выбранных источниках не найдено узлов для сборки"
            f"{suffix}. Проверьте доступность URL и формат подписки"
        )

    statuses = collections.Counter(result.overall_status for result in report.node_results)
    rejected = sum(
        result.error_category == "invalid_configuration"
        for result in report.node_results
    )
    unsupported = statuses["unsupported"]
    unfinished = sum(
        result.overall_status == "not_tested"
        and result.error_category != "invalid_configuration"
        for result in report.node_results
    )
    details = []
    if rejected:
        details.append(f"Mihomo отклонил: {rejected}")
    if unsupported:
        details.append(f"неподдерживаемый протокол: {unsupported}")
    if unfinished:
        details.append(f"не удалось проверить: {unfinished}")
    suffix = f" ({'; '.join(details)})" if details else ""
    return f"Ни один из {candidate_count} узлов не прошёл проверку конфигурации{suffix}"


def router_config_payload(report: mihomo_checker.BatchReport) -> dict[str, object]:
    """Build a complete router-ready Mihomo configuration from accepted nodes."""
    used_names = set(RESERVED_OUTBOUND_NAMES)
    proxies: list[dict[str, object]] = []
    original_to_exported: dict[str, list[str]] = {}
    for result in report.node_results:
        if result.overall_status not in {"good", "ready"}:
            continue
        proxy = dict(result.node.proxy)
        original_name = str(proxy.get("name") or "WireVeil node")
        exported_name = _unique_proxy_name(original_name, used_names)
        proxy["name"] = exported_name
        proxies.append(proxy)
        original_to_exported.setdefault(original_name, []).append(exported_name)
    if not proxies:
        raise mihomo_checker.MihomoCheckError(
            "NO_MATCHING_NODES",
            _empty_build_summary(report),
        )

    # Preserve simple dialer chains when a referenced node had to be renamed.
    for proxy in proxies:
        dialer = proxy.get("dialer-proxy")
        if isinstance(dialer, str) and dialer in original_to_exported:
            proxy["dialer-proxy"] = original_to_exported[dialer][0]

    proxy_names = [str(proxy["name"]) for proxy in proxies]
    return {
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "off",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": GROUP_AUTO,
                "type": "url-test",
                "proxies": list(proxy_names),
                "url": AUTO_TEST_URL,
                "interval": 900,
                "tolerance": 100,
                "lazy": True,
            },
            {
                "name": GROUP_MANUAL,
                "type": "select",
                "proxies": list(proxy_names),
            },
            {
                "name": GROUP_PROXY,
                "type": "select",
                "proxies": [GROUP_AUTO, GROUP_MANUAL],
            },
        ],
        "rules": [
            "DOMAIN-SUFFIX,lan,DIRECT",
            "DOMAIN-SUFFIX,local,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR6,::1/128,DIRECT,no-resolve",
            "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
            "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
            f"MATCH,{GROUP_PROXY}",
        ],
    }


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


def build_router_yaml(report: mihomo_checker.BatchReport, path: Path) -> bytes:
    """Atomically export a complete router-ready config with accepted nodes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        _write_private_yaml(temporary, router_config_payload(report))
        payload = temporary.read_bytes()
        temporary.replace(path)
        return payload
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)


def discover_lan_ip() -> str:
    """Best-effort LAN address discovery without transmitting application data."""
    candidates: list[str] = []
    with contextlib.suppress(OSError):
        candidates.extend(socket.gethostbyname_ex(socket.gethostname())[2])
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 80))
        candidates.append(str(probe.getsockname()[0]))
    except OSError:
        pass
    finally:
        probe.close()
    usable: list[ipaddress.IPv4Address] = []
    for value in dict.fromkeys(candidates):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if (
            address.version == 4
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_unspecified
        ):
            usable.append(address)
    if usable:
        # Home routers most commonly expose a 192.168/16 LAN. Prefer that over
        # virtual VPN adapters, which frequently use 10/8 and are unreachable
        # from the router itself.
        usable.sort(
            key=lambda address: (
                0 if address in ipaddress.ip_network("192.168.0.0/16") else
                1 if address.is_private else 2,
                candidates.index(str(address)),
            )
        )
        return str(usable[0])
    return "127.0.0.1"


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class RouterSubscriptionServer:
    """Serve one private YAML document and nothing else on the local network."""

    def __init__(self, token: str, *, lan_ip_provider=discover_lan_ip) -> None:  # type: ignore[no-untyped-def]
        if not valid_subscription_token(token):
            raise ValueError("invalid subscription token")
        self.token = token
        self._lan_ip_provider = lan_ip_provider
        self._content = b""
        self._lock = threading.Lock()
        self._server: _ReusableThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self) -> int | None:
        server = self._server
        return int(server.server_address[1]) if server is not None else None

    @property
    def route(self) -> str:
        return f"/subscription/{self.token}.yaml"

    @property
    def url(self) -> str | None:
        port = self.port
        if port is None:
            return None
        return f"http://{self._lan_ip_provider()}:{port}{self.route}"

    def set_content(self, content: bytes) -> None:
        if not content:
            raise ValueError("subscription content is empty")
        with self._lock:
            self._content = bytes(content)

    def start(self, port: int = DEFAULT_PORT) -> str:
        if self._server is not None:
            return self.url or ""
        if not 0 <= int(port) <= 65535:
            raise ValueError("port must be between 0 and 65535")
        with self._lock:
            if not self._content:
                raise ValueError("subscription content is empty")
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve_subscription(self, *, send_body: bool) -> None:
                if self.path != owner.route:
                    self.send_error(404)
                    return
                with owner._lock:
                    payload = owner._content
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                if send_body:
                    self.wfile.write(payload)

            def do_GET(self) -> None:  # noqa: N802
                self._serve_subscription(send_body=True)

            def do_HEAD(self) -> None:  # noqa: N802
                self._serve_subscription(send_body=False)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = _ReusableThreadingHTTPServer(("0.0.0.0", int(port)), Handler)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever,
            name="wireveil-router-subscription",
            daemon=True,
        )
        self._thread.start()
        return self.url or ""

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
