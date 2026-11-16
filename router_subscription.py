"""Local Mihomo subscription output and LAN HTTP serving helpers."""

from __future__ import annotations

import contextlib
import ipaddress
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scripts import mihomo_checker


DEFAULT_PORT = 18080
TOKEN_BYTES = 16


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


def build_router_yaml(report: mihomo_checker.BatchReport, path: Path) -> bytes:
    """Export only fully working nodes and return the exact private payload."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        mihomo_checker.export_private_yaml(report, temporary, statuses=("good",))
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

            def do_GET(self) -> None:  # noqa: N802
                if self.path != owner.route:
                    self.send_error(404)
                    return
                with owner._lock:
                    payload = owner._content
                self.send_response(200)
                self.send_header("Content-Type", "application/yaml; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(payload)

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
