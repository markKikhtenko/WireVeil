"""Isolated self-diagnostics for the bundled Mihomo core.

The diagnostic runner deliberately does not reuse subscriptions, OpenClash
configuration or an already running controller.  It owns one temporary Mihomo
process and removes its private configuration in ``finally``.
"""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol


NETWORK_TIMEOUT_SECONDS = 8.0
CONTROLLER_START_TIMEOUT_SECONDS = 8.0
USER_AGENT = "WireVeil-Mihomo-Diagnostics/1.0"
DiagnosticStatus = Literal["PASS", "FAIL", "TIMEOUT", "SKIPPED", "WARNING"]


@dataclass(frozen=True)
class ControlSite:
    name: str
    url: str
    expected_statuses: tuple[int, ...] | None = None
    expected_range: tuple[int, int] | None = None

    def accepts(self, status: int) -> bool:
        if self.expected_statuses is not None:
            return status in self.expected_statuses
        if self.expected_range is not None:
            return self.expected_range[0] <= status <= self.expected_range[1]
        return False

    @property
    def expectation(self) -> str:
        if self.expected_statuses is not None:
            return "/".join(str(item) for item in self.expected_statuses)
        if self.expected_range is not None:
            return f"{self.expected_range[0]}–{self.expected_range[1]}"
        return "—"


CONTROL_SITES = (
    ControlSite("Example", "https://example.com/", expected_range=(200, 399)),
    ControlSite("GitHub", "https://github.com/", expected_range=(200, 399)),
    ControlSite("Microsoft", "https://www.microsoft.com/", expected_range=(200, 399)),
    ControlSite("Google 204", "https://www.gstatic.com/generate_204", expected_statuses=(204,)),
    ControlSite("Cloudflare 204", "https://cp.cloudflare.com/generate_204", expected_statuses=(204,)),
)


@dataclass(frozen=True)
class DiagnosticResult:
    group: str
    check: str
    status: DiagnosticStatus
    elapsed_ms: int | None = None
    http_status: int | None = None
    detail: str = ""
    site: str | None = None
    url: str | None = None
    method: str | None = None


@dataclass(frozen=True)
class ApiObservation:
    status: int
    body: bytes
    elapsed_ms: int


@dataclass(frozen=True)
class HttpObservation:
    status: int
    elapsed_ms: int


@dataclass(frozen=True)
class DiagnosticReport:
    wireveil_version: str
    mihomo_version: str
    windows_version: str
    started_at: str
    finished_at: str
    binary_path: str | None
    results: tuple[DiagnosticResult, ...]
    conclusion: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "wireveil_version": self.wireveil_version,
            "mihomo_version": self.mihomo_version,
            "windows_version": self.windows_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "binary": Path(self.binary_path).name if self.binary_path else None,
            "results": [asdict(result) for result in self.results],
            "conclusion": self.conclusion,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n"

    def to_text(self) -> str:
        lines = [
            "WireVeil — диагностика Mihomo",
            f"WireVeil: {self.wireveil_version}",
            f"Mihomo: {self.mihomo_version}",
            f"Windows: {self.windows_version}",
            f"Начало: {self.started_at}",
            f"Завершение: {self.finished_at}",
            f"Исполняемый файл: {Path(self.binary_path).name if self.binary_path else 'не найден'}",
            "",
            "Проверки:",
        ]
        for result in self.results:
            timing = f" · {result.elapsed_ms} ms" if result.elapsed_ms is not None else ""
            http = f" · HTTP {result.http_status}" if result.http_status is not None else ""
            url = f" · {result.url}" if result.url else ""
            detail = f" · {result.detail}" if result.detail else ""
            lines.append(
                f"[{result.status}] {result.group} / {result.check}{url}{http}{timing}{detail}"
            )
        lines.extend(("", "Заключение:", self.conclusion, ""))
        return "\n".join(lines)


class DiagnosticFailure(RuntimeError):
    def __init__(self, message: str, *, timeout: bool = False):
        super().__init__(message)
        self.timeout = timeout


class DiagnosticCancelled(DiagnosticFailure):
    pass


class RuntimeProtocol(Protocol):
    controller_port: int
    proxy_port: int

    def binary_version(self, cancel_event: threading.Event) -> tuple[str, int]: ...
    def prepare(self) -> None: ...
    def validate_config(self, cancel_event: threading.Event) -> tuple[str, int]: ...
    def launch(self) -> int: ...
    def wait_for_controller(self, cancel_event: threading.Event, timeout: float) -> int: ...
    def api_request(self, path: str, *, authorized: bool, timeout: float) -> ApiObservation: ...
    def is_running(self) -> bool: ...
    def stop(self) -> None: ...


RuntimeFactory = Callable[[Path], RuntimeProtocol]
HttpProbe = Callable[[str, float, str | None], HttpObservation]
ProgressCallback = Callable[[DiagnosticResult, int, int], None]


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _safe_detail(value: object, limit: int = 600) -> str:
    text = " ".join(str(value).replace("\x00", " ").split())
    text = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(secret|token|password)(\s*[=:]\s*)[^\s,;]+", r"\1\2[REDACTED]", text)
    return text[:limit]


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _hidden_process_options() -> dict[str, object]:
    if os.name != "nt":
        return {}
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _terminate_process(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    try:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except (OSError, subprocess.SubprocessError):
        pass


class MihomoDiagnosticRuntime:
    """Temporary Mihomo instance used only by one diagnostic run."""

    def __init__(self, binary: Path):
        self.binary = binary
        self.controller_port = _free_local_port()
        self.proxy_port = _free_local_port()
        while self.proxy_port == self.controller_port:
            self.proxy_port = _free_local_port()
        self.secret = secrets.token_urlsafe(32)
        self.process: subprocess.Popen[str] | None = None
        self.validation_process: subprocess.Popen[str] | None = None
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._config_path: Path | None = None
        self._log_handle = None
        self._lock = threading.RLock()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.controller_port}"

    def prepare(self) -> None:
        if self._temporary is not None:
            return
        self._temporary = tempfile.TemporaryDirectory(prefix="wireveil-mihomo-diagnostic-")
        root = Path(self._temporary.name)
        self._config_path = root / "config.yaml"
        payload = {
            "allow-lan": False,
            "bind-address": "127.0.0.1",
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            "mixed-port": self.proxy_port,
            "external-controller": f"127.0.0.1:{self.controller_port}",
            "secret": self.secret,
            "proxies": [],
            "proxy-groups": [],
            "rules": ["MATCH,DIRECT"],
        }
        # JSON is a YAML 1.2 subset and keeps this isolated diagnostic free of
        # additional serializer state while remaining valid Mihomo input.
        self._config_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        try:
            self._config_path.chmod(0o600)
        except OSError:
            pass

    def _communicate_cancellable(
        self,
        process: subprocess.Popen[str],
        cancel_event: threading.Event,
        timeout: float,
    ) -> tuple[str, str, int]:
        started = time.perf_counter()
        deadline = time.monotonic() + timeout
        while True:
            if cancel_event.is_set():
                _terminate_process(process)
                raise DiagnosticCancelled("Диагностика отменена")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(process)
                raise DiagnosticFailure("Превышено время ожидания процесса Mihomo", timeout=True)
            try:
                stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                elapsed = round((time.perf_counter() - started) * 1000)
                return stdout or "", stderr or "", elapsed
            except subprocess.TimeoutExpired:
                continue

    def binary_version(self, cancel_event: threading.Event) -> tuple[str, int]:
        try:
            process = subprocess.Popen(
                [str(self.binary), "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                **_hidden_process_options(),
            )
        except OSError as exc:
            raise DiagnosticFailure(f"Не удалось запустить mihomo -v: {_safe_detail(exc)}") from exc
        stdout, stderr, elapsed = self._communicate_cancellable(process, cancel_event, 5.0)
        detail = _safe_detail(stdout or stderr)
        if process.returncode != 0 or not detail:
            raise DiagnosticFailure(detail or f"mihomo -v завершился с кодом {process.returncode}")
        return detail, elapsed

    def validate_config(self, cancel_event: threading.Event) -> tuple[str, int]:
        self.prepare()
        assert self._temporary is not None and self._config_path is not None
        try:
            process = subprocess.Popen(
                [
                    str(self.binary), "-d", self._temporary.name,
                    "-t", "-f", str(self._config_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                **_hidden_process_options(),
            )
        except OSError as exc:
            raise DiagnosticFailure(f"Не удалось проверить конфигурацию: {_safe_detail(exc)}") from exc
        with self._lock:
            self.validation_process = process
        try:
            stdout, stderr, elapsed = self._communicate_cancellable(process, cancel_event, 8.0)
        finally:
            with self._lock:
                self.validation_process = None
        detail = _safe_detail((stdout + " " + stderr).strip())
        if process.returncode != 0:
            raise DiagnosticFailure(detail or f"Mihomo отклонил конфигурацию ({process.returncode})")
        return detail or "Минимальная конфигурация принята", elapsed

    def launch(self) -> int:
        self.prepare()
        assert self._temporary is not None and self._config_path is not None
        log_path = Path(self._temporary.name) / "mihomo.log"
        started = time.perf_counter()
        try:
            self._log_handle = log_path.open("w", encoding="utf-8")
            process = subprocess.Popen(
                [
                    str(self.binary), "-d", self._temporary.name,
                    "-f", str(self._config_path),
                ],
                stdout=self._log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                **_hidden_process_options(),
            )
        except OSError as exc:
            if self._log_handle is not None:
                self._log_handle.close()
                self._log_handle = None
            raise DiagnosticFailure(f"Не удалось запустить процесс Mihomo: {_safe_detail(exc)}") from exc
        with self._lock:
            self.process = process
        time.sleep(0.05)
        if process.poll() is not None:
            raise DiagnosticFailure(f"Процесс Mihomo сразу завершился с кодом {process.returncode}")
        return round((time.perf_counter() - started) * 1000)

    def wait_for_controller(self, cancel_event: threading.Event, timeout: float) -> int:
        started = time.perf_counter()
        deadline = time.monotonic() + timeout
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            if cancel_event.is_set():
                raise DiagnosticCancelled("Диагностика отменена")
            if not self.is_running():
                raise DiagnosticFailure("Процесс Mihomo завершился до запуска локального API")
            try:
                with socket.create_connection(("127.0.0.1", self.controller_port), timeout=0.25):
                    return round((time.perf_counter() - started) * 1000)
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        detail = _safe_detail(last_error) if last_error else "порт контроллера не открылся"
        raise DiagnosticFailure(f"Локальный API Mihomo недоступен: {detail}", timeout=True)

    def api_request(self, path: str, *, authorized: bool, timeout: float) -> ApiObservation:
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if authorized:
            headers["Authorization"] = f"Bearer {self.secret}"
        request = urllib.request.Request(self.base_url + path, headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        started = time.perf_counter()
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read(256 * 1024)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            body = exc.read(256 * 1024)
            status = int(exc.code)
        elapsed = round((time.perf_counter() - started) * 1000)
        return ApiObservation(status=status, body=body, elapsed_ms=elapsed)

    def is_running(self) -> bool:
        with self._lock:
            return self.process is not None and self.process.poll() is None

    def stop(self) -> None:
        with self._lock:
            process = self.process
            validation = self.validation_process
            self.process = None
            self.validation_process = None
        _terminate_process(validation)
        _terminate_process(process)
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            except OSError:
                pass
            self._log_handle = None
        with self._lock:
            temporary = self._temporary
            self._temporary = None
            self._config_path = None
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                pass


def https_probe(url: str, timeout: float, proxy_url: str | None = None) -> HttpObservation:
    """Perform a verified HTTPS request, explicitly bypassing system proxies."""

    proxy_handler = (
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        if proxy_url
        else urllib.request.ProxyHandler({})
    )
    opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler())
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        method="GET",
    )
    started = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(4096)
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        try:
            exc.read(4096)
        except OSError:
            pass
        status = int(exc.code)
    return HttpObservation(status=status, elapsed_ms=round((time.perf_counter() - started) * 1000))


def _exception_root(exc: BaseException) -> BaseException:
    current = exc
    seen: set[int] = set()
    while isinstance(current, urllib.error.URLError) and isinstance(current.reason, BaseException):
        if id(current) in seen:
            break
        seen.add(id(current))
        current = current.reason
    return current


def classify_network_error(exc: BaseException, *, proxy: bool = False) -> tuple[DiagnosticStatus, str]:
    root = _exception_root(exc)
    lowered = str(root).casefold()
    if isinstance(root, (TimeoutError, socket.timeout)) or "timed out" in lowered or "timeout" in lowered:
        return "TIMEOUT", "Истекло время ожидания сетевой проверки"
    if isinstance(root, (ssl.SSLError, ssl.CertificateError)) or any(
        marker in lowered for marker in ("certificate", "tls", "ssl", "handshake")
    ):
        return "FAIL", f"Ошибка TLS: {_safe_detail(root)}"
    if isinstance(root, socket.gaierror) or any(
        marker in lowered for marker in ("name or service", "getaddrinfo", "no such host", "dns")
    ):
        return "FAIL", f"Ошибка DNS: {_safe_detail(root)}"
    if proxy:
        return "FAIL", f"Ошибка HTTP-прокси: {_safe_detail(root)}"
    return "FAIL", f"Ошибка HTTPS-подключения: {_safe_detail(root)}"


def _json_mapping(observation: ApiObservation) -> Mapping[str, object]:
    try:
        payload = json.loads(observation.body.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise DiagnosticFailure(f"Некорректный JSON локального API: {_safe_detail(exc)}") from exc
    if not isinstance(payload, Mapping):
        raise DiagnosticFailure("Локальный API вернул JSON неожиданного формата")
    return payload


class MihomoDiagnosticRunner:
    """Run deterministic core and network checks without touching app state."""

    TOTAL_CHECKS = 8 + len(CONTROL_SITES) * 3

    def __init__(
        self,
        binary: Path | None,
        wireveil_version: str,
        *,
        timeout: float = NETWORK_TIMEOUT_SECONDS,
        runtime_factory: RuntimeFactory = MihomoDiagnosticRuntime,
        http_probe: HttpProbe = https_probe,
    ):
        self.binary = binary
        self.wireveil_version = wireveil_version
        self.timeout = timeout
        self.runtime_factory = runtime_factory
        self.http_probe = http_probe
        self.cancel_event = threading.Event()
        self._runtime: RuntimeProtocol | None = None
        self._lock = threading.Lock()

    def cancel(self) -> None:
        self.cancel_event.set()
        with self._lock:
            runtime = self._runtime
        if runtime is not None:
            runtime.stop()

    @staticmethod
    def _skipped(group: str, check: str, detail: str, **kwargs: object) -> DiagnosticResult:
        return DiagnosticResult(group, check, "SKIPPED", detail=detail, **kwargs)  # type: ignore[arg-type]

    def run(self, progress: ProgressCallback | None = None) -> DiagnosticReport:
        started_at = _now_iso()
        results: list[DiagnosticResult] = []
        mihomo_version = "не определена"

        def emit(result: DiagnosticResult) -> None:
            results.append(result)
            if progress is not None:
                progress(result, len(results), self.TOTAL_CHECKS)

        binary = self.binary
        if binary is None or not binary.is_file():
            emit(DiagnosticResult("Ядро", "Наличие mihomo.exe", "FAIL", detail="mihomo.exe не найден"))
            reason = "mihomo.exe не найден"
            for check in (
                "Версия ядра", "Минимальная конфигурация", "Запуск процесса",
                "Доступность локального API", "Авторизация API",
                "Ответ /version", "Ответ /proxies",
            ):
                emit(self._skipped("Ядро", check, reason))
            self._run_sites(None, False, False, emit, reason)
            return self._report(started_at, mihomo_version, results)

        emit(DiagnosticResult("Ядро", "Наличие mihomo.exe", "PASS", detail=binary.name))
        runtime = self.runtime_factory(binary)
        with self._lock:
            self._runtime = runtime
        config_ok = False
        launch_ok = False
        controller_ok = False
        auth_ok = False
        proxies_ok = False
        blocking_reason = "предыдущий этап не выполнен"
        try:
            try:
                mihomo_version, elapsed = runtime.binary_version(self.cancel_event)
                emit(DiagnosticResult("Ядро", "Версия ядра", "PASS", elapsed, detail=mihomo_version))
            except DiagnosticCancelled:
                emit(self._skipped("Ядро", "Версия ядра", "Диагностика отменена"))
            except DiagnosticFailure as exc:
                emit(DiagnosticResult(
                    "Ядро", "Версия ядра", "TIMEOUT" if exc.timeout else "FAIL",
                    detail=_safe_detail(exc),
                ))
            except BaseException as exc:
                emit(DiagnosticResult("Ядро", "Версия ядра", "FAIL", detail=_safe_detail(exc)))

            if self.cancel_event.is_set():
                emit(self._skipped("Ядро", "Минимальная конфигурация", "Диагностика отменена"))
                blocking_reason = "диагностика отменена"
            else:
                try:
                    runtime.prepare()
                    detail, elapsed = runtime.validate_config(self.cancel_event)
                    config_ok = True
                    emit(DiagnosticResult(
                        "Ядро", "Минимальная конфигурация", "PASS", elapsed,
                        detail=detail,
                    ))
                except DiagnosticCancelled:
                    emit(self._skipped("Ядро", "Минимальная конфигурация", "Диагностика отменена"))
                    blocking_reason = "диагностика отменена"
                except DiagnosticFailure as exc:
                    status: DiagnosticStatus = "TIMEOUT" if exc.timeout else "FAIL"
                    emit(DiagnosticResult(
                        "Ядро", "Минимальная конфигурация", status,
                        detail=_safe_detail(exc),
                    ))
                    blocking_reason = "Mihomo не загрузил минимальную конфигурацию"
                except BaseException as exc:
                    emit(DiagnosticResult(
                        "Ядро", "Минимальная конфигурация", "FAIL", detail=_safe_detail(exc),
                    ))
                    blocking_reason = "ошибка подготовки минимальной конфигурации"

            if config_ok and not self.cancel_event.is_set():
                try:
                    elapsed = runtime.launch()
                    launch_ok = True
                    emit(DiagnosticResult(
                        "Ядро", "Запуск процесса", "PASS", elapsed,
                        detail="Временный процесс Mihomo запущен",
                    ))
                except DiagnosticFailure as exc:
                    emit(DiagnosticResult(
                        "Ядро", "Запуск процесса", "TIMEOUT" if exc.timeout else "FAIL",
                        detail=_safe_detail(exc),
                    ))
                    blocking_reason = "временный процесс Mihomo не запущен"
                except BaseException as exc:
                    emit(DiagnosticResult(
                        "Ядро", "Запуск процесса", "FAIL", detail=_safe_detail(exc),
                    ))
                    blocking_reason = "временный процесс Mihomo не запущен"
            else:
                emit(self._skipped("Ядро", "Запуск процесса", blocking_reason))

            if launch_ok and not self.cancel_event.is_set():
                try:
                    elapsed = runtime.wait_for_controller(
                        self.cancel_event, CONTROLLER_START_TIMEOUT_SECONDS
                    )
                    controller_ok = True
                    emit(DiagnosticResult(
                        "API", "Доступность локального API", "PASS", elapsed,
                        detail=f"127.0.0.1:{runtime.controller_port}",
                    ))
                except DiagnosticCancelled:
                    emit(self._skipped("API", "Доступность локального API", "Диагностика отменена"))
                    blocking_reason = "диагностика отменена"
                except DiagnosticFailure as exc:
                    emit(DiagnosticResult(
                        "API", "Доступность локального API",
                        "TIMEOUT" if exc.timeout else "FAIL", detail=_safe_detail(exc),
                    ))
                    blocking_reason = "локальный контроллер недоступен"
                except BaseException as exc:
                    status, detail = classify_network_error(exc)
                    emit(DiagnosticResult("API", "Доступность локального API", status, detail=detail))
                    blocking_reason = "локальный контроллер недоступен"
            else:
                emit(self._skipped("API", "Доступность локального API", blocking_reason))

            if controller_ok and not self.cancel_event.is_set():
                try:
                    unauthorized = runtime.api_request("/version", authorized=False, timeout=2.0)
                    authorized = runtime.api_request("/version", authorized=True, timeout=2.0)
                    if authorized.status in {401, 403}:
                        emit(DiagnosticResult(
                            "API", "Авторизация API", "FAIL", authorized.elapsed_ms,
                            authorized.status, "Контроллер отклонил диагностический токен",
                        ))
                        blocking_reason = "авторизация локального API не пройдена"
                    elif authorized.status != 200:
                        emit(DiagnosticResult(
                            "API", "Авторизация API", "FAIL", authorized.elapsed_ms,
                            authorized.status, "Авторизованный запрос не получил HTTP 200",
                        ))
                        blocking_reason = "авторизация локального API не подтверждена"
                    elif unauthorized.status not in {401, 403}:
                        auth_ok = True
                        emit(DiagnosticResult(
                            "API", "Авторизация API", "WARNING", authorized.elapsed_ms,
                            unauthorized.status,
                            "Авторизованный запрос работает, но запрос без токена не был отклонён",
                        ))
                    else:
                        auth_ok = True
                        emit(DiagnosticResult(
                            "API", "Авторизация API", "PASS", authorized.elapsed_ms,
                            authorized.status, "Токен принят; запрос без токена отклонён",
                        ))
                except BaseException as exc:
                    status, detail = classify_network_error(exc)
                    emit(DiagnosticResult("API", "Авторизация API", status, detail=detail))
                    blocking_reason = "ошибка проверки авторизации API"
            else:
                emit(self._skipped("API", "Авторизация API", blocking_reason))

            if auth_ok and not self.cancel_event.is_set():
                observation: ApiObservation | None = None
                try:
                    observation = runtime.api_request("/version", authorized=True, timeout=2.0)
                    if observation.status != 200:
                        raise DiagnosticFailure(f"/version вернул HTTP {observation.status}")
                    payload = _json_mapping(observation)
                    api_version = payload.get("version")
                    if not isinstance(api_version, str) or not api_version.strip():
                        raise DiagnosticFailure("В ответе /version отсутствует строка version")
                    mihomo_version = _safe_detail(api_version, 200)
                    emit(DiagnosticResult(
                        "API", "Ответ /version", "PASS", observation.elapsed_ms,
                        observation.status, f"Версия: {mihomo_version}",
                    ))
                except DiagnosticFailure as exc:
                    emit(DiagnosticResult(
                        "API", "Ответ /version", "FAIL",
                        observation.elapsed_ms if observation is not None else None,
                        observation.status if observation is not None else None,
                        _safe_detail(exc),
                    ))
                except BaseException as exc:
                    status, detail = classify_network_error(exc)
                    emit(DiagnosticResult("API", "Ответ /version", status, detail=detail))
            else:
                emit(self._skipped("API", "Ответ /version", blocking_reason))

            if auth_ok and not self.cancel_event.is_set():
                observation = None
                try:
                    observation = runtime.api_request("/proxies", authorized=True, timeout=2.0)
                    if observation.status != 200:
                        raise DiagnosticFailure(f"/proxies вернул HTTP {observation.status}")
                    payload = _json_mapping(observation)
                    proxies = payload.get("proxies")
                    if not isinstance(proxies, Mapping) or "DIRECT" not in proxies:
                        raise DiagnosticFailure("В ответе /proxies отсутствует DIRECT")
                    proxies_ok = True
                    emit(DiagnosticResult(
                        "API", "Ответ /proxies", "PASS", observation.elapsed_ms,
                        observation.status, "Прокси DIRECT доступен",
                    ))
                except DiagnosticFailure as exc:
                    emit(DiagnosticResult(
                        "API", "Ответ /proxies", "FAIL",
                        observation.elapsed_ms if observation is not None else None,
                        observation.status if observation is not None else None,
                        _safe_detail(exc),
                    ))
                    blocking_reason = "ответ /proxies некорректен"
                except BaseException as exc:
                    status, detail = classify_network_error(exc)
                    emit(DiagnosticResult("API", "Ответ /proxies", status, detail=detail))
                    blocking_reason = "запрос /proxies завершился ошибкой"
            else:
                emit(self._skipped("API", "Ответ /proxies", blocking_reason))

            api_ready = controller_ok and auth_ok and proxies_ok
            proxy_ready = launch_ok and runtime.is_running()
            reason = blocking_reason if not api_ready else ""
            self._run_sites(runtime, api_ready, proxy_ready, emit, reason)
        finally:
            runtime.stop()
            with self._lock:
                if self._runtime is runtime:
                    self._runtime = None
        return self._report(started_at, mihomo_version, results)

    def _run_sites(
        self,
        runtime: RuntimeProtocol | None,
        api_ready: bool,
        proxy_ready: bool,
        emit: Callable[[DiagnosticResult], None],
        blocking_reason: str,
    ) -> None:
        for site in CONTROL_SITES:
            emit(self._http_result(site, "Прямое HTTPS", None))

            if self.cancel_event.is_set():
                emit(self._skipped(
                    "Сайты", f"{site.name} — URL-test API", "Диагностика отменена",
                    site=site.name, url=site.url, method="api",
                ))
            elif runtime is None or not api_ready:
                emit(self._skipped(
                    "Сайты", f"{site.name} — URL-test API",
                    blocking_reason or "API Mihomo не готов к URL-test",
                    site=site.name, url=site.url, method="api",
                ))
            else:
                emit(self._api_delay_result(runtime, site))

            if self.cancel_event.is_set():
                emit(self._skipped(
                    "Сайты", f"{site.name} — HTTP-прокси", "Диагностика отменена",
                    site=site.name, url=site.url, method="proxy",
                ))
            elif runtime is None or not proxy_ready:
                emit(self._skipped(
                    "Сайты", f"{site.name} — HTTP-прокси",
                    blocking_reason or "временный HTTP-прокси Mihomo не запущен",
                    site=site.name, url=site.url, method="proxy",
                ))
            else:
                proxy_url = f"http://127.0.0.1:{runtime.proxy_port}"
                emit(self._http_result(site, "HTTP-прокси", proxy_url))

    def _http_result(
        self, site: ControlSite, label: str, proxy_url: str | None
    ) -> DiagnosticResult:
        method = "proxy" if proxy_url else "direct"
        check = f"{site.name} — {label}"
        if self.cancel_event.is_set():
            return self._skipped(
                "Сайты", check, "Диагностика отменена",
                site=site.name, url=site.url, method=method,
            )
        try:
            observation = self.http_probe(site.url, self.timeout, proxy_url)
        except BaseException as exc:
            status, detail = classify_network_error(exc, proxy=proxy_url is not None)
            return DiagnosticResult(
                "Сайты", check, status, detail=detail,
                site=site.name, url=site.url, method=method,
            )
        if site.accepts(observation.status):
            return DiagnosticResult(
                "Сайты", check, "PASS", observation.elapsed_ms, observation.status,
                f"Ожидался HTTP {site.expectation}", site.name, site.url, method,
            )
        return DiagnosticResult(
            "Сайты", check, "FAIL", observation.elapsed_ms, observation.status,
            f"Получен HTTP {observation.status}, ожидался {site.expectation}",
            site.name, site.url, method,
        )

    def _api_delay_result(
        self, runtime: RuntimeProtocol, site: ControlSite
    ) -> DiagnosticResult:
        check = f"{site.name} — URL-test API"
        query = urllib.parse.urlencode({"url": site.url, "timeout": round(self.timeout * 1000)})
        try:
            observation = runtime.api_request(
                f"/proxies/DIRECT/delay?{query}", authorized=True,
                timeout=self.timeout + 2.0,
            )
        except BaseException as exc:
            status, detail = classify_network_error(exc)
            return DiagnosticResult(
                "Сайты", check, status, detail=detail,
                site=site.name, url=site.url, method="api",
            )
        if observation.status == 200:
            try:
                payload = _json_mapping(observation)
                delay = payload.get("delay")
                if isinstance(delay, bool) or not isinstance(delay, (int, float)) or delay < 0:
                    raise DiagnosticFailure("В ответе URL-test отсутствует корректное значение delay")
            except DiagnosticFailure as exc:
                return DiagnosticResult(
                    "Сайты", check, "FAIL", observation.elapsed_ms, observation.status,
                    _safe_detail(exc), site.name, site.url, "api",
                )
            return DiagnosticResult(
                "Сайты", check, "PASS", round(float(delay)), observation.status,
                f"API ответил за {observation.elapsed_ms} ms; delay={round(float(delay))} ms",
                site.name, site.url, "api",
            )
        reason = _safe_detail(observation.body.decode("utf-8", errors="replace"), 300)
        if observation.status in {503, 504}:
            timed_out = any(marker in reason.casefold() for marker in ("timeout", "deadline"))
            status: DiagnosticStatus = "TIMEOUT" if timed_out else "FAIL"
            detail = (
                f"URL-test API вернул HTTP {observation.status}"
                + (f": {reason}" if reason else "")
                + "; это не доказывает неисправность всего контроллера"
            )
        else:
            status = "FAIL"
            detail = f"URL-test API вернул HTTP {observation.status}"
            if reason:
                detail += f": {reason}"
        return DiagnosticResult(
            "Сайты", check, status, observation.elapsed_ms, observation.status,
            detail, site.name, site.url, "api",
        )

    def _report(
        self, started_at: str, mihomo_version: str, results: list[DiagnosticResult]
    ) -> DiagnosticReport:
        return DiagnosticReport(
            wireveil_version=self.wireveil_version,
            mihomo_version=mihomo_version,
            windows_version=platform.platform(),
            started_at=started_at,
            finished_at=_now_iso(),
            binary_path=str(self.binary) if self.binary else None,
            results=tuple(results),
            conclusion=analyze_results(results),
        )


def analyze_results(results: list[DiagnosticResult] | tuple[DiagnosticResult, ...]) -> str:
    network = [result for result in results if result.group == "Сайты"]
    direct = [result for result in network if result.method == "direct"]
    api = [result for result in network if result.method == "api"]
    proxy = [result for result in network if result.method == "proxy"]
    launch = next((result for result in results if result.check == "Запуск процесса"), None)
    controller = next(
        (result for result in results if result.check == "Доступность локального API"), None
    )

    if network and all(result.status == "PASS" for result in network):
        return "Все три метода работают для всех контрольных сайтов. Базовая работоспособность Mihomo подтверждена."
    if launch is not None and launch.status in {"FAIL", "TIMEOUT", "SKIPPED"}:
        return "Временный экземпляр Mihomo не удалось запустить. Причина относится к ядру или минимальной конфигурации; пользовательские подписки не использовались."
    if any(result.status == "PASS" for result in direct) and (
        controller is None or controller.status not in {"PASS", "WARNING"}
    ):
        return "Прямое HTTPS работает, а локальный API Mihomo не отвечает. Вероятна проблема запуска контроллера или связи с ним."
    if direct and proxy and all(result.status == "PASS" for result in direct + proxy) and any(
        result.status in {"FAIL", "TIMEOUT"} for result in api
    ):
        return "Прямое HTTPS и HTTP-прокси Mihomo работают, но URL-test API возвращает ошибки. Вероятна проблема механизма API-проверки, а не передачи трафика через Mihomo."

    by_site: dict[str, list[DiagnosticResult]] = {}
    for result in network:
        if result.site:
            by_site.setdefault(result.site, []).append(result)
    unavailable = [
        site for site, site_results in by_site.items()
        if any(item.method == "direct" and item.status in {"FAIL", "TIMEOUT"} for item in site_results)
        and not any(item.status == "PASS" for item in site_results)
    ]
    if unavailable:
        names = ", ".join(unavailable)
        return f"Контрольные сайты недоступны напрямую и через Mihomo: {names}. Следует исследовать сетевое окружение; это не доказывает неисправность чекера."
    if any(result.status == "PASS" for result in direct + proxy + api):
        return "Диагностика дала смешанные результаты. Часть базовых путей работает; изучите HTTP-коды и причины отдельных ошибок без категорического вывода о всём контроллере."
    return "Проверки не подтвердили рабочий сетевой путь. Требуется проверить сетевое окружение и результаты этапов ядра/API."
