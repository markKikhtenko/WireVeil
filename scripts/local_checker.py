"""Reusable core for the portable, local-network subscription checker."""

from __future__ import annotations

import dataclasses
import concurrent.futures
import json
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Callable, Sequence

from scripts import build, healthcheck


MAX_SUBSCRIPTION_BYTES = 32 * 1024 * 1024
USER_AGENT = "WireVeil-Portable-Checker/1.0"
SPEED_TEST_URL = "https://speed.cloudflare.com/__down"


@dataclasses.dataclass(frozen=True)
class ServiceDefinition:
    name: str
    url: str


SERVICE_DEFINITIONS = (
    ServiceDefinition("ChatGPT", "https://chatgpt.com/"),
    ServiceDefinition("YouTube", "https://www.youtube.com/generate_204"),
    ServiceDefinition("GitHub", "https://github.com/"),
    ServiceDefinition("Google", "https://www.google.com/generate_204"),
    ServiceDefinition("Discord", "https://discord.com/api/v10/gateway"),
    ServiceDefinition("Telegram Web", "https://web.telegram.org/"),
)
SERVICE_DEFINITIONS_BY_NAME = {service.name: service for service in SERVICE_DEFINITIONS}
DEFAULT_SERVICE_NAME = SERVICE_DEFINITIONS[0].name


class LocalCheckError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ImportedSubscription:
    lines: tuple[str, ...]
    rejected: int = 0
    duplicates: int = 0


@dataclasses.dataclass(frozen=True)
class CheckReport:
    candidates: tuple[str, ...]
    results: tuple[healthcheck.ProbeResult, ...]
    conversion_unsupported: dict[str, int]
    runtime_rejected: dict[str, int]
    engine_version: str
    attempts: int

    @property
    def active_results(self) -> tuple[healthcheck.ProbeResult, ...]:
        return tuple(healthcheck._mix_active(self.results))

    def fast_results(self, max_latency_ms: int) -> tuple[healthcheck.ProbeResult, ...]:
        if max_latency_ms < 1:
            raise LocalCheckError("maximum latency must be positive")
        return tuple(
            result
            for result in self.active_results
            if result.delay_ms is not None and result.delay_ms <= max_latency_ms
        )

    @property
    def unsupported_count(self) -> int:
        return sum(self.conversion_unsupported.values()) + sum(self.runtime_rejected.values())


@dataclasses.dataclass(frozen=True)
class SpeedResult:
    target: healthcheck.ProbeTarget
    speed_mbps: float | None = None
    bytes_received: int = 0
    duration_ms: int | None = None
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class ServiceResult:
    target: healthcheck.ProbeTarget
    service_name: str
    available: bool = False
    latency_ms: int | None = None
    http_status: int | None = None
    error: str | None = None


def parse_subscription_text(text: str) -> ImportedSubscription:
    """Parse plain, Base64-wrapped, or config-embedded share links."""
    candidates = build.extract_uris(text.lstrip("\ufeff"))
    if not candidates:
        raise LocalCheckError(
            "Поддерживаемые ссылки не найдены. Нужны VLESS, Trojan, "
            "Shadowsocks, VMess, Hysteria2 или TUIC share-ссылки."
        )

    lines: list[str] = []
    seen: set[str] = set()
    rejected = 0
    duplicates = 0
    for uri in candidates:
        try:
            build.parse_uri(uri)
        except build.ValidationError:
            rejected += 1
            continue
        if uri in seen:
            duplicates += 1
            continue
        seen.add(uri)
        lines.append(uri)
    if not lines:
        raise LocalCheckError("В подписке нет ни одной корректной поддерживаемой ссылки.")
    return ImportedSubscription(tuple(lines), rejected, duplicates)


def _decode_subscription(body: bytes) -> str:
    if len(body) > MAX_SUBSCRIPTION_BYTES:
        raise LocalCheckError("Подписка больше 32 МБ; проверка отменена.")
    try:
        return body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LocalCheckError("Подписка должна быть в кодировке UTF-8.") from exc


def fetch_subscription(url: str, *, timeout: float = 25.0) -> ImportedSubscription:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise LocalCheckError("Укажите корректную ссылку http:// или https://.")
    request = urllib.request.Request(url.strip(), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > MAX_SUBSCRIPTION_BYTES:
                raise LocalCheckError("Подписка больше 32 МБ; загрузка отменена.")
            body = response.read(MAX_SUBSCRIPTION_BYTES + 1)
    except LocalCheckError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise LocalCheckError(f"Не удалось загрузить подписку: {exc}") from exc
    return parse_subscription_text(_decode_subscription(body))


def read_subscription_file(path: Path) -> ImportedSubscription:
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise LocalCheckError(f"Не удалось прочитать файл: {exc}") from exc
    return parse_subscription_text(_decode_subscription(body))


def import_subscription(value: str) -> ImportedSubscription:
    stripped = value.strip()
    if stripped.lower().startswith(("https://", "http://")) and "\n" not in stripped:
        return fetch_subscription(stripped)
    return parse_subscription_text(value)


def run_local_check(
    *,
    binary: Path,
    lines: Sequence[str],
    timeout_ms: int = 8000,
    workers: int = 64,
    attempts: int = 2,
    probe_urls: Sequence[str] = healthcheck.DEFAULT_PROBE_URLS,
    progress_callback: Callable[[int, int, healthcheck.ProbeResult], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> CheckReport:
    if not binary.is_file():
        raise LocalCheckError(f"Не найден sing-box: {binary}")
    if not lines:
        raise LocalCheckError("Подписка пуста.")
    if timeout_ms < 1000 or timeout_ms > 60000:
        raise LocalCheckError("Тайм-аут должен быть от 1 до 60 секунд.")
    if workers < 1 or workers > 256:
        raise LocalCheckError("Число параллельных проверок должно быть от 1 до 256.")
    if attempts < 1 or attempts > 5:
        raise LocalCheckError("Число прогонов должно быть от 1 до 5.")

    targets, conversion_unsupported = healthcheck.collect_targets(lines)
    if not targets:
        raise LocalCheckError("Ни одна ссылка не поддерживается текущим движком проверки.")
    with tempfile.TemporaryDirectory(prefix="wireveil-local-") as name:
        directory = Path(name)
        targets, runtime_rejected = healthcheck.validate_targets(binary, targets, directory)
        if not targets:
            raise LocalCheckError("sing-box отклонил все конфигурации подписки.")
        results, version = healthcheck.run_probes(
            binary,
            targets,
            probe_urls=probe_urls,
            timeout_ms=timeout_ms,
            workers=workers,
            directory=directory,
            attempts=attempts,
            required_successes=attempts,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
    return CheckReport(
        candidates=tuple(lines),
        results=tuple(results),
        conversion_unsupported=dict(Counter(conversion_unsupported)),
        runtime_rejected=dict(Counter(runtime_rejected)),
        engine_version=version,
        attempts=attempts,
    )


def _speed_test_config(
    targets: Sequence[healthcheck.ProbeTarget], ports: Sequence[int]
) -> dict:
    inbounds = []
    rules = []
    for position, (target, port) in enumerate(zip(targets, ports)):
        inbound_tag = f"wv-speed-in-{position}"
        inbounds.append(
            {
                "type": "mixed",
                "tag": inbound_tag,
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )
        rules.append(
            {
                "inbound": [inbound_tag],
                "action": "route",
                "outbound": target.tag,
            }
        )
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": inbounds,
        "outbounds": [target.outbound for target in targets],
        "route": {"rules": rules, "default_domain_resolver": "local"},
    }


def _allocate_ports(count: int) -> list[int]:
    reservations: list[socket.socket] = []
    try:
        for _index in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            reservations.append(listener)
        return [int(listener.getsockname()[1]) for listener in reservations]
    finally:
        for listener in reservations:
            listener.close()


def _wait_for_proxy_runtime(
    process: subprocess.Popen, port: int, timeout: float = 20.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise LocalCheckError("sing-box остановился до запуска дополнительного теста.")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.15)
    raise LocalCheckError("Локальный proxy для дополнительного теста не запустился.")


def _test_download_speed(
    target: healthcheck.ProbeTarget,
    port: int,
    *,
    download_bytes: int,
    timeout: float,
    cancel_event: threading.Event | None,
) -> SpeedResult:
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    query = urllib.parse.urlencode(
        {"bytes": download_bytes, "cache": f"{time.time_ns()}-{target.index}"}
    )
    request = urllib.request.Request(
        f"{SPEED_TEST_URL}?{query}",
        headers={
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache",
        },
    )
    received = 0
    try:
        with opener.open(request, timeout=timeout) as response:
            started = time.perf_counter()
            while received < download_bytes:
                if cancel_event is not None and cancel_event.is_set():
                    return SpeedResult(target, error="cancelled")
                block = response.read(min(131072, download_bytes - received))
                if not block:
                    break
                received += len(block)
            elapsed = time.perf_counter() - started
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return SpeedResult(target, error=f"{type(exc).__name__}: {str(exc)[:240]}")
    if received < download_bytes:
        return SpeedResult(target, bytes_received=received, error="неполный ответ")
    if elapsed <= 0:
        return SpeedResult(target, bytes_received=received, error="некорректное время")
    speed_mbps = round((received * 8) / elapsed / 1_000_000, 2)
    return SpeedResult(
        target,
        speed_mbps=speed_mbps,
        bytes_received=received,
        duration_ms=max(1, round(elapsed * 1000)),
    )


def run_speed_tests(
    *,
    binary: Path,
    targets: Sequence[healthcheck.ProbeTarget],
    download_bytes: int = 1_000_000,
    workers: int = 8,
    timeout: float = 15.0,
    progress_callback: Callable[[int, int, SpeedResult], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[SpeedResult, ...]:
    """Measure download throughput only for targets pre-qualified as green."""
    if not binary.is_file():
        raise LocalCheckError(f"Не найден sing-box: {binary}")
    if not targets:
        return ()
    if not 100_000 <= download_bytes <= 10_000_000:
        raise LocalCheckError("Объём теста скорости должен быть от 100 КБ до 10 МБ.")
    if not 1 <= workers <= 32:
        raise LocalCheckError("Параллельность теста скорости должна быть от 1 до 32.")
    if not 3 <= timeout <= 60:
        raise LocalCheckError("Тайм-аут теста скорости должен быть от 3 до 60 секунд.")

    ports = _allocate_ports(len(targets))
    with tempfile.TemporaryDirectory(prefix="wireveil-speed-") as name:
        directory = Path(name)
        config_path = directory / "speed.json"
        log_path = directory / "sing-box.log"
        config_path.write_text(
            json.dumps(_speed_test_config(targets, ports), ensure_ascii=False),
            encoding="utf-8",
        )
        passed, detail = healthcheck._run_config_check(binary, config_path)
        if not passed:
            raise LocalCheckError(f"Конфигурация теста скорости отклонена: {detail[-800:]}")
        with log_path.open("w", encoding="utf-8") as log_handle:
            try:
                process = subprocess.Popen(
                    [str(binary), "run", "-c", str(config_path)],
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    **healthcheck._hidden_process_options(),
                )
            except OSError as exc:
                raise LocalCheckError(f"Не удалось запустить sing-box: {exc}") from exc
            try:
                _wait_for_proxy_runtime(process, ports[0])
                executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(workers, len(targets))
                )
                futures = [
                    executor.submit(
                        _test_download_speed,
                        target,
                        port,
                        download_bytes=download_bytes,
                        timeout=timeout,
                        cancel_event=cancel_event,
                    )
                    for target, port in zip(targets, ports)
                ]
                cancelled = False
                results: list[SpeedResult] = []
                try:
                    for completed, future in enumerate(
                        concurrent.futures.as_completed(futures), start=1
                    ):
                        if cancel_event is not None and cancel_event.is_set():
                            cancelled = True
                            raise healthcheck.HealthCheckError("speed test cancelled")
                        result = future.result()
                        results.append(result)
                        if progress_callback is not None:
                            progress_callback(completed, len(targets), result)
                finally:
                    executor.shutdown(wait=not cancelled, cancel_futures=cancelled)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    return tuple(sorted(results, key=lambda result: result.target.index))


def _test_service_access(
    target: healthcheck.ProbeTarget,
    port: int,
    *,
    service: ServiceDefinition,
    timeout: float,
    cancel_event: threading.Event | None,
) -> ServiceResult:
    if cancel_event is not None and cancel_event.is_set():
        return ServiceResult(target, service.name, error="cancelled")
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    request = urllib.request.Request(
        service.url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/140.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache",
        },
    )
    started = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(1)
            elapsed = time.perf_counter() - started
            status_value = getattr(response, "status", None)
            if status_value is None:
                status_value = response.getcode()
            status = int(status_value)
    except urllib.error.HTTPError as exc:
        elapsed = time.perf_counter() - started
        exc.close()
        return ServiceResult(
            target,
            service.name,
            latency_ms=max(1, round(elapsed * 1000)),
            http_status=int(exc.code),
            error=f"HTTP {exc.code}",
        )
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return ServiceResult(
            target,
            service.name,
            error=f"{type(exc).__name__}: {str(exc)[:240]}",
        )
    available = 200 <= status < 400
    return ServiceResult(
        target,
        service.name,
        available=available,
        latency_ms=max(1, round(elapsed * 1000)),
        http_status=status,
        error=None if available else f"HTTP {status}",
    )


def run_service_tests(
    *,
    binary: Path,
    targets: Sequence[healthcheck.ProbeTarget],
    service_name: str,
    workers: int = 16,
    timeout: float = 15.0,
    progress_callback: Callable[[int, int, ServiceResult], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[ServiceResult, ...]:
    """Check one selected website through every pre-qualified green target."""
    if not binary.is_file():
        raise LocalCheckError(f"Не найден sing-box: {binary}")
    service = SERVICE_DEFINITIONS_BY_NAME.get(service_name)
    if service is None:
        raise LocalCheckError(f"Неизвестный сервис: {service_name}")
    if not targets:
        return ()
    if not 1 <= workers <= 32:
        raise LocalCheckError("Параллельность проверки сервисов должна быть от 1 до 32.")
    if not 3 <= timeout <= 60:
        raise LocalCheckError("Тайм-аут проверки сервисов должен быть от 3 до 60 секунд.")

    ports = _allocate_ports(len(targets))
    with tempfile.TemporaryDirectory(prefix="wireveil-service-") as name:
        directory = Path(name)
        config_path = directory / "service.json"
        log_path = directory / "sing-box.log"
        config_path.write_text(
            json.dumps(_speed_test_config(targets, ports), ensure_ascii=False),
            encoding="utf-8",
        )
        passed, detail = healthcheck._run_config_check(binary, config_path)
        if not passed:
            raise LocalCheckError(f"Конфигурация проверки сервиса отклонена: {detail[-800:]}")
        with log_path.open("w", encoding="utf-8") as log_handle:
            try:
                process = subprocess.Popen(
                    [str(binary), "run", "-c", str(config_path)],
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    **healthcheck._hidden_process_options(),
                )
            except OSError as exc:
                raise LocalCheckError(f"Не удалось запустить sing-box: {exc}") from exc
            try:
                _wait_for_proxy_runtime(process, ports[0])
                executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(workers, len(targets))
                )
                futures = [
                    executor.submit(
                        _test_service_access,
                        target,
                        port,
                        service=service,
                        timeout=timeout,
                        cancel_event=cancel_event,
                    )
                    for target, port in zip(targets, ports)
                ]
                cancelled = False
                results: list[ServiceResult] = []
                try:
                    for completed, future in enumerate(
                        concurrent.futures.as_completed(futures), start=1
                    ):
                        if cancel_event is not None and cancel_event.is_set():
                            cancelled = True
                            raise healthcheck.HealthCheckError("service test cancelled")
                        result = future.result()
                        results.append(result)
                        if progress_callback is not None:
                            progress_callback(completed, len(targets), result)
                finally:
                    executor.shutdown(wait=not cancelled, cancel_futures=cancelled)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    return tuple(sorted(results, key=lambda result: result.target.index))


def write_subscription(path: Path, results: Sequence[healthcheck.ProbeResult]) -> None:
    content = "".join(f"{result.target.uri}\n" for result in results)
    try:
        path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise LocalCheckError(f"Не удалось сохранить файл: {exc}") from exc


def write_report(path: Path, report: CheckReport, max_latency_ms: int) -> None:
    """Write a local diagnostic report. It contains private proxy credentials."""
    active = {result.target.index for result in report.active_results}
    fast = {result.target.index for result in report.fast_results(max_latency_ms)}
    payload = {
        "engine": report.engine_version,
        "attempts_required": report.attempts,
        "candidate_keys": len(report.candidates),
        "tested_keys": len(report.results),
        "active_keys": len(active),
        "fast_keys": len(fast),
        "max_latency_ms": max_latency_ms,
        "unsupported_keys": report.unsupported_count,
        "results": [
            {
                "index": result.target.index,
                "protocol": result.target.protocol,
                "uri": result.target.uri,
                "active": result.target.index in active,
                "fast": result.target.index in fast,
                "latency_ms": result.delay_ms,
                "successes": result.successes,
                "attempts": result.attempts,
                "error": result.error,
            }
            for result in report.results
        ],
    }
    try:
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise LocalCheckError(f"Не удалось сохранить отчёт: {exc}") from exc
