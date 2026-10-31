"""Fast device connectivity preflight used by the desktop checker."""

from __future__ import annotations

import concurrent.futures
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable


DEFAULT_ENDPOINTS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.microsoft.com/favicon.ico",
    "https://github.com/favicon.ico",
    "https://ya.ru/favicon.ico",
)
OFFLINE_MESSAGE = (
    "Нет подключения к интернету. Проверьте Wi-Fi или кабель и повторите запуск."
)


@dataclass(frozen=True)
class NetworkStatus:
    """Result of a direct HTTPS connectivity preflight."""

    online: bool
    latency_ms: int | None = None
    endpoint: str | None = None


class NetworkUnavailableError(RuntimeError):
    """A safe, user-presentable connectivity failure."""


def _probe_endpoint(endpoint: str, timeout: float) -> NetworkStatus:
    started = time.monotonic()
    request = urllib.request.Request(
        endpoint,
        headers={
            "User-Agent": "WireVeil-Checker/Network-Preflight",
            "Accept": "*/*",
            "Cache-Control": "no-cache",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1)
    except urllib.error.HTTPError as exc:
        # Any HTTP response proves that DNS, TLS and the route to the internet work.
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return NetworkStatus(online=False, endpoint=endpoint)
    latency_ms = max(1, round((time.monotonic() - started) * 1000))
    return NetworkStatus(online=True, latency_ms=latency_ms, endpoint=endpoint)


def check_device_online(
    timeout: float = 3.0,
    endpoints: Iterable[str] = DEFAULT_ENDPOINTS,
    *,
    probe: Callable[[str, float], NetworkStatus] = _probe_endpoint,
) -> NetworkStatus:
    """Return as soon as one of several independent HTTPS probes succeeds."""

    urls = tuple(dict.fromkeys(item.strip() for item in endpoints if item.strip()))
    if not urls:
        return NetworkStatus(online=False)

    per_probe_timeout = max(0.2, float(timeout))
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=len(urls),
        thread_name_prefix="wireveil-network-probe",
    )
    futures = {
        executor.submit(probe, endpoint, per_probe_timeout) for endpoint in urls
    }
    deadline = time.monotonic() + per_probe_timeout
    try:
        pending = futures
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            done, pending = concurrent.futures.wait(
                pending,
                timeout=remaining,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                break
            for future in done:
                try:
                    status = future.result()
                except Exception:
                    continue
                if status.online:
                    return status
        return NetworkStatus(online=False)
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
