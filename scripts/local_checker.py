"""Reusable core for the portable, local-network subscription checker."""

from __future__ import annotations

import dataclasses
import json
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Callable, Sequence

from scripts import build, healthcheck


MAX_SUBSCRIPTION_BYTES = 32 * 1024 * 1024
USER_AGENT = "WireVeil-Portable-Checker/1.0"


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
