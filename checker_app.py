#!/usr/bin/env python3
"""WireVeil portable Windows subscription checker."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
import queue
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from mihomo_tab import MihomoCheckerTab
from scripts import app_updater, build, healthcheck, local_checker, network_check
from wireveil_paths import application_root, user_data_file
from wireveil_version import APP_VERSION


APP_TITLE = f"WireVeil Checker {APP_VERSION}"
CONFIG_FILENAME = "WireVeilChecker.config.json"
CONFIG_VERSION = 2
RESULTS_FILENAME = "WireVeilChecker.last-results.json"
RESULTS_VERSION = 1
SERVICE_COLUMN_BY_NAME = {
    service.name: f"service_{service.key}"
    for service in local_checker.SERVICE_DEFINITIONS
}
SERVICE_NAME_BY_COLUMN = {
    column: name for name, column in SERVICE_COLUMN_BY_NAME.items()
}
TABLE_COLUMNS = (
    "number",
    "protocol",
    "endpoint",
    "name",
    "latency",
    "speed",
    "quality",
    *SERVICE_NAME_BY_COLUMN,
    "passes",
)
TABLE_COLUMN_POSITIONS = {
    column: position for position, column in enumerate(TABLE_COLUMNS)
}


def resource_root() -> Path:
    bundled = getattr(sys, "_MEIPASS", None)
    return Path(bundled) if bundled else Path(__file__).resolve().parent


def checker_settings_path() -> Path:
    return user_data_file(CONFIG_FILENAME)


def checker_results_path() -> Path:
    return user_data_file(RESULTS_FILENAME)


@dataclasses.dataclass(frozen=True)
class SavedCheckerResults:
    report: local_checker.CheckReport
    speed_results: dict[int, local_checker.SpeedResult]
    service_results: dict[tuple[int, str], local_checker.ServiceResult]
    saved_at: int
    sort_column: str | None = "quality"
    sort_descending: bool = False
    mode: str = "full"


def _source_digest(source: str) -> str:
    return hashlib.sha256(source.strip().encode("utf-8")).hexdigest()


def _result_target_payload(target: healthcheck.ProbeTarget) -> dict[str, object]:
    return {
        "index": target.index,
        "tag": target.tag,
        "uri": target.uri,
    }


def write_checker_results(
    path: Path,
    source: str,
    report: local_checker.CheckReport,
    speed_results: dict[int, local_checker.SpeedResult],
    service_results: dict[tuple[int, str], local_checker.ServiceResult],
    *,
    sort_column: str | None = "quality",
    sort_descending: bool = False,
    mode: str = "full",
) -> None:
    payload: dict[str, object] = {
        "version": RESULTS_VERSION,
        "saved_at": int(time.time()),
        "source_digest": _source_digest(source),
        "mode": mode,
        "sort_column": sort_column,
        "sort_descending": sort_descending,
        "report": {
            "candidates": list(report.candidates),
            "conversion_unsupported": report.conversion_unsupported,
            "runtime_rejected": report.runtime_rejected,
            "engine_version": report.engine_version,
            "attempts": report.attempts,
            "results": [
                {
                    "target": _result_target_payload(result.target),
                    "active": result.active,
                    "delay_ms": result.delay_ms,
                    "error": result.error,
                    "attempts": result.attempts,
                    "successes": result.successes,
                }
                for result in report.results
            ],
        },
        "speed_results": [
            {
                "target_index": result.target.index,
                "speed_mbps": result.speed_mbps,
                "bytes_received": result.bytes_received,
                "duration_ms": result.duration_ms,
                "error": result.error,
            }
            for _index, result in sorted(speed_results.items())
        ],
        "service_results": [
            {
                "target_index": result.target.index,
                "service_name": result.service_name,
                "available": result.available,
                "latency_ms": result.latency_ms,
                "http_status": result.http_status,
                "error": result.error,
            }
            for _key, result in sorted(service_results.items())
        ],
    }
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _saved_int(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError("invalid saved integer")
    return value


def _saved_optional_int(value: object, *, minimum: int = 0) -> int | None:
    return None if value is None else _saved_int(value, minimum=minimum)


def _saved_optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("invalid saved text")
    return value


def _saved_counts(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError("invalid saved counters")
    counts: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str):
            raise ValueError("invalid saved counter name")
        counts[key] = _saved_int(count)
    return counts


def load_checker_results(path: Path, source: str) -> SavedCheckerResults | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != RESULTS_VERSION:
            return None
        digest = raw.get("source_digest")
        if not source.strip() or digest != _source_digest(source):
            return None
        report_raw = raw.get("report")
        if not isinstance(report_raw, dict):
            return None
        candidates_raw = report_raw.get("candidates")
        results_raw = report_raw.get("results")
        if not isinstance(candidates_raw, list) or not all(
            isinstance(uri, str) for uri in candidates_raw
        ):
            return None
        if not isinstance(results_raw, list):
            return None

        probe_results: list[healthcheck.ProbeResult] = []
        targets: dict[int, healthcheck.ProbeTarget] = {}
        for result_raw in results_raw:
            if not isinstance(result_raw, dict):
                return None
            target_raw = result_raw.get("target")
            if not isinstance(target_raw, dict):
                return None
            index = _saved_int(target_raw.get("index"))
            tag = target_raw.get("tag")
            uri = target_raw.get("uri")
            if not isinstance(tag, str) or not isinstance(uri, str) or index in targets:
                return None
            protocol, outbound = healthcheck.uri_to_outbound(uri, tag)
            target = healthcheck.ProbeTarget(index, tag, uri, protocol, outbound)
            active = result_raw.get("active")
            if not isinstance(active, bool):
                return None
            attempts = _saved_int(result_raw.get("attempts"), minimum=1)
            successes = _saved_int(result_raw.get("successes"))
            if successes > attempts:
                return None
            delay_ms = _saved_optional_int(result_raw.get("delay_ms"), minimum=1)
            result = healthcheck.ProbeResult(
                target=target,
                active=active,
                delay_ms=delay_ms,
                error=_saved_optional_text(result_raw.get("error")),
                attempts=attempts,
                successes=successes,
            )
            targets[index] = target
            probe_results.append(result)

        report = local_checker.CheckReport(
            candidates=tuple(candidates_raw),
            results=tuple(probe_results),
            conversion_unsupported=_saved_counts(
                report_raw.get("conversion_unsupported")
            ),
            runtime_rejected=_saved_counts(report_raw.get("runtime_rejected")),
            engine_version=str(report_raw.get("engine_version", "")),
            attempts=_saved_int(report_raw.get("attempts"), minimum=1),
        )

        speed_results: dict[int, local_checker.SpeedResult] = {}
        speed_raw = raw.get("speed_results", [])
        if not isinstance(speed_raw, list):
            return None
        for item in speed_raw:
            if not isinstance(item, dict):
                return None
            index = _saved_int(item.get("target_index"))
            target = targets.get(index)
            speed = item.get("speed_mbps")
            if target is None or isinstance(speed, bool) or not (
                speed is None or isinstance(speed, (int, float)) and speed >= 0
            ):
                return None
            speed_results[index] = local_checker.SpeedResult(
                target=target,
                speed_mbps=None if speed is None else float(speed),
                bytes_received=_saved_int(item.get("bytes_received")),
                duration_ms=_saved_optional_int(item.get("duration_ms")),
                error=_saved_optional_text(item.get("error")),
            )

        known_services = {
            service.name for service in local_checker.SERVICE_DEFINITIONS
        }
        service_results: dict[tuple[int, str], local_checker.ServiceResult] = {}
        services_raw = raw.get("service_results", [])
        if not isinstance(services_raw, list):
            return None
        for item in services_raw:
            if not isinstance(item, dict):
                return None
            index = _saved_int(item.get("target_index"))
            target = targets.get(index)
            service_name = item.get("service_name")
            available = item.get("available")
            if (
                target is None
                or not isinstance(service_name, str)
                or service_name not in known_services
                or not isinstance(available, bool)
            ):
                return None
            service_results[(index, service_name)] = local_checker.ServiceResult(
                target=target,
                service_name=service_name,
                available=available,
                latency_ms=_saved_optional_int(item.get("latency_ms")),
                http_status=_saved_optional_int(item.get("http_status"), minimum=100),
                error=_saved_optional_text(item.get("error")),
            )

        sort_column = raw.get("sort_column")
        if sort_column is not None and sort_column not in TABLE_COLUMNS:
            sort_column = "quality"
        sort_descending = raw.get("sort_descending")
        if not isinstance(sort_descending, bool):
            sort_descending = False
        mode = raw.get("mode")
        if mode not in {"full", "watch"}:
            mode = "full"
        return SavedCheckerResults(
            report=report,
            speed_results=speed_results,
            service_results=service_results,
            saved_at=_saved_int(raw.get("saved_at")),
            sort_column=sort_column,
            sort_descending=sort_descending,
            mode=mode,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        build.ValidationError,
        healthcheck.HealthCheckError,
        KeyError,
    ):
        return None


def find_app_icon() -> Path | None:
    candidates = (
        resource_root() / "wireveil-icon.ico",
        resource_root() / "assets" / "wireveil-icon.ico",
        application_root() / "assets" / "wireveil-icon.ico",
    )
    return next((path for path in candidates if path.is_file()), None)


def _bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if minimum <= parsed <= maximum else default


def load_checker_settings(path: Path) -> dict[str, object]:
    defaults: dict[str, object] = {
        "rounds": 2,
        "timeout": 8,
        "workers": 64,
        "latency": 500,
        "auto_enabled": False,
        "auto_interval": 30,
        "watch_enabled": False,
        "watch_interval": 30,
        "watched_uris": (),
        "services": (local_checker.DEFAULT_SERVICE_NAME,),
        "advanced_visible": False,
        "subscription": "",
    }
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return defaults
    if not isinstance(raw, dict):
        return defaults

    known_services = {
        service.name for service in local_checker.SERVICE_DEFINITIONS
    }
    requested_services = raw.get("services")
    if isinstance(requested_services, list) and all(
        isinstance(name, str) for name in requested_services
    ):
        selected_services = tuple(
            service.name
            for service in local_checker.SERVICE_DEFINITIONS
            if service.name in requested_services and service.name in known_services
        )
    else:
        selected_services = defaults["services"]

    requested_watched = raw.get("watched_uris")
    if isinstance(requested_watched, list) and all(
        isinstance(uri, str) for uri in requested_watched
    ):
        watched_uris = tuple(
            dict.fromkeys(uri.strip() for uri in requested_watched if uri.strip())
        )
    else:
        watched_uris = defaults["watched_uris"]

    return {
        "rounds": _bounded_int(raw.get("rounds"), 2, 1, 5),
        "timeout": _bounded_int(raw.get("timeout"), 8, 1, 60),
        "workers": _bounded_int(raw.get("workers"), 64, 1, 256),
        "latency": _bounded_int(raw.get("latency"), 500, 1, 10_000),
        "auto_enabled": raw.get("auto_enabled")
        if isinstance(raw.get("auto_enabled"), bool)
        else False,
        "auto_interval": _bounded_int(raw.get("auto_interval"), 30, 1, 1440),
        "watch_enabled": raw.get("watch_enabled")
        if isinstance(raw.get("watch_enabled"), bool)
        else False,
        "watch_interval": _bounded_int(raw.get("watch_interval"), 30, 1, 1440),
        "watched_uris": watched_uris,
        "services": selected_services,
        "advanced_visible": raw.get("advanced_visible")
        if isinstance(raw.get("advanced_visible"), bool)
        else False,
        "subscription": raw.get("subscription")
        if isinstance(raw.get("subscription"), str)
        else "",
    }


def write_checker_settings(path: Path, settings: dict[str, object]) -> None:
    payload = {"version": CONFIG_VERSION, **settings}
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def find_sing_box() -> Path | None:
    names = ("sing-box.exe", "sing-box")
    roots = [resource_root(), Path(sys.executable).resolve().parent, Path(__file__).resolve().parent]
    for root in roots:
        for name in names:
            candidate = root / name
            if candidate.is_file():
                return candidate
    development = Path(__file__).resolve().parent / ".wireveil-singbox-1.14.0"
    if development.is_dir():
        matches = sorted(development.glob("*/sing-box.exe"))
        if matches:
            return matches[0]
    return None


def display_name(uri: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(uri)
        fragment = urllib.parse.unquote(parsed.fragment).strip()
        if fragment:
            return fragment
        if parsed.scheme.lower() == "vmess":
            payload = uri.split("://", 1)[1].split("#", 1)[0]
            padding = "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload + padding).decode("utf-8"))
            name = str(data.get("ps", "")).strip()
            if name:
                return name
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        fragment = ""
    return "—"


class WireVeilChecker(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        icon_path = find_app_icon()
        if icon_path is not None:
            try:
                self.iconbitmap(str(icon_path))
                self.iconbitmap(default=str(icon_path))
            except tk.TclError:
                pass
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = max(960, min(1240, screen_width - 80))
        window_height = max(680, min(800, screen_height - 80))
        window_x = max(0, (screen_width - window_width) // 2)
        window_y = max(0, (screen_height - window_height) // 3)
        self.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")
        self.minsize(min(960, window_width), min(680, window_height))
        self.option_add("*Font", ("Segoe UI", 10))

        self.settings_path = checker_settings_path()
        self.results_path = checker_results_path()
        saved_settings = load_checker_settings(self.settings_path)
        restore_advanced = bool(saved_settings["advanced_visible"])
        restore_subscription = str(saved_settings["subscription"])
        self.settings_save_job: str | None = None
        self.settings_save_error_reported = False
        self.results_save_error_reported = False

        self.events: queue.Queue[tuple] = queue.Queue()
        self.cancel_event = threading.Event()
        self.running = False
        self.update_busy = False
        self.update_downloading = False
        self.activity: str | None = None
        self.one_click_mode = False
        self.advanced_visible = False
        self.magic_tooltip: tk.Toplevel | None = None
        self.easter_window: tk.Toplevel | None = None
        self.easter_job: str | None = None
        self.closing = False
        self.report: local_checker.CheckReport | None = None
        self.imported: local_checker.ImportedSubscription | None = None
        self.table_items: dict[int, str] = {}
        self.item_uris: dict[str, str] = {}
        self.live_results: dict[int, dict[str, object]] = {}
        self.speed_results: dict[int, local_checker.SpeedResult] = {}
        self.service_results: dict[tuple[int, str], local_checker.ServiceResult] = {}
        self.column_headings: dict[str, str] = {}
        self.sort_column: str | None = "quality"
        self.sort_descending = False
        self.sort_job: str | None = None
        self.auto_job: str | None = None
        self.watch_job: str | None = None
        self.countdown_job: str | None = None
        self.timer_refresh_job: str | None = None
        self.network_job: str | None = None
        self.table_resize_job: str | None = None
        self.poll_job: str | None = None
        self.network_check_in_progress = False
        self.auto_due_at: float | None = None
        self.watch_due_at: float | None = None
        self.watched_uris = tuple(str(uri) for uri in saved_settings["watched_uris"])

        self.rounds_var = tk.IntVar(value=int(saved_settings["rounds"]))
        self.timeout_var = tk.IntVar(value=int(saved_settings["timeout"]))
        self.workers_var = tk.IntVar(value=int(saved_settings["workers"]))
        self.latency_var = tk.IntVar(value=int(saved_settings["latency"]))
        self.auto_enabled_var = tk.BooleanVar(
            value=bool(saved_settings["auto_enabled"])
        )
        self.auto_interval_var = tk.IntVar(
            value=int(saved_settings["auto_interval"])
        )
        self.watch_enabled_var = tk.BooleanVar(
            value=bool(saved_settings["watch_enabled"])
        )
        self.watch_interval_var = tk.IntVar(
            value=int(saved_settings["watch_interval"])
        )
        selected_services = set(saved_settings["services"])
        self.service_vars = {
            service.name: tk.BooleanVar(
                value=service.name in selected_services
            )
            for service in local_checker.SERVICE_DEFINITIONS
        }
        self.service_menu_text_var = tk.StringVar(value=local_checker.DEFAULT_SERVICE_NAME)
        self.status_var = tk.StringVar(value="Вставьте ссылку подписки или её содержимое.")
        self.summary_var = tk.StringVar(value="Результатов пока нет")
        self.auto_countdown_var = tk.StringVar(value="○ ждёт первого полного запуска")
        self.watch_countdown_var = tk.StringVar(value="○ ждёт копирования годных серверов")
        self.progress_var = tk.DoubleVar(value=0)
        self.network_status_var = tk.StringVar(value="Проверка сети…")

        self._configure_style()
        self._build_ui()
        if restore_subscription:
            self.source.insert("1.0", restore_subscription)
            self.status_var.set("Сохранённая подписка загружена из конфига.")
        if restore_advanced:
            self._toggle_advanced_settings(persist=False)
        self._watch_settings()
        self._log(f"Настройки: {self.settings_path}")
        self._restore_last_results(restore_subscription)
        if self.auto_enabled_var.get():
            self._log("Полный автоцикл сохранён и продолжит работу после первого запуска.")
        if self.watch_enabled_var.get():
            if self.watched_uris:
                self._log(
                    f"Контроль доступности восстановлен: {len(self.watched_uris)} "
                    "скопированных серверов."
                )
                self.after_idle(self._schedule_watch_check)
            else:
                self._log("Контроль доступности ждёт первого копирования годных серверов.")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.poll_job = self.after(100, self._poll_events)
        self.after_idle(self._update_countdowns)
        self.after_idle(self._refresh_network_status)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        self.configure(background="#0d1117")
        style.configure(".", background="#161b22", foreground="#f0f6fc")
        style.configure("TFrame", background="#0d1117")
        style.configure("AppShell.TFrame", background="#0d1117")
        style.configure("Topbar.TFrame", background="#010409")
        style.configure("NavBar.TFrame", background="#0d1117")
        style.configure("PageHeader.TFrame", background="#0d1117")
        style.configure("Panel.TFrame", background="#161b22", borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid")
        style.configure("Card.TFrame", background="#161b22", borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid")
        style.configure("PanelBody.TFrame", background="#161b22", borderwidth=0, relief="flat")
        style.configure("CardBody.TFrame", background="#161b22", borderwidth=0, relief="flat")
        style.configure("HeroBody.TFrame", background="#161b22", borderwidth=0, relief="flat")
        style.configure("TLabel", background="#0d1117", foreground="#f0f6fc")
        style.configure("Topbar.TLabel", background="#010409", foreground="#f0f6fc")
        style.configure("Panel.TLabel", background="#161b22", foreground="#f0f6fc")
        style.configure("PanelTitle.TLabel", background="#161b22", foreground="#f0f6fc", font=("Segoe UI Semibold", 10))
        style.configure("PanelDim.TLabel", background="#161b22", foreground="#8b949e")
        style.configure("Card.TLabel", background="#161b22", foreground="#f0f6fc")
        style.configure("Dim.TLabel", background="#0d1117", foreground="#8b949e")
        style.configure("CardDim.TLabel", background="#161b22", foreground="#8b949e")
        style.configure("BrandMark.TLabel", background="#1f6feb", foreground="#ffffff", font=("Segoe UI Semibold", 10), padding=(7, 4))
        style.configure("Brand.TLabel", background="#010409", foreground="#f0f6fc", font=("Segoe UI Semibold", 12))
        style.configure("TopbarSubtitle.TLabel", background="#010409", foreground="#8b949e", font=("Segoe UI", 9))
        style.configure("PageTitle.TLabel", background="#0d1117", foreground="#f0f6fc", font=("Segoe UI Semibold", 15))
        style.configure("PageSubtitle.TLabel", background="#0d1117", foreground="#8b949e", font=("Segoe UI", 10))
        style.configure("Version.TLabel", background="#21262d", foreground="#c9d1d9", font=("Segoe UI Semibold", 9), padding=(8, 4))
        style.configure("NetworkPending.TLabel", background="#010409", foreground="#8b949e", font=("Segoe UI Semibold", 9))
        style.configure("NetworkOnline.TLabel", background="#010409", foreground="#3fb950", font=("Segoe UI Semibold", 9))
        style.configure("NetworkOffline.TLabel", background="#010409", foreground="#f85149", font=("Segoe UI Semibold", 9))
        style.configure("Section.TLabel", background="#161b22", foreground="#8b949e", font=("Segoe UI Semibold", 9))
        style.configure("CardTitle.TLabel", background="#161b22", foreground="#f0f6fc", font=("Segoe UI Semibold", 11))
        style.configure("CardBody.TLabel", background="#161b22", foreground="#8b949e", font=("Segoe UI", 10))
        style.configure("SectionTitle.TLabel", background="#0d1117", foreground="#f0f6fc", font=("Segoe UI Semibold", 12))
        style.configure("Countdown.TLabel", background="#161b22", foreground="#58a6ff", font=("Segoe UI Semibold", 10))
        style.configure("Summary.TLabel", background="#0d1117", foreground="#8b949e")
        style.configure("TButton", background="#21262d", foreground="#f0f6fc", padding=(10, 6), borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid", focusthickness=1, focuscolor="#58a6ff")
        style.map("TButton", background=[("active", "#30363d"), ("pressed", "#1f6feb"), ("disabled", "#161b22")], foreground=[("disabled", "#6e7681")], bordercolor=[("active", "#8b949e"), ("disabled", "#21262d")])
        style.configure("Secondary.TButton", background="#21262d", foreground="#f0f6fc", padding=(9, 5), borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid")
        style.map("Secondary.TButton", background=[("active", "#30363d"), ("pressed", "#1f6feb"), ("disabled", "#161b22")], foreground=[("disabled", "#6e7681")], bordercolor=[("active", "#8b949e"), ("disabled", "#21262d")])
        style.configure("Utility.TButton", background="#161b22", foreground="#c9d1d9", padding=(9, 5), borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid", font=("Segoe UI Semibold", 9))
        style.map("Utility.TButton", background=[("active", "#21262d"), ("pressed", "#1f6feb"), ("disabled", "#161b22")], foreground=[("disabled", "#6e7681")], bordercolor=[("active", "#8b949e"), ("disabled", "#21262d")])
        style.configure("Accent.TButton", background="#238636", foreground="#ffffff", font=("Segoe UI Semibold", 9), padding=(10, 6), borderwidth=1, bordercolor="#2ea043", lightcolor="#2ea043", darkcolor="#2ea043", relief="solid")
        style.map("Accent.TButton", background=[("active", "#2ea043"), ("pressed", "#196c2e"), ("disabled", "#1b4725")], foreground=[("disabled", "#7d8590")])
        style.configure(
            "Launch.TButton",
            background="#da3633",
            foreground="#ffffff",
            font=("Segoe UI Semibold", 12),
            padding=(14, 9),
            borderwidth=0,
            bordercolor="#f85149",
            lightcolor="#f85149",
            darkcolor="#b62324",
            focuscolor="#f85149",
        )
        style.map(
            "Launch.TButton",
            background=[("active", "#f85149"), ("pressed", "#b62324"), ("disabled", "#5a2725")],
            foreground=[("disabled", "#8b949e"), ("!disabled", "#ffffff")],
        )
        style.configure("Hero.TFrame", background="#161b22", borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid")
        style.configure("Hero.TLabel", background="#161b22", foreground="#8b949e", font=("Segoe UI Semibold", 9))
        style.configure(
            "Stepper.TEntry",
            fieldbackground="#0d1117",
            foreground="#f0f6fc",
            insertcolor="#f0f6fc",
            borderwidth=1,
            bordercolor="#30363d",
            lightcolor="#30363d",
            darkcolor="#30363d",
            padding=(5, 3),
        )
        style.configure(
            "Stepper.TButton",
            background="#21262d",
            foreground="#ffffff",
            font=("Segoe UI Semibold", 10),
            padding=(4, 1),
        )
        style.map("Stepper.TButton", background=[("active", "#30363d"), ("pressed", "#1f6feb")])
        style.configure("TCheckbutton", background="#0d1117", foreground="#f0f6fc")
        style.map("TCheckbutton", background=[("active", "#0d1117")])
        style.configure("Panel.TCheckbutton", background="#161b22", foreground="#f0f6fc")
        style.map("Panel.TCheckbutton", background=[("active", "#161b22")])
        style.configure("Card.TCheckbutton", background="#161b22", foreground="#f0f6fc", font=("Segoe UI Semibold", 10))
        style.map("Card.TCheckbutton", background=[("active", "#161b22")], foreground=[("disabled", "#6e7681")])
        style.configure(
            "Service.TMenubutton",
            background="#21262d",
            foreground="#f0f6fc",
            arrowcolor="#c9d1d9",
            borderwidth=1,
            padding=(5, 3),
        )
        style.map(
            "Service.TMenubutton",
            background=[("active", "#30363d"), ("pressed", "#1f6feb")],
            foreground=[("disabled", "#888888"), ("!disabled", "#ffffff")],
            arrowcolor=[("disabled", "#777777"), ("!disabled", "#ffffff")],
        )
        style.configure("Horizontal.TProgressbar", background="#2f81f7", troughcolor="#21262d", borderwidth=0, thickness=3)
        style.configure("TNotebook", background="#0d1117", borderwidth=0, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", tabmargins=(12, 8, 0, 0))
        style.configure("TNotebook.Tab", background="#0d1117", foreground="#8b949e", padding=(16, 8), borderwidth=0, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", font=("Segoe UI Semibold", 9))
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#21262d"), ("active", "#161b22")],
            foreground=[("selected", "#f0f6fc"), ("active", "#c9d1d9")],
        )
        style.configure(
            "Treeview",
            background="#0d1117",
            fieldbackground="#0d1117",
            foreground="#c9d1d9",
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.map("Treeview", background=[("selected", "#1f6feb")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background="#161b22", foreground="#c9d1d9", relief="flat", padding=(6, 7), font=("Segoe UI Semibold", 9))
        style.map("Treeview.Heading", background=[("active", "#21262d")])
        style.configure("TScrollbar", background="#21262d", troughcolor="#0d1117", bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", arrowcolor="#8b949e", relief="flat")
        style.map("TScrollbar", background=[("active", "#30363d"), ("pressed", "#484f58")])

    def _build_ui(self) -> None:
        shell = ttk.Frame(self, style="AppShell.TFrame")
        shell.pack(fill="both", expand=True)

        topbar = ttk.Frame(shell, style="Topbar.TFrame", padding=(18, 8))
        topbar.pack(fill="x")
        self.brand_mark = tk.Canvas(
            topbar,
            width=30,
            height=30,
            background="#010409",
            highlightthickness=0,
            borderwidth=0,
            cursor="hand2",
        )
        self.brand_mark.create_polygon(
            15, 2, 27, 7, 25, 20, 15, 28, 5, 20, 3, 7,
            fill="#0d1117",
            outline="#30363d",
            width=1,
        )
        self.brand_mark.create_line(
            7, 9, 10, 21, 15, 15, 20, 21, 23, 9,
            fill="#58a6ff",
            width=3,
            capstyle=tk.ROUND,
            joinstyle=tk.ROUND,
        )
        self.brand_mark.create_oval(21, 5, 25, 9, fill="#3fb950", outline="")
        self.brand_mark.bind("<Triple-Button-1>", self._show_rkn_easter_egg)
        self.brand_mark.pack(side="left")
        brand = ttk.Frame(topbar, style="Topbar.TFrame")
        brand.pack(side="left", padx=(10, 0))
        ttk.Label(brand, text="WireVeil", style="Brand.TLabel").pack(side="left")
        ttk.Label(brand, text="/ Checker", style="TopbarSubtitle.TLabel").pack(
            side="left", padx=(5, 0)
        )
        self.update_button = ttk.Button(
            topbar,
            text="Обновления",
            command=self._check_for_updates,
            style="Utility.TButton",
        )
        self.update_button.pack(side="right", padx=(8, 0))
        self.update_buttons = [self.update_button]
        ttk.Label(topbar, text=f"v{APP_VERSION}", style="Version.TLabel").pack(side="right", padx=(8, 0))
        self.network_status_label = ttk.Label(
            topbar,
            textvariable=self.network_status_var,
            style="NetworkPending.TLabel",
        )
        self.network_status_label.pack(side="right", padx=(12, 4))
        self.bind_all("<Control-u>", lambda _event: self._check_for_updates())

        nav_bar = ttk.Frame(shell, style="NavBar.TFrame", padding=(18, 4, 18, 0))
        nav_bar.pack(fill="x")
        self.engine_nav: dict[str, tuple[tk.Button, tk.Frame]] = {}
        for key, title in (
            ("legacy", "Проверка подписки"),
            ("mihomo", "Mihomo / OpenClash"),
        ):
            nav_item = tk.Frame(nav_bar, background="#0d1117")
            nav_item.pack(side="left", padx=(0, 6))
            nav_button = tk.Button(
                nav_item,
                text=title,
                command=lambda page=key: self._show_engine_page(page),
                background="#0d1117",
                foreground="#8b949e",
                activebackground="#161b22",
                activeforeground="#f0f6fc",
                borderwidth=0,
                highlightthickness=0,
                relief="flat",
                padx=12,
                pady=6,
                font=("Segoe UI Semibold", 9),
                cursor="hand2",
            )
            nav_button.pack(fill="x")
            nav_indicator = tk.Frame(nav_item, height=2, background="#0d1117")
            nav_indicator.pack(fill="x")
            self.engine_nav[key] = (nav_button, nav_indicator)

        self.engine_content = ttk.Frame(shell)
        self.engine_content.pack(fill="both", expand=True)
        self.engine_content.rowconfigure(0, weight=1)
        self.engine_content.columnconfigure(0, weight=1)
        legacy_page = ttk.Frame(self.engine_content)
        mihomo_page = ttk.Frame(self.engine_content)
        legacy_page.grid(row=0, column=0, sticky="nsew")
        mihomo_page.grid(row=0, column=0, sticky="nsew")
        self.engine_pages = {"legacy": legacy_page, "mihomo": mihomo_page}

        outer = ttk.Frame(legacy_page, padding=(20, 14, 20, 14))
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer, style="PageHeader.TFrame", padding=(0, 0, 0, 8))
        header.pack(fill="x")
        ttk.Label(
            header, text="Проверка подписки", style="PageTitle.TLabel"
        ).pack(side="left")
        ttk.Label(
            header,
            text="Добавьте подписку и запустите проверку. Остальное приложение сделает само.",
            style="PageSubtitle.TLabel",
        ).pack(side="left", padx=(14, 0), pady=(3, 0))
        source_card = ttk.Frame(outer, style="Card.TFrame", padding=(12, 8))
        source_card.pack(fill="x", pady=(0, 10))
        source_header = ttk.Frame(source_card, style="CardBody.TFrame")
        source_header.pack(fill="x", pady=(0, 5))
        source_copy = ttk.Frame(source_header, style="CardBody.TFrame")
        source_copy.pack(side="left")
        ttk.Label(
            source_copy, text="1. Добавьте подписку", style="CardTitle.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            source_copy,
            text="Вставьте ссылку, содержимое подписки или выберите файл",
            style="CardBody.TLabel",
        ).pack(anchor="w")
        self.clear_source_button = ttk.Button(
            source_header,
            text="Очистить",
            command=self._clear_source,
            style="Secondary.TButton",
        )
        self.clear_source_button.pack(side="right")
        self.file_button = ttk.Button(
            source_header,
            text="Выбрать файл…",
            command=self._choose_file,
            style="Secondary.TButton",
        )
        self.file_button.pack(side="right", padx=(0, 5))
        self.paste_button = ttk.Button(
            source_header,
            text="Вставить",
            command=self._paste,
            style="Secondary.TButton",
        )
        self.paste_button.pack(side="right", padx=(0, 5))
        self.source = tk.Text(
            source_card,
            height=1,
            wrap="word",
            undo=True,
            background="#0d1117",
            foreground="#f0f6fc",
            insertbackground="#f0f6fc",
            selectbackground="#1f6feb",
            relief="flat",
            padx=9,
            pady=6,
            highlightthickness=1,
            highlightbackground="#30363d",
            highlightcolor="#58a6ff",
        )
        self.source.pack(fill="x")
        self.source.bind("<Control-KeyPress>", self._source_keyboard_shortcut)
        self.source.bind("<Control-Insert>", self._source_copy_event)
        self.source.bind("<Shift-Insert>", self._source_paste_event)

        command_bar = ttk.Frame(outer, style="Hero.TFrame", padding=(14, 11))
        command_bar.pack(fill="x", pady=(0, 12))
        self.magic_button = ttk.Button(
            command_bar,
            text="⚡",
            command=self._start_one_click,
            style="Launch.TButton",
            width=4,
        )
        self.magic_button.pack(side="left")
        self.magic_button.bind("<Enter>", self._show_magic_button_label)
        self.magic_button.bind("<Leave>", self._hide_magic_button_label)
        self.magic_button.bind("<FocusIn>", self._show_magic_button_label)
        self.magic_button.bind("<FocusOut>", self._hide_magic_button_label)
        command_copy = ttk.Frame(command_bar, style="HeroBody.TFrame")
        command_copy.pack(side="left", padx=(14, 0))
        ttk.Label(
            command_copy,
            text="2. Запустите полную проверку",
            style="PanelTitle.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            command_copy,
            text="Пинг → скорость → доступ к сайтам → готовые ключи",
            style="Hero.TLabel",
        ).pack(anchor="w", pady=(2, 0))
        self.advanced_toggle_button = ttk.Button(
            command_bar,
            text="Расширенные настройки",
            command=self._toggle_advanced_settings,
            style="Secondary.TButton",
        )
        self.advanced_toggle_button.pack(side="right")
        self.stop_button = ttk.Button(
            command_bar,
            text="Остановить",
            command=self._stop,
            state="disabled",
            style="Secondary.TButton",
        )
        self.stop_button.pack(side="right", padx=(0, 6))

        self.schedule_frame = ttk.Frame(outer)
        self.schedule_frame.pack(fill="x", pady=(0, 12))
        schedule_header = ttk.Frame(self.schedule_frame)
        schedule_header.pack(fill="x", pady=(0, 7))
        ttk.Label(
            schedule_header, text="Расписание", style="SectionTitle.TLabel"
        ).pack(side="left")
        ttk.Label(
            schedule_header,
            text="Необязательно — включайте только если нужна автоматическая проверка",
            style="Summary.TLabel",
        ).pack(side="left", padx=(12, 0))

        schedule_cards = ttk.Frame(self.schedule_frame)
        schedule_cards.pack(fill="x")
        schedule_cards.columnconfigure(0, weight=1, uniform="schedule")
        schedule_cards.columnconfigure(1, weight=1, uniform="schedule")

        auto_card = ttk.Frame(schedule_cards, style="Card.TFrame", padding=(12, 8))
        auto_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        ttk.Checkbutton(
            auto_card,
            text="Проверять всю подписку автоматически",
            variable=self.auto_enabled_var,
            command=self._toggle_auto,
            style="Card.TCheckbutton",
        ).pack(anchor="w")
        ttk.Label(
            auto_card,
            textvariable=self.auto_countdown_var,
            style="Countdown.TLabel",
        ).pack(anchor="w", pady=(4, 7))
        auto_controls = ttk.Frame(auto_card, style="CardBody.TFrame")
        auto_controls.pack(fill="x")
        ttk.Label(auto_controls, text="Каждые", style="CardDim.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        self._numeric_stepper(
            auto_controls,
            self.auto_interval_var,
            1,
            1440,
            1,
            width=4,
            frame_style="CardBody.TFrame",
            padx=(7, 7),
        )
        ttk.Label(auto_controls, text="минут", style="CardDim.TLabel").grid(
            row=0, column=2, sticky="w"
        )
        watch_card = ttk.Frame(schedule_cards, style="Card.TFrame", padding=(12, 8))
        watch_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ttk.Checkbutton(
            watch_card,
            text="Следить за сохранёнными серверами",
            variable=self.watch_enabled_var,
            command=self._toggle_watch,
            style="Card.TCheckbutton",
        ).pack(anchor="w")
        ttk.Label(
            watch_card,
            textvariable=self.watch_countdown_var,
            style="Countdown.TLabel",
        ).pack(anchor="w", pady=(4, 7))
        watch_controls = ttk.Frame(watch_card, style="CardBody.TFrame")
        watch_controls.pack(fill="x")
        watch_controls.columnconfigure(4, weight=1)
        ttk.Label(watch_controls, text="Каждые", style="CardDim.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        self._numeric_stepper(
            watch_controls,
            self.watch_interval_var,
            1,
            1440,
            1,
            width=4,
            frame_style="CardBody.TFrame",
            padx=(7, 7),
        )
        ttk.Label(watch_controls, text="минут", style="CardDim.TLabel").grid(
            row=0, column=2, sticky="w"
        )
        self.watch_now_button = ttk.Button(
            watch_controls,
            text="Проверить сейчас",
            command=self._start_watch_check,
            state="normal" if self.watched_uris else "disabled",
            style="Secondary.TButton",
        )
        self.watch_now_button.grid(row=0, column=5, sticky="e")

        self.advanced_window = tk.Toplevel(self)
        self.advanced_window.withdraw()
        self.advanced_window.title(f"Расширенные настройки — {APP_TITLE}")
        self.advanced_window.configure(background="#0d1117")
        self.advanced_window.transient(self)
        self.advanced_window.protocol(
            "WM_DELETE_WINDOW", self._close_advanced_settings
        )
        self.advanced_frame = ttk.Frame(
            self.advanced_window, style="Panel.TFrame", padding=(18, 16)
        )
        self.advanced_frame.pack(fill="both", expand=True, padx=12, pady=12)
        checks_panel = ttk.Frame(self.advanced_frame, style="PanelBody.TFrame")
        checks_panel.pack(fill="x")

        advanced_intro = ttk.Frame(checks_panel, style="PanelBody.TFrame")
        advanced_intro.pack(fill="x", pady=(0, 10))
        ttk.Label(
            advanced_intro,
            text="Расширенные настройки",
            style="PanelTitle.TLabel",
        ).pack(side="left")
        ttk.Label(
            advanced_intro,
            text="Здесь можно изменить сайты и технические параметры. Обычно это не требуется.",
            style="PanelDim.TLabel",
        ).pack(side="left", padx=(12, 0))

        ttk.Label(
            checks_panel, text="ЧТО ПРОВЕРЯТЬ", style="Section.TLabel"
        ).pack(anchor="w", pady=(0, 5))
        services = ttk.Frame(checks_panel, style="PanelBody.TFrame")
        services.pack(fill="x")
        ttk.Label(services, text="Сайты", style="PanelTitle.TLabel").pack(
            side="left", padx=(0, 8)
        )
        self.service_menu_button = ttk.Menubutton(
            services,
            textvariable=self.service_menu_text_var,
            style="Service.TMenubutton",
            width=19,
        )
        service_menu = tk.Menu(
            self.service_menu_button,
            tearoff=False,
            background="#161b22",
            foreground="#f0f6fc",
            activebackground="#1f6feb",
            activeforeground="#ffffff",
            selectcolor="#3fb950",
        )
        for service in local_checker.SERVICE_DEFINITIONS:
            service_menu.add_checkbutton(
                label=service.name,
                variable=self.service_vars[service.name],
                command=self._service_selection_changed,
            )
        self.service_menu_button.configure(menu=service_menu)
        self.service_menu_button.pack(side="left")
        ttk.Label(
            services,
            text="Только серверы, прошедшие основной тест",
            style="PanelDim.TLabel",
        ).pack(side="left", padx=(8, 0))

        tk.Frame(
            checks_panel, height=1, background="#30363d"
        ).pack(fill="x", pady=7)

        parameters_header = ttk.Frame(checks_panel, style="PanelBody.TFrame")
        parameters_header.pack(fill="x", pady=(0, 4))
        ttk.Label(
            parameters_header, text="ПАРАМЕТРЫ ПРОВЕРКИ", style="Section.TLabel"
        ).pack(side="left")
        ttk.Label(
            parameters_header,
            text="Обычно менять не требуется",
            style="PanelDim.TLabel",
        ).pack(side="left", padx=(10, 0))
        parameters = ttk.Frame(checks_panel, style="PanelBody.TFrame")
        parameters.pack(fill="x")
        for column, label, variable, minimum, maximum, width, unit in (
            (0, "Прогоны", self.rounds_var, 1, 5, 3, "раз"),
            (1, "Тайм-аут", self.timeout_var, 1, 60, 3, "сек"),
            (2, "Потоки", self.workers_var, 1, 256, 4, "шт"),
            (3, "Быстрые до", self.latency_var, 1, 10000, 5, "мс"),
        ):
            parameters.columnconfigure(column, weight=1, uniform="parameters")
            group = ttk.Frame(parameters, style="PanelBody.TFrame")
            group.grid(row=0, column=column, sticky="w", padx=(0, 14))
            ttk.Label(group, text=label, style="PanelDim.TLabel").grid(
                row=0, column=0, columnspan=2, sticky="w", pady=(0, 3)
            )
            self._numeric_stepper(
                group,
                variable,
                minimum,
                maximum,
                0,
                row=1,
                width=width,
                padx=(0, 5),
            )
            ttk.Label(group, text=unit, style="PanelDim.TLabel").grid(
                row=1, column=1, sticky="w"
            )

        tk.Frame(
            checks_panel, height=1, background="#30363d"
        ).pack(fill="x", pady=7)

        ttk.Label(
            checks_panel, text="РУЧНЫЕ ЗАПУСКИ", style="Section.TLabel"
        ).pack(anchor="w", pady=(0, 4))
        manual = ttk.Frame(checks_panel, style="PanelBody.TFrame")
        manual.pack(fill="x")
        self.start_button = ttk.Button(manual, text="Только пинг", command=self._start)
        self.start_button.pack(side="left")
        self.speed_button = ttk.Button(
            manual,
            text="Скорость годных",
            command=self._start_speed_test,
            state="disabled",
        )
        self.speed_button.pack(side="left", padx=(5, 0))
        self.service_button = ttk.Button(
            manual,
            text="Выбранные сайты",
            command=self._start_service_test,
            state="disabled",
        )
        self.service_button.pack(side="left", padx=(5, 0))

        self.results_header = ttk.Frame(outer, padding=(0, 2, 0, 7))
        self.results_header.pack(fill="x")
        self.results_actions_frame = ttk.Frame(self.results_header)
        self.results_actions_frame.pack(side="right")
        self.active_button = ttk.Button(
            self.results_actions_frame,
            text="Сохранить доступные",
            command=self._save_active,
            state="disabled",
            style="Secondary.TButton",
        )
        self.active_button.pack(side="right")
        self.fast_button = ttk.Button(
            self.results_actions_frame,
            text="Сохранить годные",
            command=self._save_fast,
            state="disabled",
            style="Secondary.TButton",
        )
        self.fast_button.pack(side="right", padx=(0, 5))
        self.copy_button = ttk.Button(
            self.results_actions_frame,
            text="Копировать годные",
            command=self._copy_fast,
            state="disabled",
            style="Secondary.TButton",
        )
        self.copy_button.pack(side="right", padx=(0, 5))
        self.copy_selected_button = ttk.Button(
            self.results_actions_frame,
            text="Копировать выбранные",
            command=self._copy_selected,
            state="disabled",
            style="Secondary.TButton",
        )
        self.copy_selected_button.pack(side="right", padx=(0, 5))

        results_copy = ttk.Frame(self.results_header)
        results_copy.pack(side="left", fill="x", expand=True)
        ttk.Label(
            results_copy, text="Результаты", style="SectionTitle.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            results_copy, textvariable=self.summary_var, style="Summary.TLabel"
        ).pack(anchor="w", pady=(2, 0))

        self.table_frame = ttk.Frame(outer, style="Panel.TFrame", padding=1)
        self.table_frame.pack(fill="both", expand=True)
        table_frame = self.table_frame
        self.table = ttk.Treeview(
            table_frame,
            columns=TABLE_COLUMNS,
            show="headings",
            selectmode="extended",
            height=2,
        )
        headings = {
            "number": "#",
            "protocol": "Тип",
            "endpoint": "Адрес",
            "name": "Имя / ошибка",
            "latency": "Пинг",
            "speed": "Мбит/с",
            "quality": "Рейтинг",
            "passes": "Тесты",
        }
        headings.update(
            {
                SERVICE_COLUMN_BY_NAME[service.name]: (
                    "Telegram" if service.name == "Telegram Web" else service.name
                )
                for service in local_checker.SERVICE_DEFINITIONS
            }
        )
        self.column_headings = headings
        widths = {
            "number": 34,
            "protocol": 60,
            "endpoint": 140,
            "name": 170,
            "latency": 62,
            "speed": 66,
            "quality": 72,
            "passes": 52,
        }
        widths.update({column: 70 for column in SERVICE_NAME_BY_COLUMN})
        minimum_widths = {
            "number": 30,
            "protocol": 48,
            "endpoint": 105,
            "name": 105,
            "latency": 52,
            "speed": 54,
            "quality": 56,
            "passes": 44,
        }
        minimum_widths.update({column: 55 for column in SERVICE_NAME_BY_COLUMN})
        self.table_column_widths = widths
        self.table_column_minimums = minimum_widths
        for column in TABLE_COLUMNS:
            self.table.heading(
                column,
                text=headings[column],
                command=lambda selected=column: self._sort_table(selected),
            )
            self.table.column(
                column,
                width=widths[column],
                minwidth=minimum_widths[column],
                stretch=column in {"endpoint", "name"},
            )
        self._refresh_sort_headers()
        self._refresh_service_columns()
        self.table.tag_configure("fast", foreground="#3fb950")
        self.table.tag_configure("active", foreground="#d29922")
        self.table.tag_configure("dead", foreground="#f85149")
        self.table.tag_configure("pending", foreground="#6e7681")
        table_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table_scroll_x = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.table.xview
        )
        self.table.configure(
            yscrollcommand=table_scroll.set,
            xscrollcommand=self.table_scroll_x.set,
        )
        self.table.bind("<<TreeviewSelect>>", self._selection_changed)
        self.table.bind("<Control-c>", self._copy_selected_event)
        self.table.bind("<Configure>", self._schedule_table_fit, add="+")
        table_frame.bind("<Configure>", self._schedule_table_fit, add="+")
        self.bind("<Configure>", self._schedule_table_fit, add="+")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.table.grid(row=0, column=0, sticky="nsew")
        table_scroll.grid(row=0, column=1, sticky="ns")
        self.table_scroll_x.grid(row=1, column=0, sticky="ew")

        self.log_visible = False
        self.log_frame = ttk.Frame(outer, style="Card.TFrame", padding=(8, 6))
        ttk.Label(self.log_frame, text="Журнал", style="Section.TLabel").pack(
            anchor="w"
        )
        self.log = tk.Text(
            self.log_frame,
            height=3,
            background="#0d1117",
            foreground="#8b949e",
            insertbackground="#f0f6fc",
            relief="flat",
            state="disabled",
            font=("Consolas", 9),
            padx=6,
            pady=4,
        )
        self.log.pack(fill="x")

        self.progress = ttk.Progressbar(outer, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", pady=(5, 3))
        statusbar = ttk.Frame(outer)
        statusbar.pack(fill="x")
        ttk.Label(statusbar, textvariable=self.status_var).pack(side="left")
        self.log_toggle_button = ttk.Button(
            statusbar,
            text="Журнал",
            command=self._toggle_log,
            style="Utility.TButton",
        )
        self.log_toggle_button.pack(side="right")

        self.mihomo_tab = MihomoCheckerTab(
            mihomo_page,
            network_callback=lambda status: self.events.put(("network_state", status)),
        )
        self.mihomo_tab.pack(fill="both", expand=True)
        self._show_engine_page("legacy")

    def _show_engine_page(self, page: str) -> None:
        target = self.engine_pages.get(page)
        if target is None:
            return
        target.tkraise()
        for key, (button, indicator) in self.engine_nav.items():
            selected = key == page
            button.configure(
                background="#161b22" if selected else "#0d1117",
                foreground="#f0f6fc" if selected else "#8b949e",
            )
            indicator.configure(
                background="#2f81f7" if selected else "#0d1117"
            )

    def _schedule_network_refresh(self) -> None:
        if self.network_job is not None:
            try:
                self.after_cancel(self.network_job)
            except tk.TclError:
                pass
        self.network_job = None if self.closing else self.after(30_000, self._refresh_network_status)

    def _refresh_network_status(self) -> None:
        self.network_job = None
        if self.closing or self.network_check_in_progress:
            return
        self.network_check_in_progress = True
        self.network_status_var.set("Проверка сети…")
        self.network_status_label.configure(style="NetworkPending.TLabel")

        def worker() -> None:
            status = network_check.check_device_online()
            self.events.put(("network_state", status))

        threading.Thread(
            target=worker,
            name="wireveil-network-status",
            daemon=True,
        ).start()

    def _apply_network_status(self, status: network_check.NetworkStatus) -> None:
        self.network_check_in_progress = False
        if status.online:
            self.network_status_var.set("● Сеть доступна")
            self.network_status_label.configure(style="NetworkOnline.TLabel")
        else:
            self.network_status_var.set("● Нет подключения")
            self.network_status_label.configure(style="NetworkOffline.TLabel")
        self._schedule_network_refresh()

    def _configure_update_buttons(self, *, text: str, state: str) -> None:
        for button in self.update_buttons:
            button.configure(text=text, state=state)

    def _check_for_updates(self) -> None:
        if self.update_busy or self.running or self.closing:
            return
        self.update_busy = True
        self._configure_update_buttons(text="Проверка…", state="disabled")
        self.status_var.set("Проверяем обновления WireVeil Checker…")
        self._log(f"Проверка обновлений для версии {APP_VERSION}.")

        def worker() -> None:
            try:
                release = app_updater.check_for_update(APP_VERSION)
            except app_updater.UpdateError as exc:
                self.events.put(("update_error", str(exc)))
            else:
                self.events.put(("update_checked", release))

        threading.Thread(target=worker, daemon=True, name="wireveil-update-check").start()

    def _finish_update_check(
        self, release: app_updater.ReleaseUpdate | None
    ) -> None:
        if release is None:
            self.update_busy = False
            self._configure_update_buttons(text="Обновления", state="normal")
            self.status_var.set(f"Установлена актуальная версия {APP_VERSION}")
            self._log("Новых стабильных версий нет.")
            return

        install = messagebox.askyesno(
            APP_TITLE,
            f"Доступна версия {release.version}.\n\n"
            "Скачать и установить обновление сейчас? "
            "После проверки файла приложение закроется, а установщик запустится автоматически.",
            parent=self,
        )
        if not install:
            self.update_busy = False
            self._configure_update_buttons(text="Обновления", state="normal")
            self.status_var.set(f"Доступна версия {release.version}")
            self._log(f"Обновление до {release.version} отложено пользователем.")
            return

        self._configure_update_buttons(text="Скачивание…", state="disabled")
        self.status_var.set(f"Скачиваем WireVeil Checker {release.version}…")
        self.update_downloading = True
        self._cancel_background_timers()
        self._set_running_controls(True)
        self.stop_button.configure(state="disabled")

        def progress(downloaded: int, total: int | None) -> None:
            self.events.put(("update_progress", downloaded, total, release.version))

        def worker() -> None:
            try:
                installer = app_updater.download_update(release, progress=progress)
            except app_updater.UpdateError as exc:
                self.events.put(("update_error", str(exc)))
            else:
                self.events.put(("update_downloaded", installer, release.version))

        threading.Thread(target=worker, daemon=True, name="wireveil-update-download").start()

    def _show_update_progress(
        self, downloaded: int, total: int | None, version: str
    ) -> None:
        downloaded_mb = downloaded / (1024 * 1024)
        if total:
            total_mb = total / (1024 * 1024)
            self.status_var.set(
                f"Скачиваем версию {version}: {downloaded_mb:.1f} / {total_mb:.1f} МБ"
            )
        else:
            self.status_var.set(
                f"Скачиваем версию {version}: {downloaded_mb:.1f} МБ"
            )

    def _finish_update_download(self, installer: Path, version: str) -> None:
        self._configure_update_buttons(text="Запуск установщика…", state="disabled")
        self.status_var.set("Контрольная сумма верна. Запускаем установщик…")
        try:
            app_updater.launch_installer(installer)
        except app_updater.UpdateError as exc:
            self._finish_update_error(str(exc))
            return
        self._log(
            f"Установщик версии {version} проверен и запущен; приложение закрывается."
        )
        self.closing = True
        self.after(150, self._on_close)

    def _finish_update_error(self, detail: str) -> None:
        was_downloading = self.update_downloading
        self.update_busy = False
        self.update_downloading = False
        self._configure_update_buttons(text="Обновления", state="normal")
        self.status_var.set("Не удалось обновить WireVeil Checker")
        self._log(f"Ошибка обновления: {detail}")
        if was_downloading:
            self._set_running_controls(False)
            self._restore_result_buttons()
        if not self.closing:
            if was_downloading:
                self._schedule_background_checks()
            messagebox.showerror(APP_TITLE, detail, parent=self)

    def _watch_settings(self) -> None:
        variables = (
            self.rounds_var,
            self.timeout_var,
            self.workers_var,
            self.latency_var,
            self.auto_enabled_var,
            self.auto_interval_var,
            self.watch_enabled_var,
            self.watch_interval_var,
            *self.service_vars.values(),
        )
        for variable in variables:
            variable.trace_add("write", self._queue_settings_save)
        self.auto_interval_var.trace_add("write", self._queue_timer_refresh)
        self.watch_interval_var.trace_add("write", self._queue_timer_refresh)
        self.source.bind("<<Modified>>", self._source_settings_changed, add=True)
        self.source.edit_modified(False)

    def _queue_timer_refresh(self, *_args: object) -> None:
        if self.closing or self.running:
            return
        if self.timer_refresh_job is not None:
            try:
                self.after_cancel(self.timer_refresh_job)
            except tk.TclError:
                pass
        self.timer_refresh_job = self.after(500, self._refresh_scheduled_intervals)

    def _refresh_scheduled_intervals(self) -> None:
        self.timer_refresh_job = None
        if self.auto_job is not None:
            self._schedule_auto_check()
        if self.watch_job is not None:
            self._schedule_watch_check()

    def _source_settings_changed(self, _event: object | None = None) -> None:
        if not self.source.edit_modified():
            return
        self.source.edit_modified(False)
        self._queue_settings_save()

    def _queue_settings_save(self, *_args: object) -> None:
        if self.closing:
            return
        if self.settings_save_job is not None:
            try:
                self.after_cancel(self.settings_save_job)
            except tk.TclError:
                pass
        self.settings_save_job = self.after(400, self._save_settings)

    @staticmethod
    def _saved_int(variable: tk.Variable, default: int) -> int:
        try:
            return int(variable.get())
        except (TypeError, ValueError, tk.TclError):
            return default

    def _save_settings(self) -> None:
        self.settings_save_job = None
        settings: dict[str, object] = {
            "rounds": _bounded_int(self._saved_int(self.rounds_var, 2), 2, 1, 5),
            "timeout": _bounded_int(self._saved_int(self.timeout_var, 8), 8, 1, 60),
            "workers": _bounded_int(self._saved_int(self.workers_var, 64), 64, 1, 256),
            "latency": _bounded_int(
                self._saved_int(self.latency_var, 500), 500, 1, 10_000
            ),
            "auto_enabled": bool(self.auto_enabled_var.get()),
            "auto_interval": _bounded_int(
                self._saved_int(self.auto_interval_var, 30), 30, 1, 1440
            ),
            "watch_enabled": bool(self.watch_enabled_var.get()),
            "watch_interval": _bounded_int(
                self._saved_int(self.watch_interval_var, 30), 30, 1, 1440
            ),
            "watched_uris": list(self.watched_uris),
            "services": list(self._selected_service_names()),
            "advanced_visible": self.advanced_visible,
            "subscription": self.source.get("1.0", "end-1c"),
        }
        try:
            write_checker_settings(self.settings_path, settings)
            self.settings_save_error_reported = False
        except OSError as exc:
            if not self.settings_save_error_reported:
                self._log(f"Не удалось сохранить настройки: {exc}")
                self.settings_save_error_reported = True

    def _save_last_results(self, *, mode: str = "full") -> None:
        if self.report is None:
            return
        try:
            write_checker_results(
                self.results_path,
                self.source.get("1.0", "end-1c"),
                self.report,
                self.speed_results,
                self.service_results,
                sort_column=self.sort_column,
                sort_descending=self.sort_descending,
                mode=mode,
            )
            self.results_save_error_reported = False
        except (OSError, ValueError, TypeError) as exc:
            if not self.results_save_error_reported:
                self._log(f"Не удалось сохранить последний результат: {exc}")
                self.results_save_error_reported = True

    def _restore_last_results(self, source: str) -> None:
        saved = load_checker_results(self.results_path, source)
        if saved is None:
            return
        self.report = saved.report
        self.imported = local_checker.ImportedSubscription(saved.report.candidates)
        self.speed_results = dict(saved.speed_results)
        self.service_results = dict(saved.service_results)
        self.sort_column = saved.sort_column
        self.sort_descending = saved.sort_descending
        self._populate_table(saved.report)
        if self.service_results:
            for result in saved.report.results:
                self._update_service_quality(result.target.index)
        if self.sort_column is not None:
            self._apply_sort()
        self.progress_var.set(100)
        active = saved.report.active_results
        fast = saved.report.fast_results(self._latency_limit())
        saved_label = time.strftime(
            "%d.%m.%Y %H:%M", time.localtime(saved.saved_at)
        )
        if saved.mode == "watch":
            self.status_var.set("Восстановлен последний контроль доступности")
        else:
            self.status_var.set("Восстановлена последняя проверка")
        self.summary_var.set(
            f"Всего {len(saved.report.candidates)}  |  доступны {len(active)}  |  "
            f"быстрых {len(fast)}  |  сохранено {saved_label}"
        )
        self._restore_result_buttons()
        self._log(
            f"Последний результат восстановлен: {len(saved.report.candidates)} "
            f"серверов, сохранён {saved_label}."
        )

    def _toggle_log(self) -> None:
        if self.log_visible:
            self.log_frame.pack_forget()
            self.log_visible = False
            self.log_toggle_button.configure(text="Журнал")
            return
        self.log_frame.pack(fill="x", pady=(5, 0), before=self.progress)
        self.log_visible = True
        self.log_toggle_button.configure(text="Скрыть журнал")

    def _show_magic_button_label(self, _event: object | None = None) -> None:
        if self.magic_button.instate(("disabled",)) or self.magic_tooltip is not None:
            return
        tooltip = tk.Toplevel(self)
        tooltip.overrideredirect(True)
        tooltip.attributes("-topmost", True)
        label = tk.Label(
            tooltip,
            text="Сделать заебись",
            background="#21262d",
            foreground="#f0f6fc",
            font=("Segoe UI Semibold", 10),
            padx=10,
            pady=6,
            relief="solid",
            borderwidth=1,
        )
        label.pack()
        tooltip.update_idletasks()
        x = self.magic_button.winfo_rootx() + self.magic_button.winfo_width() + 8
        y = self.magic_button.winfo_rooty() + max(
            0, (self.magic_button.winfo_height() - tooltip.winfo_reqheight()) // 2
        )
        tooltip.geometry(f"+{x}+{y}")
        self.magic_tooltip = tooltip

    def _hide_magic_button_label(self, _event: object | None = None) -> None:
        if self.magic_tooltip is not None:
            self.magic_tooltip.destroy()
            self.magic_tooltip = None

    def _show_rkn_easter_egg(self, _event: object | None = None) -> str:
        if self.easter_window is not None and self.easter_window.winfo_exists():
            self.easter_window.lift()
            return "break"

        window = tk.Toplevel(self)
        window.overrideredirect(True)
        window.configure(background="#30363d")
        try:
            window.attributes("-topmost", True)
        except tk.TclError:
            pass
        width, height = 430, 270
        x = max(0, self.winfo_rootx() + (self.winfo_width() - width) // 2)
        y = max(0, self.winfo_rooty() + (self.winfo_height() - height) // 3)
        window.geometry(f"{width}x{height}+{x}+{y}")
        canvas = tk.Canvas(
            window,
            width=width,
            height=height,
            background="#0d1117",
            highlightthickness=1,
            highlightbackground="#58a6ff",
            borderwidth=0,
        )
        canvas.pack(fill="both", expand=True)
        canvas.create_text(
            18,
            17,
            text="СЕКРЕТНЫЙ ПРОТОКОЛ",
            anchor="w",
            fill="#8b949e",
            font=("Segoe UI Semibold", 9),
        )
        canvas.create_text(
            18,
            42,
            text="РКН-тян обнаружена",
            anchor="w",
            fill="#f0f6fc",
            font=("Segoe UI Semibold", 14),
        )

        # Hair, head and body form a small code-drawn mascot; no external assets.
        canvas.create_oval(
            151, 55, 249, 157, fill="#6e40c9", outline="#a371f7", width=2,
            tags=("rkn",),
        )
        canvas.create_oval(
            166, 65, 234, 140, fill="#ffd7c2", outline="#f2b8a0", width=2,
            tags=("rkn",),
        )
        canvas.create_polygon(
            164, 83, 178, 62, 196, 76, 210, 61, 237, 83, 232, 59, 170, 58,
            fill="#6e40c9", outline="", tags=("rkn",),
        )
        canvas.create_line(
            181, 104, 189, 104, fill="#24292f", width=2, tags=("rkn", "rkn_face"),
        )
        canvas.create_line(
            211, 104, 219, 104, fill="#24292f", width=2, tags=("rkn", "rkn_face"),
        )
        canvas.create_arc(
            190, 108, 211, 126, start=205, extent=130, style=tk.ARC,
            outline="#cf6a87", width=2, tags=("rkn", "rkn_face"),
        )
        canvas.create_polygon(
            170, 139, 230, 139, 250, 231, 150, 231,
            fill="#8c2f39", outline="#f85149", width=2, tags=("rkn",),
        )
        canvas.create_text(
            200, 181, text="РКН", fill="#ffffff",
            font=("Segoe UI Black", 15), tags=("rkn",),
        )
        canvas.create_line(
            171, 151, 135, 196, fill="#ffd7c2", width=9,
            capstyle=tk.ROUND, tags=("rkn",),
        )
        canvas.create_line(
            229, 151, 265, 196, fill="#ffd7c2", width=9,
            capstyle=tk.ROUND, tags=("rkn",),
        )
        canvas.create_line(
            178, 226, 171, 257, fill="#c9d1d9", width=10,
            capstyle=tk.ROUND, tags=("rkn",),
        )
        canvas.create_line(
            222, 226, 229, 257, fill="#c9d1d9", width=10,
            capstyle=tk.ROUND, tags=("rkn",),
        )

        canvas.create_line(
            385, 35, 275, -70, fill="#8b5a2b", width=15,
            capstyle=tk.ROUND, tags=("bat_line",),
        )
        canvas.create_line(
            385, 35, 275, -70, fill="#d29922", width=8,
            capstyle=tk.ROUND, tags=("bat_core",),
        )
        canvas.create_oval(
            374, 24, 396, 46, fill="#ffd7c2", outline="#f2b8a0",
            tags=("bat_hand",),
        )
        canvas.create_text(
            width - 12,
            height - 10,
            text="Esc — закрыть",
            anchor="se",
            fill="#6e7681",
            font=("Segoe UI", 8),
        )

        self.easter_window = window
        window.bind("<Escape>", lambda _event: self._close_rkn_easter_egg())
        window.bind("<Destroy>", self._rkn_easter_destroyed, add="+")
        self.easter_job = window.after(
            80, lambda: self._animate_rkn_easter_egg(window, canvas, 0)
        )
        window.focus_force()
        return "break"

    def _animate_rkn_easter_egg(
        self, window: tk.Toplevel, canvas: tk.Canvas, frame: int
    ) -> None:
        self.easter_job = None
        if self.easter_window is not window or not window.winfo_exists():
            return
        pivot_x, pivot_y, length = 385, 35, 185
        if frame <= 12:
            angle = math.radians(225 - (75 * frame / 12))
            tip_x = pivot_x + length * math.cos(angle)
            tip_y = pivot_y + length * math.sin(angle)
            canvas.coords("bat_line", pivot_x, pivot_y, tip_x, tip_y)
            canvas.coords("bat_core", pivot_x, pivot_y, tip_x, tip_y)
        if frame == 12:
            canvas.delete("rkn_face")
            for left in (180, 211):
                canvas.create_line(
                    left, 99, left + 10, 109, left, 109, left + 10, 99,
                    fill="#24292f", width=2, tags=("rkn",),
                )
            canvas.create_text(
                115, 80, text="БОНК!", fill="#f2cc60",
                font=("Segoe UI Black", 18), tags=("impact",),
            )
            for x, y in ((145, 106), (158, 79), (132, 128), (252, 91)):
                canvas.create_text(
                    x, y, text="★", fill="#f2cc60",
                    font=("Segoe UI", 16), tags=("impact",),
                )
        elif 13 <= frame <= 22:
            canvas.move("rkn", 7 if frame % 2 else -7, 0)
        elif 23 <= frame <= 38:
            canvas.move("rkn", 10, 13)
            canvas.move("impact", 0, -2)
        elif frame == 39:
            canvas.delete("rkn")
            canvas.delete("impact")
            canvas.create_text(
                215, 145, text="Удалено из реестра.", fill="#3fb950",
                font=("Segoe UI Semibold", 15), tags=("final",),
            )
        elif frame >= 52:
            self._close_rkn_easter_egg()
            return
        self.easter_job = window.after(
            38, lambda: self._animate_rkn_easter_egg(window, canvas, frame + 1)
        )

    def _rkn_easter_destroyed(self, event: tk.Event) -> None:
        if self.easter_window is not None and event.widget is self.easter_window:
            self.easter_window = None
            self.easter_job = None

    def _close_rkn_easter_egg(self) -> None:
        window = self.easter_window
        self.easter_window = None
        job = self.easter_job
        self.easter_job = None
        if window is not None and job is not None:
            try:
                window.after_cancel(job)
            except tk.TclError:
                pass
        if window is not None and window.winfo_exists():
            window.destroy()

    def _toggle_advanced_settings(self, *, persist: bool = True) -> None:
        if self.advanced_visible:
            self._close_advanced_settings(persist=persist)
            return
        self.advanced_window.deiconify()
        self.advanced_window.update_idletasks()
        width = min(
            max(780, self.advanced_window.winfo_reqwidth()),
            self.winfo_screenwidth() - 80,
        )
        height = min(
            max(360, self.advanced_window.winfo_reqheight()),
            self.winfo_screenheight() - 100,
        )
        x = max(0, self.winfo_rootx() + (self.winfo_width() - width) // 2)
        y = max(0, self.winfo_rooty() + (self.winfo_height() - height) // 2)
        self.advanced_window.geometry(f"{width}x{height}+{x}+{y}")
        self.advanced_window.lift()
        self.advanced_visible = True
        self.advanced_toggle_button.configure(text="Закрыть настройки")
        if persist:
            self._queue_settings_save()

    def _close_advanced_settings(self, *, persist: bool = True) -> None:
        if self.advanced_window.winfo_exists():
            self.advanced_window.withdraw()
        self.advanced_visible = False
        self.advanced_toggle_button.configure(text="Расширенные настройки")
        if persist:
            self._queue_settings_save()

    def _numeric_stepper(
        self,
        parent: ttk.Frame,
        variable: tk.IntVar,
        minimum: int,
        maximum: int,
        column: int,
        *,
        width: int = 5,
        row: int = 0,
        frame_style: str = "PanelBody.TFrame",
        padx: tuple[int, int] = (0, 18),
    ) -> None:
        frame = ttk.Frame(parent, style=frame_style)
        frame.grid(row=row, column=column, sticky="w", padx=padx)
        ttk.Entry(
            frame,
            textvariable=variable,
            width=width,
            justify="center",
            style="Stepper.TEntry",
        ).pack(side="left")
        ttk.Button(
            frame,
            text="−",
            width=2,
            style="Stepper.TButton",
            command=lambda: self._step_value(variable, minimum, maximum, -1),
        ).pack(side="left", padx=(2, 1))
        ttk.Button(
            frame,
            text="+",
            width=2,
            style="Stepper.TButton",
            command=lambda: self._step_value(variable, minimum, maximum, 1),
        ).pack(side="left")

    @staticmethod
    def _step_value(variable: tk.IntVar, minimum: int, maximum: int, delta: int) -> None:
        try:
            current = int(variable.get())
        except (ValueError, tk.TclError):
            current = minimum
        variable.set(min(maximum, max(minimum, current + delta)))

    def _paste(self) -> None:
        try:
            value = self.clipboard_get()
        except tk.TclError:
            messagebox.showinfo(APP_TITLE, "Буфер обмена пуст.")
            return
        self.source.delete("1.0", "end")
        self.source.insert("1.0", value)

    def _clear_source(self) -> None:
        if self.running:
            return
        self.source.delete("1.0", "end")
        self.imported = None
        self.status_var.set("Поле подписки и сохранённое значение очищены.")
        self._queue_settings_save()

    @staticmethod
    def _source_shortcut_action(event: object) -> str | None:
        keycode_actions = {65: "select_all", 67: "copy", 86: "paste", 88: "cut"}
        try:
            keycode = int(getattr(event, "keycode", -1))
        except (TypeError, ValueError):
            keycode = -1
        if keycode in keycode_actions:
            return keycode_actions[keycode]
        keysym = str(getattr(event, "keysym", "")).casefold()
        return {
            "a": "select_all",
            "c": "copy",
            "v": "paste",
            "x": "cut",
            "cyrillic_ef": "select_all",
            "cyrillic_es": "copy",
            "cyrillic_em": "paste",
            "cyrillic_che": "cut",
        }.get(keysym)

    def _source_copy_selection(self) -> bool:
        selection = self.source.tag_ranges("sel")
        if not selection:
            return False
        value = self.source.get(selection[0], selection[1])
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update_idletasks()
        return True

    def _source_paste_clipboard(self) -> None:
        try:
            value = self.clipboard_get()
        except tk.TclError:
            return
        selection = self.source.tag_ranges("sel")
        if selection:
            self.source.delete(selection[0], selection[1])
        self.source.insert("insert", value)
        self.source.see("insert")

    def _source_keyboard_shortcut(self, event: object) -> str | None:
        action = self._source_shortcut_action(event)
        if action == "copy":
            self._source_copy_selection()
        elif action == "paste":
            self._source_paste_clipboard()
        elif action == "cut":
            selection = self.source.tag_ranges("sel")
            if selection and self._source_copy_selection():
                self.source.delete(selection[0], selection[1])
        elif action == "select_all":
            self.source.tag_add("sel", "1.0", "end-1c")
            self.source.mark_set("insert", "end-1c")
            self.source.see("insert")
        else:
            return None
        return "break"

    def _source_copy_event(self, _event: object | None = None) -> str:
        self._source_copy_selection()
        return "break"

    def _source_paste_event(self, _event: object | None = None) -> str:
        self._source_paste_clipboard()
        return "break"

    def _choose_file(self) -> None:
        name = filedialog.askopenfilename(
            title="Выберите файл подписки",
            filetypes=(("Подписки", "*.txt *.conf *.json *.yaml *.yml"), ("Все файлы", "*.*")),
        )
        if not name:
            return
        try:
            imported = local_checker.read_subscription_file(Path(name))
        except local_checker.LocalCheckError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.imported = imported
        self.source.delete("1.0", "end")
        self.source.insert("1.0", "\n".join(imported.lines))
        self.status_var.set(f"Загружено ключей: {len(imported.lines)}")

    def _settings(self) -> tuple[int, int, int, int] | None:
        try:
            rounds = int(self.rounds_var.get())
            timeout = int(self.timeout_var.get())
            workers = int(self.workers_var.get())
            latency = int(self.latency_var.get())
        except (ValueError, tk.TclError):
            messagebox.showerror(APP_TITLE, "Проверьте числовые параметры.")
            return None
        if not 1 <= rounds <= 5 or not 1 <= timeout <= 60 or not 1 <= workers <= 256 or latency < 1:
            messagebox.showerror(APP_TITLE, "Параметры находятся вне допустимого диапазона.")
            return None
        return rounds, timeout, workers, latency

    def _start_one_click(self) -> None:
        if self.running:
            return
        for variable in self.service_vars.values():
            variable.set(True)
        self._service_selection_changed()
        self.one_click_mode = True
        self._start()
        if not self.running:
            self.one_click_mode = False

    def _start(self) -> None:
        if self.running:
            return
        settings = self._settings()
        if settings is None:
            return
        value = self.source.get("1.0", "end").strip()
        if not value:
            messagebox.showerror(APP_TITLE, "Вставьте ссылку или содержимое подписки.")
            return
        binary = find_sing_box()
        if binary is None:
            messagebox.showerror(
                APP_TITLE,
                "Рядом с приложением не найден sing-box. Скачайте готовый portable-архив из Releases.",
            )
            return

        rounds, timeout, workers, _latency = settings
        self._cancel_background_timers()
        self.running = True
        self.activity = "ping"
        self.report = None
        self.speed_results.clear()
        self.service_results.clear()
        self.cancel_event = threading.Event()
        self.progress_var.set(0)
        self.summary_var.set("Подготовка конфигураций…")
        self.status_var.set("Проверяю подключение к сети…")
        self._clear_table()
        self._clear_log()
        if self.one_click_mode:
            self._log(
                "Режим «Сделать заебись»: ping → скорость → все сайты → буфер."
            )
        else:
            self._log("Запуск проверки из текущей сети.")
        self._set_running_controls(True)

        def work() -> None:
            try:
                network_status = network_check.check_device_online()
                self.events.put(("network_state", network_status))
                if not network_status.online:
                    raise network_check.NetworkUnavailableError(
                        network_check.OFFLINE_MESSAGE
                    )
                imported = local_checker.import_subscription(value)
                self.events.put(("imported", imported, rounds))

                def progress(done: int, total: int, result: healthcheck.ProbeResult) -> None:
                    self.events.put(("progress", done, total, result, rounds))

                report = local_checker.run_local_check(
                    binary=binary,
                    lines=imported.lines,
                    timeout_ms=timeout * 1000,
                    workers=workers,
                    attempts=rounds,
                    progress_callback=progress,
                    cancel_event=self.cancel_event,
                )
                self.events.put(("done", report))
            except (
                network_check.NetworkUnavailableError,
                local_checker.LocalCheckError,
                healthcheck.HealthCheckError,
                build.BuildError,
                OSError,
            ) as exc:
                self.events.put(("error", str(exc)))
            except Exception as exc:  # Keep a windowed build diagnosable.
                self.events.put(("error", f"Непредвиденная ошибка: {type(exc).__name__}: {exc}"))

        threading.Thread(target=work, name="wireveil-check", daemon=True).start()

    def _start_watch_check(self) -> None:
        if self.running:
            return
        watched = self.watched_uris
        if not watched:
            self._log("Контроль доступности: пока нет скопированных годных серверов.")
            return
        binary = find_sing_box()
        if binary is None:
            self._log("Контроль доступности: не найден вложенный sing-box.")
            self._schedule_watch_check()
            return
        try:
            timeout = max(1, min(60, int(self.timeout_var.get())))
            workers = max(1, min(256, int(self.workers_var.get())))
        except (ValueError, tk.TclError):
            timeout, workers = 8, 64

        self._cancel_watch_timer()
        self.running = True
        self.activity = "watch"
        self.one_click_mode = False
        self.report = None
        self.speed_results.clear()
        self.service_results.clear()
        self.cancel_event = threading.Event()
        self.progress_var.set(0)
        self.status_var.set("Проверяю подключение к сети…")
        self.summary_var.set("Один HTTPS-прогон без скорости и проверки сайтов")
        self._clear_table()
        self._set_running_controls(True)
        self._log(
            f"Контроль доступности: один прогон для {len(watched)} "
            "скопированных зелёных серверов."
        )

        def work() -> None:
            try:
                network_status = network_check.check_device_online()
                self.events.put(("network_state", network_status))
                if not network_status.online:
                    raise network_check.NetworkUnavailableError(
                        network_check.OFFLINE_MESSAGE
                    )
                imported = local_checker.import_subscription("\n".join(watched))
                self.events.put(("watch_imported", imported))

                def progress(
                    done: int, total: int, result: healthcheck.ProbeResult
                ) -> None:
                    self.events.put(("watch_progress", done, total, result))

                report = local_checker.run_local_check(
                    binary=binary,
                    lines=imported.lines,
                    timeout_ms=timeout * 1000,
                    workers=workers,
                    attempts=1,
                    progress_callback=progress,
                    cancel_event=self.cancel_event,
                )
                self.events.put(("watch_done", report))
            except (
                network_check.NetworkUnavailableError,
                local_checker.LocalCheckError,
                healthcheck.HealthCheckError,
                build.BuildError,
                OSError,
            ) as exc:
                self.events.put(("watch_error", str(exc)))
            except Exception as exc:
                self.events.put(
                    (
                        "watch_error",
                        f"Непредвиденная ошибка: {type(exc).__name__}: {exc}",
                    )
                )

        threading.Thread(target=work, name="wireveil-watch", daemon=True).start()

    def _stop(self) -> None:
        if self.running:
            self.one_click_mode = False
            self.auto_enabled_var.set(False)
            self.watch_enabled_var.set(False)
            self._cancel_background_timers()
            self.cancel_event.set()
            self.stop_button.configure(state="disabled")
            self.status_var.set("Останавливаю проверку…")

    def _selected_service_names(self) -> tuple[str, ...]:
        return tuple(
            service.name
            for service in local_checker.SERVICE_DEFINITIONS
            if self.service_vars[service.name].get()
        )

    def _qualified_results(self) -> tuple[healthcheck.ProbeResult, ...]:
        if self.report is None:
            return ()
        fast = self.report.fast_results(self._latency_limit())
        service_names = self._selected_service_names()
        if not service_names or not self.service_results:
            return fast
        return tuple(
            result
            for result in fast
            if all(
                (service_result := self.service_results.get(
                    (result.target.index, service_name)
                )) is not None
                and service_result.available
                for service_name in service_names
            )
        )

    @staticmethod
    def _services_label(service_names: tuple[str, ...]) -> str:
        if not service_names:
            return "Сайты не выбраны"
        if len(service_names) <= 2:
            return " + ".join(service_names)
        return f"Выбрано сайтов: {len(service_names)}"

    def _refresh_service_columns(self) -> None:
        selected = self._selected_service_names()
        displayed = (
            "number",
            "protocol",
            "endpoint",
            "name",
            "latency",
            "speed",
            "quality",
            *(SERVICE_COLUMN_BY_NAME[name] for name in selected),
            "passes",
        )
        self.table.configure(displaycolumns=displayed)
        self.service_menu_text_var.set(self._services_label(selected))
        self._schedule_table_fit()

    def _schedule_table_fit(self, _event: object | None = None) -> None:
        if self.table_resize_job is not None:
            try:
                self.after_cancel(self.table_resize_job)
            except tk.TclError:
                pass
        self.table_resize_job = self.after(50, self._fit_table_columns)

    def _fit_table_columns(self) -> None:
        self.table_resize_job = None
        displayed = tuple(str(column) for column in self.table["displaycolumns"])
        if not displayed or displayed == ("#all",):
            displayed = TABLE_COLUMNS
        available = max(1, self.table.winfo_width() - 4)
        if available < 100:
            self.table_resize_job = self.after(50, self._fit_table_columns)
            return
        desired = {
            column: self.table_column_widths[column] for column in displayed
        }
        minimums = {
            column: self.table_column_minimums[column] for column in displayed
        }
        desired_total = sum(desired.values())
        if available >= desired_total:
            fitted = dict(desired)
            extra = available - desired_total
            fitted["endpoint"] = fitted.get("endpoint", 0) + (extra * 2 // 5)
            fitted["name"] = fitted.get("name", 0) + (extra - extra * 2 // 5)
        else:
            fitted = dict(desired)
            reduction = desired_total - available
            capacities = {
                column: max(0, desired[column] - minimums[column])
                for column in displayed
            }
            capacity_total = sum(capacities.values())
            if capacity_total:
                for column in displayed:
                    share = round(reduction * capacities[column] / capacity_total)
                    fitted[column] = max(minimums[column], desired[column] - share)
        difference = available - sum(fitted.values())
        if difference > 0:
            primary = "name" if "name" in fitted else displayed[-1]
            fitted[primary] += difference
        elif difference < 0:
            remaining = -difference
            shrink_order = tuple(
                column
                for column in ("name", "endpoint", *reversed(displayed))
                if column in fitted
            )
            for column in dict.fromkeys(shrink_order):
                capacity = max(0, fitted[column] - minimums[column])
                amount = min(capacity, remaining)
                fitted[column] -= amount
                remaining -= amount
                if remaining == 0:
                    break
        for column, width in fitted.items():
            self.table.column(
                column,
                width=width,
                stretch=column in {"endpoint", "name"},
            )
        if sum(fitted.values()) <= available:
            self.table.xview_moveto(0.0)
            self.table_scroll_x.grid_remove()
        else:
            self.table_scroll_x.grid()

    def _clear_service_cells(self) -> None:
        service_positions = (
            TABLE_COLUMN_POSITIONS["quality"],
            *(
                TABLE_COLUMN_POSITIONS[column]
                for column in SERVICE_NAME_BY_COLUMN
            ),
        )
        for item in self.table.get_children(""):
            values = list(self.table.item(item, "values"))
            if len(values) != len(TABLE_COLUMNS):
                continue
            for position in service_positions:
                values[position] = "—"
            self.table.item(item, values=values)

    def _restore_base_tags(self) -> None:
        if self.report is None:
            return
        fast_ids = {
            result.target.index
            for result in self.report.fast_results(self._latency_limit())
        }
        active_ids = {result.target.index for result in self.report.active_results}
        for index, item in self.table_items.items():
            if index in fast_ids:
                tag = "fast"
            elif index in active_ids:
                tag = "active"
            else:
                tag = "dead"
            self.table.item(item, tags=(tag,))

    def _service_selection_changed(self) -> None:
        if self.running:
            return
        self.service_results.clear()
        self._clear_service_cells()
        self._restore_base_tags()
        selected = self._selected_service_names()
        if (
            self.sort_column in SERVICE_NAME_BY_COLUMN
            and self.sort_column not in {
                SERVICE_COLUMN_BY_NAME[name] for name in selected
            }
        ):
            self.sort_column = "quality"
            self.sort_descending = False
        self._refresh_service_columns()
        if self.report is not None:
            self._apply_sort()
        else:
            self._refresh_sort_headers()
        self.status_var.set(f"Проверка сайтов: {self._services_label(selected)}")
        if self.report is not None:
            has_fast = bool(self._qualified_results())
            self.service_button.configure(
                state="normal" if selected and has_fast else "disabled"
            )
            self._restore_result_buttons()
            self._save_last_results()

    def _start_service_test(self) -> None:
        if self.running or self.report is None:
            return
        targets = tuple(
            result.target
            for result in self.report.fast_results(self._latency_limit())
        )
        if not targets:
            messagebox.showinfo(APP_TITLE, "Нет зелёных серверов для проверки сайта.")
            return
        binary = find_sing_box()
        if binary is None:
            messagebox.showerror(APP_TITLE, "Не найден вложенный sing-box.")
            return
        service_names = self._selected_service_names()
        if not service_names:
            messagebox.showerror(APP_TITLE, "Выберите хотя бы один сайт из списка.")
            return
        try:
            timeout = max(5, min(60, int(self.timeout_var.get())))
            workers = max(1, min(16, int(self.workers_var.get())))
        except (ValueError, tk.TclError):
            timeout, workers = 15, 16

        self._cancel_background_timers()
        self.running = True
        self.activity = "service"
        self.cancel_event = threading.Event()
        self.service_results.clear()
        self._clear_service_cells()
        self.progress_var.set(0)
        self.status_var.set(
            "Проверяю подключение к сети…"
        )
        self._set_running_controls(True)
        for target in targets:
            for service_name in service_names:
                self._set_service_cell(target.index, service_name, "ожидание…")
            self._update_service_quality(target.index)
        self._log(
            f"Проверка сайтов {', '.join(service_names)}: "
            f"{len(targets)} зелёных серверов."
        )

        def work() -> None:
            try:
                network_status = network_check.check_device_online()
                self.events.put(("network_state", network_status))
                if not network_status.online:
                    raise network_check.NetworkUnavailableError(
                        network_check.OFFLINE_MESSAGE
                    )

                def progress(
                    done: int, total: int, result: local_checker.ServiceResult
                ) -> None:
                    self.events.put(("service_progress", done, total, result))

                results = local_checker.run_service_tests(
                    binary=binary,
                    targets=targets,
                    service_names=service_names,
                    workers=workers,
                    timeout=float(timeout),
                    progress_callback=progress,
                    cancel_event=self.cancel_event,
                )
                self.events.put(("service_done", service_names, results))
            except (
                network_check.NetworkUnavailableError,
                local_checker.LocalCheckError,
                healthcheck.HealthCheckError,
                OSError,
            ) as exc:
                self.events.put(("service_error", service_names, str(exc)))
            except Exception as exc:
                self.events.put(
                    (
                        "service_error",
                        service_names,
                        f"Непредвиденная ошибка: {type(exc).__name__}: {exc}",
                    )
                )

        threading.Thread(target=work, name="wireveil-service", daemon=True).start()

    def _start_speed_test(self) -> None:
        if self.running or self.report is None:
            return
        targets = tuple(result.target for result in self._qualified_results())
        if not targets:
            messagebox.showinfo(APP_TITLE, "Нет зелёных серверов для теста скорости.")
            return
        binary = find_sing_box()
        if binary is None:
            messagebox.showerror(APP_TITLE, "Не найден вложенный sing-box.")
            return
        try:
            timeout = max(10, min(60, int(self.timeout_var.get())))
            workers = max(1, min(8, int(self.workers_var.get())))
        except (ValueError, tk.TclError):
            timeout, workers = 15, 8

        self._cancel_background_timers()
        self.running = True
        self.activity = "speed"
        self.cancel_event = threading.Event()
        self.progress_var.set(0)
        self.status_var.set("Проверяю подключение к сети…")
        self._set_running_controls(True)
        for target in targets:
            self._set_speed_cell(target.index, "ожидание…")
        self._log(
            f"Тест скорости: {len(targets)} зелёных серверов, "
            "по 1 МБ загрузки на сервер."
        )

        def work() -> None:
            try:
                network_status = network_check.check_device_online()
                self.events.put(("network_state", network_status))
                if not network_status.online:
                    raise network_check.NetworkUnavailableError(
                        network_check.OFFLINE_MESSAGE
                    )

                def progress(
                    done: int, total: int, result: local_checker.SpeedResult
                ) -> None:
                    self.events.put(("speed_progress", done, total, result))

                results = local_checker.run_speed_tests(
                    binary=binary,
                    targets=targets,
                    download_bytes=1_000_000,
                    workers=workers,
                    timeout=float(timeout),
                    progress_callback=progress,
                    cancel_event=self.cancel_event,
                )
                self.events.put(("speed_done", results))
            except (
                network_check.NetworkUnavailableError,
                local_checker.LocalCheckError,
                healthcheck.HealthCheckError,
                OSError,
            ) as exc:
                self.events.put(("speed_error", str(exc)))
            except Exception as exc:
                self.events.put(
                    ("speed_error", f"Непредвиденная ошибка: {type(exc).__name__}: {exc}")
                )

        threading.Thread(target=work, name="wireveil-speed", daemon=True).start()

    @staticmethod
    def _format_speed(result: local_checker.SpeedResult | None) -> str:
        if result is None:
            return "—"
        if result.speed_mbps is not None:
            return f"{result.speed_mbps:.2f}"
        return "ошибка"

    def _set_speed_cell(self, index: int, value: str) -> None:
        item = self.table_items.get(index)
        if not item:
            return
        values = list(self.table.item(item, "values"))
        if len(values) >= 7:
            values[5] = value
            self.table.item(item, values=values)
            self._schedule_resort()

    def _update_speed_result(self, result: local_checker.SpeedResult) -> None:
        self.speed_results[result.target.index] = result
        self._set_speed_cell(result.target.index, self._format_speed(result))

    @staticmethod
    def _format_service(result: local_checker.ServiceResult | None) -> str:
        if result is None:
            return "—"
        latency = str(result.latency_ms) if result.latency_ms is not None else ""
        if result.available:
            if result.http_status is not None and result.http_status >= 400:
                delay = f" · {latency}" if latency else ""
                return f"✓ {result.http_status}{delay}"
            return f"✓ {latency}" if latency else "✓"
        if result.http_status is not None:
            return f"✕ {result.http_status}"
        return "✕"

    def _service_quality(self, index: int) -> tuple[int, int, int, int | None]:
        service_names = self._selected_service_names()
        results = [
            self.service_results.get((index, service_name))
            for service_name in service_names
        ]
        completed = sum(result is not None for result in results)
        passed = sum(
            result is not None and result.available for result in results
        )
        latencies = [
            result.latency_ms
            for result in results
            if result is not None and result.available and result.latency_ms is not None
        ]
        return passed, len(service_names), completed, max(latencies) if latencies else None

    def _update_service_quality(self, index: int) -> None:
        item = self.table_items.get(index)
        if not item:
            return
        passed, total, completed, _worst_latency = self._service_quality(index)
        if total == 0:
            tag = None
        elif completed < total:
            tag = "pending"
        else:
            if passed == total:
                tag = "fast"
            elif passed > 0:
                tag = "active"
            else:
                tag = "dead"
        values = list(self.table.item(item, "values"))
        if len(values) == len(TABLE_COLUMNS):
            self.table.item(item, values=values, tags=(tag,) if tag else ())
            self._schedule_resort()

    def _set_service_cell(self, index: int, service_name: str, value: str) -> None:
        item = self.table_items.get(index)
        if not item:
            return
        values = list(self.table.item(item, "values"))
        column = SERVICE_COLUMN_BY_NAME[service_name]
        position = TABLE_COLUMN_POSITIONS[column]
        if len(values) == len(TABLE_COLUMNS):
            values[position] = value
            self.table.item(item, values=values)
            self._schedule_resort()

    def _update_service_result(self, result: local_checker.ServiceResult) -> None:
        self.service_results[(result.target.index, result.service_name)] = result
        self._set_service_cell(
            result.target.index,
            result.service_name,
            self._format_service(result),
        )
        self._update_service_quality(result.target.index)

    def _restore_result_buttons(self) -> None:
        if self.report is None:
            return
        active = self.report.active_results
        fast = self.report.fast_results(self._latency_limit())
        qualified = self._qualified_results()
        self.active_button.configure(state="normal" if active else "disabled")
        qualified_state = "normal" if qualified else "disabled"
        self.fast_button.configure(state=qualified_state)
        self.copy_button.configure(state=qualified_state)
        self.speed_button.configure(state=qualified_state)
        self.service_button.configure(
            state="normal" if fast and self._selected_service_names() else "disabled"
        )

    def _finish_service_test(
        self,
        service_names: tuple[str, ...],
        results: tuple[local_checker.ServiceResult, ...],
    ) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(100)
        self._set_running_controls(False)
        for result in results:
            self._update_service_result(result)
        target_ids = {result.target.index for result in results}
        passed_all = sum(
            all(
                self.service_results.get((target_id, service_name), None) is not None
                and self.service_results[(target_id, service_name)].available
                for service_name in service_names
            )
            for target_id in target_ids
        )
        self.status_var.set("Проверка выбранных сайтов завершена")
        self.summary_var.set(
            f"Все {len(service_names)} сайтов доступны через "
            f"{passed_all} из {len(target_ids)} зелёных серверов"
        )
        details = ", ".join(
            f"{service_name} "
            f"{sum(result.available for result in results if result.service_name == service_name)}"
            f"/{len(target_ids)}"
            for service_name in service_names
        )
        self._log(f"Проверка сайтов завершена: {details}.")
        self.sort_column = "quality"
        self.sort_descending = False
        self._apply_sort()
        self._restore_result_buttons()
        self._save_last_results()
        if self.one_click_mode:
            self.one_click_mode = False
            self._copy_fast()
            self._schedule_background_checks()
            return
        self._schedule_background_checks()

    def _fail_service_test(self, service_names: tuple[str, ...], detail: str) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(0)
        self._set_running_controls(False)
        label = self._services_label(service_names)
        if "cancelled" in detail.lower():
            self.status_var.set("Проверка сайтов остановлена")
            self._log(f"Проверка сайтов ({label}) остановлена пользователем.")
        else:
            self.status_var.set("Ошибка проверки сайтов")
            self._log(f"Ошибка проверки сайтов ({label}): {detail}")
            if not self.closing:
                messagebox.showerror(APP_TITLE, detail)
        self.one_click_mode = False
        self._restore_result_buttons()
        if not self.closing:
            self._schedule_background_checks()

    def _finish_speed_test(
        self, results: tuple[local_checker.SpeedResult, ...]
    ) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(100)
        self._set_running_controls(False)
        for result in results:
            self._update_speed_result(result)
        measured = [result for result in results if result.speed_mbps is not None]
        self.status_var.set("Тест скорости завершён")
        if measured:
            fastest = max(result.speed_mbps or 0 for result in measured)
            self.summary_var.set(
                f"Скорость измерена: {len(measured)}/{len(results)}  |  "
                f"максимум {fastest:.2f} Мбит/с"
            )
        else:
            self.summary_var.set(f"Скорость не измерена ни для одного из {len(results)} серверов")
        self._log(f"Тест скорости завершён: успешно {len(measured)}/{len(results)}.")
        self.sort_column = "quality"
        self.sort_descending = False
        self._apply_sort()
        self._restore_result_buttons()
        self._save_last_results()
        if self.one_click_mode:
            self.after_idle(self._start_service_test)
            return
        self._schedule_background_checks()

    def _fail_speed_test(self, detail: str) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(0)
        self._set_running_controls(False)
        if "cancelled" in detail.lower():
            self.status_var.set("Тест скорости остановлен")
            self._log("Тест скорости остановлен пользователем.")
        else:
            self.status_var.set("Ошибка теста скорости")
            self._log(f"Ошибка теста скорости: {detail}")
            if not self.closing:
                messagebox.showerror(APP_TITLE, detail)
        self.one_click_mode = False
        self._restore_result_buttons()
        if not self.closing:
            self._schedule_background_checks()

    def _finish_watch_check(self, report: local_checker.CheckReport) -> None:
        self.running = False
        self.activity = None
        self.report = report
        self.progress_var.set(100)
        self._set_running_controls(False)
        self.sort_column = "quality"
        self.sort_descending = False
        self._populate_table(report)
        active = report.active_results
        fast = report.fast_results(self._latency_limit())
        self.status_var.set("Быстрый контроль доступности завершён")
        self.summary_var.set(
            f"На контроле {len(self.watched_uris)}  |  доступны сейчас {len(active)}  |  "
            f"быстрых {len(fast)}"
        )
        self._log(
            f"Контроль доступности завершён: доступны {len(active)}/"
            f"{len(report.candidates)}, быстрых {len(fast)}."
        )
        self._restore_result_buttons()
        self._save_last_results(mode="watch")
        self._schedule_watch_check()

    def _fail_watch_check(self, detail: str) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(0)
        self._set_running_controls(False)
        if "cancelled" in detail.lower():
            self.status_var.set("Контроль доступности остановлен")
            self._log("Контроль доступности остановлен пользователем.")
        else:
            self.status_var.set("Ошибка контроля доступности")
            self._log(f"Ошибка контроля доступности: {detail}")
        if not self.closing:
            self._schedule_watch_check()

    def _poll_events(self) -> None:
        self.poll_job = None
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "network_state":
                    self._apply_network_status(event[1])
                elif kind == "update_checked":
                    self._finish_update_check(event[1])
                elif kind == "update_progress":
                    self._show_update_progress(event[1], event[2], event[3])
                elif kind == "update_downloaded":
                    self._finish_update_download(event[1], event[2])
                elif kind == "update_error":
                    self._finish_update_error(event[1])
                elif kind == "imported":
                    self.imported = event[1]
                    self._show_pending(self.imported.lines, event[2])
                    self.status_var.set(f"Подготовлено ключей: {len(self.imported.lines)}")
                    self._log(
                        f"Импортировано: {len(self.imported.lines)}; "
                        f"дубликатов: {self.imported.duplicates}; отклонено: {self.imported.rejected}."
                    )
                elif kind == "progress":
                    done, total, result, rounds = event[1], event[2], event[3], event[4]
                    self.progress_var.set((done / total) * 100 if total else 0)
                    self.status_var.set(f"Проверено запросов: {done} / {total}")
                    self._update_live_result(result, rounds)
                elif kind == "done":
                    self._finish(event[1])
                    if self.closing:
                        self.destroy()
                        return
                elif kind == "error":
                    self._fail(event[1])
                    if self.closing:
                        self.destroy()
                        return
                elif kind == "watch_imported":
                    imported = event[1]
                    self._show_pending(imported.lines, 1)
                    self.status_var.set(
                        f"Контроль доступности: подготовлено {len(imported.lines)} серверов"
                    )
                elif kind == "watch_progress":
                    done, total, result = event[1], event[2], event[3]
                    self.progress_var.set((done / total) * 100 if total else 0)
                    self.status_var.set(f"Контроль доступности: {done} / {total}")
                    self._update_live_result(result, 1)
                elif kind == "watch_done":
                    self._finish_watch_check(event[1])
                    if self.closing:
                        self.destroy()
                        return
                elif kind == "watch_error":
                    self._fail_watch_check(event[1])
                    if self.closing:
                        self.destroy()
                        return
                elif kind == "speed_progress":
                    done, total, result = event[1], event[2], event[3]
                    self.progress_var.set((done / total) * 100 if total else 0)
                    self.status_var.set(f"Проверка скорости: {done} / {total}")
                    self._update_speed_result(result)
                elif kind == "speed_done":
                    self._finish_speed_test(event[1])
                    if self.closing:
                        self.destroy()
                        return
                elif kind == "speed_error":
                    self._fail_speed_test(event[1])
                    if self.closing:
                        self.destroy()
                        return
                elif kind == "service_progress":
                    done, total, result = event[1], event[2], event[3]
                    self.progress_var.set((done / total) * 100 if total else 0)
                    self.status_var.set(
                        f"Проверка сайтов: {done} / {total} · сейчас {result.service_name}"
                    )
                    self._update_service_result(result)
                elif kind == "service_done":
                    self._finish_service_test(event[1], event[2])
                    if self.closing:
                        self.destroy()
                        return
                elif kind == "service_error":
                    self._fail_service_test(event[1], event[2])
                    if self.closing:
                        self.destroy()
                        return
        except queue.Empty:
            pass
        if not self.closing:
            self.poll_job = self.after(100, self._poll_events)

    def _finish(self, report: local_checker.CheckReport) -> None:
        self.running = False
        self.activity = None
        self.report = report
        self.progress_var.set(100)
        self._set_running_controls(False)
        self.sort_column = "quality"
        self.sort_descending = False
        self._populate_table(report)
        fast = report.fast_results(self._latency_limit())
        active = report.active_results
        self.status_var.set("Проверка завершена")
        self.summary_var.set(
            f"Всего {len(report.candidates)}  |  доступны {len(active)}  |  "
            f"быстрых {len(fast)}  |  не поддержано {report.unsupported_count}"
        )
        self._log(
            f"Готово: доступны {len(active)}, быстрых до {self._latency_limit()} мс — {len(fast)}."
        )
        self._restore_result_buttons()
        self._save_last_results()
        if self.one_click_mode:
            if fast:
                self.after_idle(self._start_speed_test)
            else:
                self.one_click_mode = False
                self.status_var.set("Нет быстрых серверов для полного теста")
                self._schedule_background_checks()
            return
        self._schedule_background_checks()

    def _fail(self, detail: str) -> None:
        self.running = False
        self.activity = None
        self._set_running_controls(False)
        self.progress_var.set(0)
        if "cancelled" in detail.lower():
            self.status_var.set("Проверка остановлена")
            self.summary_var.set("Результат не сохранён")
            self._log("Проверка остановлена пользователем.")
        else:
            self.status_var.set("Ошибка")
            self.summary_var.set(detail)
            self._log(f"Ошибка: {detail}")
            if not self.closing:
                messagebox.showerror(APP_TITLE, detail)
        self.one_click_mode = False
        if not self.closing:
            self._schedule_background_checks()

    def _set_running_controls(self, running: bool) -> None:
        for button in self.update_buttons:
            button.configure(
                state="disabled" if running or self.update_busy else "normal"
            )
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.file_button.configure(state="disabled" if running else "normal")
        self.paste_button.configure(state="disabled" if running else "normal")
        self.clear_source_button.configure(state="disabled" if running else "normal")
        self.service_menu_button.configure(state="disabled" if running else "normal")
        self.magic_button.configure(state="disabled" if running else "normal")
        if running:
            self._hide_magic_button_label()
        self.watch_now_button.configure(
            state="disabled" if running or not self.watched_uris else "normal"
        )
        if running:
            self.active_button.configure(state="disabled")
            self.fast_button.configure(state="disabled")
            self.copy_button.configure(state="disabled")
            self.speed_button.configure(state="disabled")
            self.service_button.configure(state="disabled")

    def _clear_table(self) -> None:
        children = self.table.get_children()
        if children:
            self.table.delete(*children)
        self.table_items.clear()
        self.item_uris.clear()
        self.live_results.clear()
        self.copy_selected_button.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _log(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _update_live_result(self, result: healthcheck.ProbeResult, attempts: int) -> None:
        index = result.target.index
        state = self.live_results.setdefault(
            index, {"completed": 0, "successes": 0, "delays": [], "error": ""}
        )
        state["completed"] = int(state["completed"]) + 1
        if result.active and result.delay_ms is not None:
            state["successes"] = int(state["successes"]) + 1
            delays = state["delays"]
            if isinstance(delays, list):
                delays.append(result.delay_ms)
        elif result.error:
            state["error"] = result.error
        parsed = build.parse_uri(result.target.uri)
        endpoint = f"{parsed.server}:{parsed.port}"
        delays = state["delays"] if isinstance(state["delays"], list) else []
        if delays:
            delay = round(sum(delays) / len(delays))
            test = f"{delay} ms"
            tag = "fast" if delay <= self._latency_limit() else "active"
            name = display_name(result.target.uri)
        else:
            test = "timeout"
            tag = "dead"
            name = str(state["error"] or "Нет ответа")[:180]
        values = (
            index + 1,
            result.target.protocol,
            endpoint,
            name,
            test,
            "—",
            "—",
            *("—" for _service in local_checker.SERVICE_DEFINITIONS),
            f"{state['successes']}/{attempts}",
        )
        item = self.table_items.get(index)
        if item:
            self.table.item(item, values=values, tags=(tag,))
        else:
            item = self.table.insert("", "end", values=values, tags=(tag,))
            self.table_items[index] = item
            self.item_uris[item] = result.target.uri
        self._schedule_resort()

    def _show_pending(self, lines: tuple[str, ...], attempts: int) -> None:
        """Display every imported server before the first network result arrives."""
        for index, uri in enumerate(lines):
            try:
                parsed = build.parse_uri(uri)
            except build.ValidationError:
                continue
            values = (
                index + 1,
                parsed.protocol,
                f"{parsed.server}:{parsed.port}",
                display_name(uri),
                "ожидание…",
                "—",
                "—",
                *("—" for _service in local_checker.SERVICE_DEFINITIONS),
                f"0/{attempts}",
            )
            item = self.table.insert(
                "", "end", values=values, tags=("pending",)
            )
            self.table_items[index] = item
            self.item_uris[item] = uri
        self._schedule_resort()

    def _populate_table(self, report: local_checker.CheckReport) -> None:
        self._clear_table()
        fast_ids = {result.target.index for result in report.fast_results(self._latency_limit())}
        active_ids = {result.target.index for result in report.active_results}
        ordered = sorted(
            report.results,
            key=lambda result: (
                result.target.index not in active_ids,
                result.delay_ms if result.delay_ms is not None else sys.maxsize,
                result.target.index,
            ),
        )
        for result in ordered:
            parsed = build.parse_uri(result.target.uri)
            endpoint = f"{parsed.server}:{parsed.port}"
            if result.target.index in fast_ids:
                tag = "fast"
            elif result.target.index in active_ids:
                tag = "active"
            else:
                tag = "dead"
            detail = display_name(result.target.uri)
            if result.error and tag == "dead":
                detail = result.error[:180]
            item = self.table.insert(
                "",
                "end",
                values=(
                    result.target.index + 1,
                    result.target.protocol,
                    endpoint,
                    detail,
                    f"{result.delay_ms} ms" if result.delay_ms is not None else "timeout",
                    self._format_speed(self.speed_results.get(result.target.index)),
                    "—",
                    *(
                        self._format_service(
                            self.service_results.get(
                                (result.target.index, service.name)
                            )
                        )
                        for service in local_checker.SERVICE_DEFINITIONS
                    ),
                    f"{result.successes}/{result.attempts}",
                ),
                tags=(tag,),
            )
            self.table_items[result.target.index] = item
            self.item_uris[item] = result.target.uri
        if self.sort_column is not None:
            self._apply_sort()

    def _sort_table(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_descending = not self.sort_descending
        else:
            self.sort_column = column
            self.sort_descending = False
        self._apply_sort()

    def _schedule_resort(self) -> None:
        if self.sort_column is None or self.sort_job is not None:
            return
        self.sort_job = self.after(250, self._resort_current)

    def _resort_current(self) -> None:
        self.sort_job = None
        if self.sort_column is not None:
            self._apply_sort()

    @staticmethod
    def _column_sort_value(column: str, values: tuple[str, ...]) -> object | None:
        raw = str(values[TABLE_COLUMN_POSITIONS[column]]).strip()
        if column == "number":
            try:
                return int(raw)
            except ValueError:
                return None
        if column == "latency":
            match = re.match(r"^(\d+)\s*ms$", raw, re.IGNORECASE)
            return int(match.group(1)) if match else None
        if column == "passes":
            match = re.match(r"^(\d+)\s*/\s*(\d+)$", raw)
            if not match:
                return None
            passed, total = int(match.group(1)), int(match.group(2))
            return (passed / total if total else 0.0, passed, total)
        if column == "speed":
            match = re.match(
                r"^(\d+(?:[.,]\d+)?)(?:\s*Мбит/с)?$", raw, re.IGNORECASE
            )
            return float(match.group(1).replace(",", ".")) if match else None
        if column == "quality":
            match = re.match(r"^(?:★\s*)?(\d+)$", raw)
            return int(match.group(1)) if match else None
        if column in SERVICE_NAME_BY_COLUMN:
            match = re.search(r"(\d+)(?:\s*ms)?$", raw, re.IGNORECASE)
            if raw.startswith("✓") or raw.casefold().startswith(("доступен", "домен отвечает")):
                return (0, int(match.group(1)) if match else sys.maxsize)
            if raw.startswith("✕") or raw.upper().startswith("HTTP"):
                status = re.search(r"(\d+)", raw)
                if status is None:
                    return (2, sys.maxsize)
                return (1, int(status.group(1)) if status else sys.maxsize)
            if raw == "нет доступа":
                return (2, sys.maxsize)
            return None
        return raw.casefold()

    @staticmethod
    def _smart_sort_value(values: tuple[str, ...]) -> tuple[object, ...]:
        """Rank a server by reliability, sites, speed, and latency."""

        passes_raw = str(values[TABLE_COLUMN_POSITIONS["passes"]]).strip()
        passes_match = re.match(r"^(\d+)\s*/\s*(\d+)$", passes_raw)
        if passes_match:
            passed_checks = int(passes_match.group(1))
            total_checks = int(passes_match.group(2))
            reliability = passed_checks / total_checks if total_checks else 0.0
        else:
            passed_checks = 0
            reliability = 0.0

        tested_sites = 0
        available_sites = 0
        for service_column in SERVICE_NAME_BY_COLUMN:
            raw = str(values[TABLE_COLUMN_POSITIONS[service_column]]).strip()
            if raw.startswith("✓") or raw.casefold().startswith(
                ("доступен", "домен отвечает")
            ):
                tested_sites += 1
                available_sites += 1
            elif raw.startswith("✕") or raw.upper().startswith("HTTP") or raw == "нет доступа":
                tested_sites += 1
        site_ratio = available_sites / tested_sites if tested_sites else 0.0

        speed_value = WireVeilChecker._column_sort_value("speed", values)
        latency_value = WireVeilChecker._column_sort_value("latency", values)
        number_value = WireVeilChecker._column_sort_value("number", values)
        speed = float(speed_value) if speed_value is not None else 0.0
        latency = int(latency_value) if latency_value is not None else sys.maxsize
        number = int(number_value) if number_value is not None else sys.maxsize

        return (
            0 if passed_checks > 0 else 1,
            -reliability,
            0 if tested_sites else 1,
            -site_ratio,
            0 if speed_value is not None else 1,
            -speed,
            latency,
            number,
        )

    def _apply_sort(self) -> None:
        column = self.sort_column
        if column is None:
            return
        rows = [
            (
                item,
                tuple(str(value) for value in self.table.item(item, "values")),
            )
            for item in self.table.get_children("")
        ]
        ranked = sorted(rows, key=lambda entry: self._smart_sort_value(entry[1]))
        for rank, (item, values) in enumerate(ranked, start=1):
            updated = list(values)
            updated[TABLE_COLUMN_POSITIONS["quality"]] = (
                f"★ {rank}" if rank == 1 else str(rank)
            )
            self.table.item(item, values=updated)

        valid: list[tuple[object, str]] = []
        missing: list[str] = []
        for item in self.table.get_children(""):
            values = tuple(str(value) for value in self.table.item(item, "values"))
            value = (
                self._smart_sort_value(values)
                if column == "quality"
                else self._column_sort_value(column, values)
            )
            if value is None:
                missing.append(item)
            else:
                valid.append((value, item))
        valid.sort(key=lambda entry: entry[0], reverse=self.sort_descending)
        ordered = [item for _value, item in valid] + missing
        for position, item in enumerate(ordered):
            self.table.move(item, "", position)
        self._refresh_sort_headers()

    def _refresh_sort_headers(self) -> None:
        for name, label in self.column_headings.items():
            arrow = " ↕"
            if name == self.sort_column:
                arrow = " ▼" if self.sort_descending else " ▲"
            self.table.heading(name, text=label + arrow)

    def _latency_limit(self) -> int:
        try:
            return max(1, int(self.latency_var.get()))
        except (ValueError, tk.TclError):
            return 500

    def _save_results(self, results: tuple[healthcheck.ProbeResult, ...], default: str) -> None:
        name = filedialog.asksaveasfilename(
            title="Сохранить подписку",
            defaultextension=".txt",
            initialfile=default,
            filetypes=(("TXT-подписка", "*.txt"), ("Все файлы", "*.*")),
        )
        if not name:
            return
        try:
            local_checker.write_subscription(Path(name), results)
        except local_checker.LocalCheckError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.status_var.set(f"Сохранено: {name}")

    def _save_active(self) -> None:
        if self.report:
            self._save_results(self.report.active_results, "wireveil-active.txt")

    def _save_fast(self) -> None:
        if self.report:
            self._save_results(self._qualified_results(), "wireveil-good.txt")

    def _copy_fast(self) -> None:
        if not self.report:
            return
        results = self._qualified_results()
        value = "\n".join(result.target.uri for result in results)
        if value:
            value += "\n"
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update_idletasks()
        self.watched_uris = tuple(result.target.uri for result in results)
        if "watch_now_button" in self.__dict__:
            self.watch_now_button.configure(
                state="normal"
                if self.watched_uris and not self.__dict__.get("running", False)
                else "disabled"
            )
        self._queue_settings_save()
        self.status_var.set(f"Годных ключей скопировано в буфер: {len(results)}")
        self._log(
            f"В буфер обмена экспортировано годных ключей: {len(results)}; "
            "этот набор сохранён для быстрого контроля доступности."
        )
        if self.watch_enabled_var.get():
            self._schedule_watch_check()

    def _selection_changed(self, _event: object | None = None) -> None:
        state = "normal" if self.table.selection() else "disabled"
        self.copy_selected_button.configure(state=state)

    def _copy_selected_event(self, _event: object | None = None) -> str:
        self._copy_selected()
        return "break"

    def _copy_selected(self) -> None:
        selected = set(self.table.selection())
        uris: list[str] = []
        seen: set[str] = set()
        for item in self.table.get_children(""):
            if item not in selected:
                continue
            uri = self.item_uris.get(item)
            if uri and uri not in seen:
                seen.add(uri)
                uris.append(uri)
        if not uris:
            return
        self.clipboard_clear()
        self.clipboard_append("".join(f"{uri}\n" for uri in uris))
        self.update_idletasks()
        self.status_var.set(f"Выбранных ключей скопировано: {len(uris)}")
        self._log(f"В буфер обмена скопировано выбранных ключей: {len(uris)}.")

    @staticmethod
    def _format_countdown(seconds: float) -> str:
        remaining = max(0, int(seconds + 0.999))
        hours, tail = divmod(remaining, 3600)
        minutes, secs = divmod(tail, 60)
        if hours:
            return f"{hours}:{minutes:02}:{secs:02}"
        return f"{minutes:02}:{secs:02}"

    def _update_countdowns(self) -> None:
        self.countdown_job = None
        if self.closing:
            return
        now = time.monotonic()

        if not self.auto_enabled_var.get():
            auto_text = "○ выключен"
        elif self.running and self.one_click_mode:
            auto_text = "● полный цикл выполняется"
        elif self.auto_due_at is not None:
            auto_text = (
                "● следующий запуск через "
                f"{self._format_countdown(self.auto_due_at - now)}"
            )
        elif self.report is None:
            auto_text = "○ ждёт первого полного запуска"
        elif self.running:
            auto_text = "○ отсчёт начнётся после текущей проверки"
        else:
            # A restored report may outlive the Tk timer after an app restart.
            # Recreate it here instead of leaving the schedule in a stale state.
            self._schedule_auto_check()
            if self.auto_due_at is not None:
                auto_text = (
                    "● следующий запуск через "
                    f"{self._format_countdown(self.auto_due_at - now)}"
                )
            else:
                auto_text = "○ расписание не запущено"

        watched_count = len(self.watched_uris)
        if not self.watch_enabled_var.get():
            watch_text = "○ выключен"
        elif not watched_count:
            watch_text = "○ ждёт копирования годных серверов"
        elif self.running and self.activity == "watch":
            watch_text = f"● проверка выполняется · {watched_count} серверов"
        elif self.watch_due_at is not None:
            watch_text = (
                f"● через {self._format_countdown(self.watch_due_at - now)}"
                f" · {watched_count} серверов"
            )
        else:
            watch_text = f"○ ожидает запуска · {watched_count} серверов"

        self.auto_countdown_var.set(auto_text)
        self.watch_countdown_var.set(watch_text)
        self.countdown_job = self.after(1000, self._update_countdowns)

    def _toggle_auto(self) -> None:
        if not self.auto_enabled_var.get():
            self._cancel_auto_timer()
            self._log("Полный автоцикл выключен.")
            return
        try:
            interval = int(self.auto_interval_var.get())
        except (ValueError, tk.TclError):
            interval = 0
        if not 1 <= interval <= 1440:
            self.auto_enabled_var.set(False)
            messagebox.showerror(APP_TITLE, "Интервал автозапуска должен быть от 1 до 1440 минут.")
            return
        if self.running:
            self._log(f"Полный автоцикл включён: запуск через {interval} мин после текущего.")
        elif self.report is not None:
            self._schedule_auto_check()
        else:
            self._log("Полный автоцикл включён и начнёт отсчёт после первого запуска.")

    def _toggle_watch(self) -> None:
        if not self.watch_enabled_var.get():
            self._cancel_watch_timer()
            self._log("Контроль доступности выключен.")
            return
        try:
            interval = int(self.watch_interval_var.get())
        except (ValueError, tk.TclError):
            interval = 0
        if not 1 <= interval <= 1440:
            self.watch_enabled_var.set(False)
            messagebox.showerror(
                APP_TITLE,
                "Интервал контроля доступности должен быть от 1 до 1440 минут.",
            )
            return
        if not self.watched_uris:
            self._log(
                "Контроль доступности включён и начнётся после копирования годных серверов."
            )
            return
        if self.running:
            self._log(
                f"Контроль доступности включён: запуск через {interval} мин после текущей проверки."
            )
            return
        self._schedule_watch_check()

    def _schedule_background_checks(self) -> None:
        self._schedule_auto_check()
        self._schedule_watch_check()

    def _cancel_background_timers(self) -> None:
        self._cancel_auto_timer()
        self._cancel_watch_timer()

    def _schedule_auto_check(self) -> None:
        self._cancel_auto_timer()
        if not self.auto_enabled_var.get() or self.closing:
            return
        try:
            interval = int(self.auto_interval_var.get())
        except (ValueError, tk.TclError):
            self.auto_enabled_var.set(False)
            return
        if not 1 <= interval <= 1440:
            self.auto_enabled_var.set(False)
            return
        self.auto_job = self.after(interval * 60_000, self._run_auto_check)
        self.auto_due_at = time.monotonic() + interval * 60
        self._log(f"Следующий полный автозапуск через {interval} мин.")

    def _cancel_auto_timer(self) -> None:
        if self.auto_job is not None:
            try:
                self.after_cancel(self.auto_job)
            except tk.TclError:
                pass
            self.auto_job = None
        self.auto_due_at = None

    def _run_auto_check(self) -> None:
        self.auto_job = None
        self.auto_due_at = None
        if not self.auto_enabled_var.get() or self.closing:
            return
        if self.running:
            self._log("Полный автозапуск отложен: сейчас выполняется другая проверка.")
            self._schedule_auto_check()
            return
        self._log("Запуск полного автоматического цикла.")
        self._start_one_click()

    def _schedule_watch_check(self) -> None:
        self._cancel_watch_timer()
        if (
            not self.watch_enabled_var.get()
            or not self.watched_uris
            or self.closing
        ):
            return
        try:
            interval = int(self.watch_interval_var.get())
        except (ValueError, tk.TclError):
            self.watch_enabled_var.set(False)
            return
        if not 1 <= interval <= 1440:
            self.watch_enabled_var.set(False)
            return
        self.watch_job = self.after(interval * 60_000, self._run_watch_check)
        self.watch_due_at = time.monotonic() + interval * 60
        self._log(
            f"Следующий контроль {len(self.watched_uris)} скопированных серверов "
            f"через {interval} мин."
        )

    def _cancel_watch_timer(self) -> None:
        if self.watch_job is not None:
            try:
                self.after_cancel(self.watch_job)
            except tk.TclError:
                pass
            self.watch_job = None
        self.watch_due_at = None

    def _run_watch_check(self) -> None:
        self.watch_job = None
        self.watch_due_at = None
        if (
            not self.watch_enabled_var.get()
            or not self.watched_uris
            or self.closing
        ):
            return
        if self.running:
            self._log("Контроль доступности отложен: сейчас выполняется другая проверка.")
            self._schedule_watch_check()
            return
        self._start_watch_check()

    def _on_close(self) -> None:
        self.closing = True
        self._close_rkn_easter_egg()
        self.mihomo_tab.close()
        self._cancel_background_timers()
        for job_name in (
            "countdown_job",
            "timer_refresh_job",
            "network_job",
            "table_resize_job",
            "poll_job",
        ):
            job = getattr(self, job_name, None)
            if job is not None:
                try:
                    self.after_cancel(job)
                except tk.TclError:
                    pass
                setattr(self, job_name, None)
        if self.settings_save_job is not None:
            try:
                self.after_cancel(self.settings_save_job)
            except tk.TclError:
                pass
            self.settings_save_job = None
        self._save_settings()
        if self.running:
            self.cancel_event.set()
            self.withdraw()
            return
        self.destroy()


def main() -> int:
    app = WireVeilChecker()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
