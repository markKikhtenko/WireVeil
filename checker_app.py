#!/usr/bin/env python3
"""WireVeil portable Windows subscription checker."""

from __future__ import annotations

import base64
import json
import queue
import re
import sys
import threading
import urllib.parse
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scripts import build, healthcheck, local_checker


APP_TITLE = "WireVeil Checker"
CONFIG_FILENAME = "WireVeilChecker.config.json"
CONFIG_VERSION = 2
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


def application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def checker_settings_path() -> Path:
    return application_root() / CONFIG_FILENAME


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
        self.geometry("1080x720")
        self.minsize(820, 600)
        self.option_add("*Font", ("Segoe UI", 10))

        self.settings_path = checker_settings_path()
        saved_settings = load_checker_settings(self.settings_path)
        restore_advanced = bool(saved_settings["advanced_visible"])
        restore_subscription = str(saved_settings["subscription"])
        self.settings_save_job: str | None = None
        self.settings_save_error_reported = False

        self.events: queue.Queue[tuple] = queue.Queue()
        self.cancel_event = threading.Event()
        self.running = False
        self.activity: str | None = None
        self.one_click_mode = False
        self.advanced_visible = False
        self.closing = False
        self.report: local_checker.CheckReport | None = None
        self.imported: local_checker.ImportedSubscription | None = None
        self.table_items: dict[int, str] = {}
        self.item_uris: dict[str, str] = {}
        self.live_results: dict[int, dict[str, object]] = {}
        self.speed_results: dict[int, local_checker.SpeedResult] = {}
        self.service_results: dict[tuple[int, str], local_checker.ServiceResult] = {}
        self.column_headings: dict[str, str] = {}
        self.sort_column: str | None = "latency"
        self.sort_descending = False
        self.sort_job: str | None = None
        self.auto_job: str | None = None
        self.watch_job: str | None = None
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
        self.progress_var = tk.DoubleVar(value=0)

        self._configure_style()
        self._build_ui()
        if restore_subscription:
            self.source.insert("1.0", restore_subscription)
            self.status_var.set("Сохранённая подписка загружена из конфига.")
        if restore_advanced:
            self._toggle_advanced_settings(persist=False)
        self._watch_settings()
        self._log(f"Настройки: {self.settings_path}")
        if self.auto_enabled_var.get():
            self._log("Автозаебись сохранён и продолжит работу после полного запуска.")
        if self.watch_enabled_var.get():
            if self.watched_uris:
                self._log(
                    f"Контроль живости восстановлен: {len(self.watched_uris)} "
                    "скопированных серверов."
                )
                self.after_idle(self._schedule_watch_check)
            else:
                self._log("Контроль живости ждёт первого копирования годных серверов.")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        self.configure(background="#202020")
        style.configure(".", background="#2b2b2b", foreground="#f0f0f0")
        style.configure("TFrame", background="#202020")
        style.configure("Panel.TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#202020", foreground="#ededed")
        style.configure("Dim.TLabel", background="#202020", foreground="#a8a8a8")
        style.configure("Brand.TLabel", background="#303030", foreground="#ffffff", font=("Segoe UI Semibold", 11))
        style.configure("Summary.TLabel", background="#202020", foreground="#d8d8d8")
        style.configure("TButton", background="#363636", foreground="#f4f4f4", padding=(9, 5), borderwidth=1)
        style.map("TButton", background=[("active", "#444444"), ("pressed", "#1f78a8")])
        style.configure(
            "Launch.TButton",
            background="#b52b2b",
            foreground="#ffffff",
            font=("Segoe UI Semibold", 10),
            padding=(10, 5),
            borderwidth=1,
            relief="raised",
            focuscolor="#e26060",
        )
        style.map(
            "Launch.TButton",
            background=[("active", "#cf3838"), ("pressed", "#8d2020")],
            foreground=[("disabled", "#a0a0a0"), ("!disabled", "#ffffff")],
            relief=[("pressed", "sunken"), ("!pressed", "raised")],
        )
        style.configure("Hero.TFrame", background="#272222")
        style.configure(
            "Stepper.TEntry",
            fieldbackground="#292929",
            foreground="#ffffff",
            insertcolor="#ffffff",
            borderwidth=1,
            padding=(5, 3),
        )
        style.configure(
            "Stepper.TButton",
            background="#424242",
            foreground="#ffffff",
            font=("Segoe UI Semibold", 10),
            padding=(4, 1),
        )
        style.map("Stepper.TButton", background=[("active", "#575757"), ("pressed", "#278dcc")])
        style.configure("TCheckbutton", background="#202020", foreground="#ededed")
        style.map("TCheckbutton", background=[("active", "#202020")])
        style.configure(
            "Service.TMenubutton",
            background="#424242",
            foreground="#ffffff",
            arrowcolor="#ffffff",
            borderwidth=1,
            padding=(5, 3),
        )
        style.map(
            "Service.TMenubutton",
            background=[("active", "#575757"), ("pressed", "#278dcc")],
            foreground=[("disabled", "#888888"), ("!disabled", "#ffffff")],
            arrowcolor=[("disabled", "#777777"), ("!disabled", "#ffffff")],
        )
        style.configure("Horizontal.TProgressbar", background="#2d9cdb", troughcolor="#303030", borderwidth=0)
        style.configure(
            "Treeview",
            background="#242424",
            fieldbackground="#242424",
            foreground="#f0f0f0",
            rowheight=25,
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", "#278dcc")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background="#333333", foreground="#f4f4f4", relief="flat")
        style.map("Treeview.Heading", background=[("active", "#414141")])

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=8)
        outer.pack(fill="both", expand=True)

        toolbar = ttk.Frame(outer, style="Panel.TFrame", padding=5)
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text=" WireVeil ", style="Brand.TLabel").pack(side="left", padx=(0, 6))
        self.paste_button = ttk.Button(toolbar, text="Вставить", command=self._paste)
        self.paste_button.pack(side="left")
        self.file_button = ttk.Button(toolbar, text="Файл…", command=self._choose_file)
        self.file_button.pack(side="left", padx=(4, 0))
        self.active_button = ttk.Button(toolbar, text="Сохранить живые", command=self._save_active, state="disabled")
        self.active_button.pack(side="right")
        self.fast_button = ttk.Button(toolbar, text="Сохранить годные", command=self._save_fast, state="disabled")
        self.fast_button.pack(side="right", padx=(0, 4))
        self.copy_button = ttk.Button(
            toolbar, text="В буфер годные", command=self._copy_fast, state="disabled"
        )
        self.copy_button.pack(side="right", padx=(0, 4))
        self.copy_selected_button = ttk.Button(
            toolbar,
            text="Копировать выбранные",
            command=self._copy_selected,
            state="disabled",
        )
        self.copy_selected_button.pack(side="right", padx=(0, 4))

        source_row = ttk.Frame(outer, padding=(0, 6, 0, 4))
        source_row.pack(fill="x")
        ttk.Label(source_row, text="Подписка:").pack(side="left", padx=(2, 6))
        self.clear_source_button = ttk.Button(
            source_row,
            text="Очистить",
            command=self._clear_source,
        )
        self.clear_source_button.pack(side="right", padx=(5, 0))
        self.source = tk.Text(
            source_row,
            height=2,
            wrap="word",
            undo=True,
            background="#292929",
            foreground="#f2f2f2",
            insertbackground="#ffffff",
            selectbackground="#278dcc",
            relief="flat",
            padx=7,
            pady=5,
        )
        self.source.pack(side="left", fill="x", expand=True)
        self.source.bind("<Control-KeyPress>", self._source_keyboard_shortcut)
        self.source.bind("<Control-Insert>", self._source_copy_event)
        self.source.bind("<Shift-Insert>", self._source_paste_event)

        hero = ttk.Frame(outer, style="Hero.TFrame", padding=(7, 5))
        hero.pack(fill="x", pady=(0, 4))
        hero.columnconfigure(0, weight=1)
        hero.columnconfigure(3, weight=1)
        self.magic_button = ttk.Button(
            hero,
            text="☢  Сделать заебись",
            command=self._start_one_click,
            style="Launch.TButton",
        )
        self.magic_button.grid(row=0, column=1, padx=8)
        self.stop_button = ttk.Button(
            hero,
            text="■ Аварийный стоп",
            command=self._stop,
            state="disabled",
        )
        self.stop_button.grid(row=0, column=2, padx=(8, 0))

        quick = ttk.Frame(outer)
        quick.pack(fill="x", pady=(0, 4))
        ttk.Checkbutton(
            quick,
            text="Автозаебись каждые",
            variable=self.auto_enabled_var,
            command=self._toggle_auto,
        ).grid(row=0, column=0, sticky="w", padx=(2, 4))
        self._numeric_stepper(quick, self.auto_interval_var, 1, 1440, 1, width=5)
        ttk.Label(quick, text="мин", style="Dim.TLabel").grid(row=0, column=2, padx=(0, 8))
        quick.columnconfigure(3, weight=1)
        ttk.Checkbutton(
            quick,
            text="Контроль скопированных зелёных каждые",
            variable=self.watch_enabled_var,
            command=self._toggle_watch,
        ).grid(row=1, column=0, sticky="w", padx=(2, 4), pady=(3, 0))
        self._numeric_stepper(
            quick,
            self.watch_interval_var,
            1,
            1440,
            1,
            width=5,
            row=1,
        )
        ttk.Label(quick, text="мин · только живость", style="Dim.TLabel").grid(
            row=1, column=2, columnspan=2, sticky="w", padx=(0, 8), pady=(3, 0)
        )
        self.advanced_toggle_button = ttk.Button(
            quick,
            text="⚙ Дополнительные настройки…",
            command=self._toggle_advanced_settings,
        )
        self.advanced_toggle_button.grid(row=0, column=4, rowspan=2, sticky="e")

        self.advanced_host = ttk.Frame(outer)
        self.advanced_host.pack(fill="x")
        self.advanced_frame = ttk.Frame(
            self.advanced_host, style="Panel.TFrame", padding=6
        )
        manual = ttk.Frame(self.advanced_frame, style="Panel.TFrame")
        manual.pack(fill="x")
        self.start_button = ttk.Button(manual, text="▶ Только ping", command=self._start)
        self.start_button.pack(side="left")
        self.speed_button = ttk.Button(
            manual,
            text="⚡ Скорость годных",
            command=self._start_speed_test,
            state="disabled",
        )
        self.speed_button.pack(side="left", padx=(4, 0))
        self.service_button = ttk.Button(
            manual,
            text="Проверить выбранные сайты",
            command=self._start_service_test,
            state="disabled",
        )
        self.service_button.pack(side="left", padx=(4, 0))

        settings = ttk.Frame(self.advanced_frame, style="Panel.TFrame")
        settings.pack(fill="x", pady=(6, 0))
        self._spin_setting(settings, "Прогонов", self.rounds_var, 1, 5, 0)
        self._spin_setting(settings, "Тайм-аут", self.timeout_var, 1, 60, 2)
        ttk.Label(settings, text="сек", style="Dim.TLabel").grid(row=0, column=4, padx=(0, 14))
        self._spin_setting(settings, "Потоков", self.workers_var, 1, 256, 5)
        self._spin_setting(settings, "Быстрые ≤", self.latency_var, 1, 10000, 7)
        ttk.Label(settings, text="мс", style="Dim.TLabel").grid(row=0, column=9)

        services = ttk.Frame(self.advanced_frame, style="Panel.TFrame")
        services.pack(fill="x", pady=(6, 0))
        ttk.Label(services, text="Проверка сайтов:", style="Brand.TLabel").pack(
            side="left", padx=(0, 6)
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
            background="#292929",
            foreground="#ffffff",
            activebackground="#278dcc",
            activeforeground="#ffffff",
            selectcolor="#60d35f",
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
            text="можно выбрать несколько; тестируются только зелёные серверы",
            style="Dim.TLabel",
        ).pack(side="left", padx=(8, 0))

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(
            table_frame, columns=TABLE_COLUMNS, show="headings", selectmode="extended"
        )
        headings = {
            "number": "#",
            "protocol": "Тип",
            "endpoint": "Адрес",
            "name": "Имя / ошибка",
            "latency": "Пинг",
            "speed": "Скорость",
            "quality": "Итог сайтов",
            "passes": "Прогоны",
        }
        headings.update(
            {
                SERVICE_COLUMN_BY_NAME[service.name]: service.name
                for service in local_checker.SERVICE_DEFINITIONS
            }
        )
        self.column_headings = headings
        widths = {
            "number": 42,
            "protocol": 80,
            "endpoint": 190,
            "name": 230,
            "latency": 80,
            "speed": 100,
            "quality": 110,
            "passes": 70,
        }
        widths.update({column: 125 for column in SERVICE_NAME_BY_COLUMN})
        for column in TABLE_COLUMNS:
            self.table.heading(
                column,
                text=headings[column],
                command=lambda selected=column: self._sort_table(selected),
            )
            self.table.column(
                column,
                width=widths[column],
                minwidth=35,
                stretch=column in {"endpoint", "name"},
            )
        self._refresh_sort_headers()
        self._refresh_service_columns()
        self.table.tag_configure("fast", foreground="#60d35f")
        self.table.tag_configure("active", foreground="#d8ce43")
        self.table.tag_configure("dead", foreground="#e26b6b")
        self.table.tag_configure("pending", foreground="#a0a0a0")
        table_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        table_scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(
            yscrollcommand=table_scroll.set,
            xscrollcommand=table_scroll_x.set,
        )
        self.table.bind("<<TreeviewSelect>>", self._selection_changed)
        self.table.bind("<Control-c>", self._copy_selected_event)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.table.grid(row=0, column=0, sticky="nsew")
        table_scroll.grid(row=0, column=1, sticky="ns")
        table_scroll_x.grid(row=1, column=0, sticky="ew")

        log_frame = ttk.Frame(outer)
        log_frame.pack(fill="x", pady=(5, 0))
        ttk.Label(log_frame, text="Журнал", style="Dim.TLabel").pack(anchor="w")
        self.log = tk.Text(
            log_frame,
            height=4,
            background="#191919",
            foreground="#cfcfcf",
            insertbackground="#ffffff",
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
        ttk.Label(statusbar, textvariable=self.summary_var, style="Summary.TLabel").pack(side="right")

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
        self.source.bind("<<Modified>>", self._source_settings_changed, add=True)
        self.source.edit_modified(False)

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

    def _toggle_advanced_settings(self, *, persist: bool = True) -> None:
        if self.advanced_visible:
            self.advanced_frame.pack_forget()
            self.advanced_visible = False
            self.advanced_toggle_button.configure(
                text="⚙ Дополнительные настройки…"
            )
        else:
            self.advanced_frame.pack(fill="x", pady=(0, 5))
            self.advanced_visible = True
            self.advanced_toggle_button.configure(text="Скрыть настройки ▲")
        if persist:
            self._queue_settings_save()

    def _spin_setting(
        self, parent: ttk.Frame, label: str, variable: tk.IntVar, start: int, end: int, column: int
    ) -> None:
        ttk.Label(parent, text=label).grid(row=0, column=column, sticky="w", padx=(0, 6))
        self._numeric_stepper(parent, variable, start, end, column + 1)

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
    ) -> None:
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.grid(row=row, column=column, sticky="w", padx=(0, 18))
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
        self.status_var.set("Читаю подписку…")
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
            except (local_checker.LocalCheckError, healthcheck.HealthCheckError, build.BuildError, OSError) as exc:
                self.events.put(("error", str(exc)))
            except Exception as exc:  # Keep a windowed build diagnosable.
                self.events.put(("error", f"Непредвиденная ошибка: {type(exc).__name__}: {exc}"))

        threading.Thread(target=work, name="wireveil-check", daemon=True).start()

    def _start_watch_check(self) -> None:
        if self.running:
            return
        watched = self.watched_uris
        if not watched:
            self._log("Контроль живости: пока нет скопированных годных серверов.")
            return
        binary = find_sing_box()
        if binary is None:
            self._log("Контроль живости: не найден вложенный sing-box.")
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
        self.status_var.set(
            f"Быстрый контроль живости: {len(watched)} скопированных серверов…"
        )
        self.summary_var.set("Один HTTPS-прогон без скорости и проверки сайтов")
        self._clear_table()
        self._set_running_controls(True)
        self._log(
            f"Контроль живости: один прогон для {len(watched)} "
            "скопированных зелёных серверов."
        )

        def work() -> None:
            try:
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
        if self.sort_column == "quality" or (
            self.sort_column in SERVICE_NAME_BY_COLUMN
            and self.sort_column not in {
                SERVICE_COLUMN_BY_NAME[name] for name in selected
            }
        ):
            self.sort_column = "latency"
            self.sort_descending = False
        self._refresh_service_columns()
        self._refresh_sort_headers()
        self.status_var.set(f"Проверка сайтов: {self._services_label(selected)}")
        if self.report is not None:
            has_fast = bool(self._qualified_results())
            self.service_button.configure(
                state="normal" if selected and has_fast else "disabled"
            )
            self._restore_result_buttons()

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
            f"Подготовка проверки {len(service_names)} сайтов для "
            f"{len(targets)} зелёных серверов…"
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
            except (local_checker.LocalCheckError, healthcheck.HealthCheckError, OSError) as exc:
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
        self.status_var.set(f"Подготовка теста скорости для {len(targets)} зелёных серверов…")
        self._set_running_controls(True)
        for target in targets:
            self._set_speed_cell(target.index, "ожидание…")
        self._log(
            f"Тест скорости: {len(targets)} зелёных серверов, "
            "по 1 МБ загрузки на сервер."
        )

        def work() -> None:
            try:
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
            except (local_checker.LocalCheckError, healthcheck.HealthCheckError, OSError) as exc:
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
            return f"{result.speed_mbps:.2f} Мбит/с"
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
        delay = f" · {result.latency_ms} ms" if result.latency_ms is not None else ""
        if result.available:
            if result.http_status is not None and result.http_status >= 400:
                return f"домен отвечает · HTTP {result.http_status}{delay}"
            return f"доступен{delay}"
        if result.http_status is not None:
            return f"HTTP {result.http_status}{delay}"
        return "нет доступа"

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
        passed, total, completed, worst_latency = self._service_quality(index)
        if total == 0:
            text = "—"
            tag = None
        elif completed < total:
            text = f"{passed}/{total} · {completed} проверено"
            tag = "pending"
        else:
            text = f"{passed}/{total}"
            if worst_latency is not None:
                text += f" · {worst_latency} ms"
            if passed == total:
                tag = "fast"
            elif passed > 0:
                tag = "active"
            else:
                tag = "dead"
        values = list(self.table.item(item, "values"))
        if len(values) == len(TABLE_COLUMNS):
            values[TABLE_COLUMN_POSITIONS["quality"]] = text
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
        self._restore_result_buttons()
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
        self.sort_column = "latency"
        self.sort_descending = False
        self._populate_table(report)
        active = report.active_results
        fast = report.fast_results(self._latency_limit())
        self.status_var.set("Быстрый контроль живости завершён")
        self.summary_var.set(
            f"Скопировано {len(self.watched_uris)}  |  живых сейчас {len(active)}  |  "
            f"быстрых {len(fast)}"
        )
        self._log(
            f"Контроль живости завершён: живых {len(active)}/"
            f"{len(report.candidates)}, быстрых {len(fast)}."
        )
        self._restore_result_buttons()
        self._schedule_watch_check()

    def _fail_watch_check(self, detail: str) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(0)
        self._set_running_controls(False)
        if "cancelled" in detail.lower():
            self.status_var.set("Контроль живости остановлен")
            self._log("Контроль живости остановлен пользователем.")
        else:
            self.status_var.set("Ошибка контроля живости")
            self._log(f"Ошибка контроля живости: {detail}")
        if not self.closing:
            self._schedule_watch_check()

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "imported":
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
                        f"Контроль живости: подготовлено {len(imported.lines)} серверов"
                    )
                elif kind == "watch_progress":
                    done, total, result = event[1], event[2], event[3]
                    self.progress_var.set((done / total) * 100 if total else 0)
                    self.status_var.set(f"Контроль живости: {done} / {total}")
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
                        f"Проверка {result.service_name}: {done} / {total}"
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
        self.after(100, self._poll_events)

    def _finish(self, report: local_checker.CheckReport) -> None:
        self.running = False
        self.activity = None
        self.report = report
        self.progress_var.set(100)
        self._set_running_controls(False)
        self._populate_table(report)
        fast = report.fast_results(self._latency_limit())
        active = report.active_results
        self.status_var.set("Проверка завершена")
        self.summary_var.set(
            f"Всего {len(report.candidates)}  |  живых {len(active)}  |  "
            f"быстрых {len(fast)}  |  не поддержано {report.unsupported_count}"
        )
        self._log(
            f"Готово: живых {len(active)}, быстрых до {self._latency_limit()} мс — {len(fast)}."
        )
        self._restore_result_buttons()
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
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.file_button.configure(state="disabled" if running else "normal")
        self.paste_button.configure(state="disabled" if running else "normal")
        self.clear_source_button.configure(state="disabled" if running else "normal")
        self.service_menu_button.configure(state="disabled" if running else "normal")
        self.magic_button.configure(state="disabled" if running else "normal")
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
            match = re.match(r"^(\d+(?:[.,]\d+)?)\s*Мбит/с$", raw, re.IGNORECASE)
            return float(match.group(1).replace(",", ".")) if match else None
        if column == "quality":
            match = re.match(
                r"^(\d+)\s*/\s*(\d+)(?:\s*·\s*(\d+)\s*ms)?$",
                raw,
                re.IGNORECASE,
            )
            if not match:
                return None
            passed, total = int(match.group(1)), int(match.group(2))
            latency = int(match.group(3)) if match.group(3) else sys.maxsize
            return (-(passed / total if total else 0.0), latency)
        if column in SERVICE_NAME_BY_COLUMN:
            match = re.search(r"(\d+)\s*ms$", raw, re.IGNORECASE)
            if raw.casefold().startswith(("доступен", "домен отвечает")):
                return (0, int(match.group(1)) if match else sys.maxsize)
            if raw.upper().startswith("HTTP"):
                status = re.match(r"^HTTP\s+(\d+)", raw, re.IGNORECASE)
                return (1, int(status.group(1)) if status else sys.maxsize)
            if raw == "нет доступа":
                return (2, sys.maxsize)
            return None
        return raw.casefold()

    def _apply_sort(self) -> None:
        column = self.sort_column
        if column is None:
            return
        valid: list[tuple[object, str]] = []
        missing: list[str] = []
        for item in self.table.get_children(""):
            values = tuple(str(value) for value in self.table.item(item, "values"))
            value = self._column_sort_value(column, values)
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
        self._queue_settings_save()
        self.status_var.set(f"Годных ключей скопировано в буфер: {len(results)}")
        self._log(
            f"В буфер обмена экспортировано годных ключей: {len(results)}; "
            "этот набор сохранён для быстрого контроля живости."
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

    def _toggle_auto(self) -> None:
        if not self.auto_enabled_var.get():
            self._cancel_auto_timer()
            self._log("Автозаебись выключен.")
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
            self._log(f"Автозаебись включён: полный цикл через {interval} мин после текущего.")
        elif self.report is not None:
            self._schedule_auto_check()
        else:
            self._log("Автозаебись включён и начнёт отсчёт после первого полного запуска.")

    def _toggle_watch(self) -> None:
        if not self.watch_enabled_var.get():
            self._cancel_watch_timer()
            self._log("Контроль скопированных зелёных выключен.")
            return
        try:
            interval = int(self.watch_interval_var.get())
        except (ValueError, tk.TclError):
            interval = 0
        if not 1 <= interval <= 1440:
            self.watch_enabled_var.set(False)
            messagebox.showerror(
                APP_TITLE,
                "Интервал контроля живости должен быть от 1 до 1440 минут.",
            )
            return
        if not self.watched_uris:
            self._log(
                "Контроль живости включён и начнётся после копирования годных серверов."
            )
            return
        if self.running:
            self._log(
                f"Контроль живости включён: запуск через {interval} мин после текущей проверки."
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
        self._log(f"Следующий полный автозапуск через {interval} мин.")

    def _cancel_auto_timer(self) -> None:
        if self.auto_job is not None:
            try:
                self.after_cancel(self.auto_job)
            except tk.TclError:
                pass
            self.auto_job = None

    def _run_auto_check(self) -> None:
        self.auto_job = None
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

    def _run_watch_check(self) -> None:
        self.watch_job = None
        if (
            not self.watch_enabled_var.get()
            or not self.watched_uris
            or self.closing
        ):
            return
        if self.running:
            self._log("Контроль живости отложен: сейчас выполняется другая проверка.")
            self._schedule_watch_check()
            return
        self._start_watch_check()

    def _on_close(self) -> None:
        self._cancel_background_timers()
        if self.settings_save_job is not None:
            try:
                self.after_cancel(self.settings_save_job)
            except tk.TclError:
                pass
            self.settings_save_job = None
        self._save_settings()
        if self.running:
            self.closing = True
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
