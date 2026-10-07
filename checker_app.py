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


def resource_root() -> Path:
    bundled = getattr(sys, "_MEIPASS", None)
    return Path(bundled) if bundled else Path(__file__).resolve().parent


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
        self.geometry("1080x720")
        self.minsize(820, 600)
        self.option_add("*Font", ("Segoe UI", 10))

        self.events: queue.Queue[tuple] = queue.Queue()
        self.cancel_event = threading.Event()
        self.running = False
        self.activity: str | None = None
        self.closing = False
        self.report: local_checker.CheckReport | None = None
        self.imported: local_checker.ImportedSubscription | None = None
        self.table_items: dict[int, str] = {}
        self.item_uris: dict[str, str] = {}
        self.live_results: dict[int, dict[str, object]] = {}
        self.speed_results: dict[int, local_checker.SpeedResult] = {}
        self.service_results: dict[int, local_checker.ServiceResult] = {}
        self.service_result_name: str | None = None
        self.column_headings: dict[str, str] = {}
        self.sort_column: str | None = "latency"
        self.sort_descending = False
        self.sort_job: str | None = None
        self.auto_job: str | None = None

        self.rounds_var = tk.IntVar(value=2)
        self.timeout_var = tk.IntVar(value=8)
        self.workers_var = tk.IntVar(value=64)
        self.latency_var = tk.IntVar(value=500)
        self.auto_enabled_var = tk.BooleanVar(value=False)
        self.auto_interval_var = tk.IntVar(value=30)
        self.service_var = tk.StringVar(value=local_checker.DEFAULT_SERVICE_NAME)
        self.status_var = tk.StringVar(value="Вставьте ссылку подписки или её содержимое.")
        self.summary_var = tk.StringVar(value="Результатов пока нет")
        self.progress_var = tk.DoubleVar(value=0)

        self._configure_style()
        self._build_ui()
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
            "TCombobox",
            fieldbackground="#292929",
            background="#424242",
            foreground="#ffffff",
            arrowcolor="#ffffff",
            borderwidth=1,
            padding=(5, 3),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", "#292929")],
            foreground=[("readonly", "#ffffff")],
            selectbackground=[("readonly", "#292929")],
            selectforeground=[("readonly", "#ffffff")],
            arrowcolor=[("disabled", "#777777"), ("readonly", "#ffffff")],
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
        self.start_button = ttk.Button(toolbar, text="▶ Проверить", command=self._start)
        self.start_button.pack(side="left", padx=(8, 0))
        self.stop_button = ttk.Button(toolbar, text="■ Стоп", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=(4, 0))
        self.speed_button = ttk.Button(
            toolbar,
            text="⚡ Скорость зелёных",
            command=self._start_speed_test,
            state="disabled",
        )
        self.speed_button.pack(side="left", padx=(4, 0))
        self.active_button = ttk.Button(toolbar, text="Сохранить живые", command=self._save_active, state="disabled")
        self.active_button.pack(side="right")
        self.fast_button = ttk.Button(toolbar, text="Сохранить быстрые", command=self._save_fast, state="disabled")
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

        settings = ttk.Frame(outer)
        settings.pack(fill="x", pady=(0, 5))
        self._spin_setting(settings, "Прогонов", self.rounds_var, 1, 5, 0)
        self._spin_setting(settings, "Тайм-аут", self.timeout_var, 1, 60, 2)
        ttk.Label(settings, text="сек", style="Dim.TLabel").grid(row=0, column=4, padx=(0, 14))
        self._spin_setting(settings, "Потоков", self.workers_var, 1, 256, 5)
        self._spin_setting(settings, "Быстрые ≤", self.latency_var, 1, 10000, 7)
        ttk.Label(settings, text="мс", style="Dim.TLabel").grid(row=0, column=9)
        ttk.Checkbutton(
            settings,
            text="Автопроверка каждые",
            variable=self.auto_enabled_var,
            command=self._toggle_auto,
        ).grid(row=0, column=10, sticky="e", padx=(18, 6))
        self._numeric_stepper(settings, self.auto_interval_var, 1, 1440, 11, width=5)
        ttk.Label(settings, text="мин", style="Dim.TLabel").grid(row=0, column=12, padx=(4, 2))
        settings.columnconfigure(10, weight=1)

        ttk.Label(settings, text="Проверка сайта:").grid(
            row=1, column=0, sticky="w", pady=(6, 0), padx=(0, 6)
        )
        self.service_combo = ttk.Combobox(
            settings,
            textvariable=self.service_var,
            values=tuple(service.name for service in local_checker.SERVICE_DEFINITIONS),
            state="readonly",
            width=16,
        )
        self.service_combo.grid(row=1, column=1, columnspan=2, sticky="w", pady=(6, 0))
        self.service_combo.bind("<<ComboboxSelected>>", self._service_changed)
        self.service_button = ttk.Button(
            settings,
            text="Проверить доступ",
            command=self._start_service_test,
            state="disabled",
        )
        self.service_button.grid(row=1, column=3, columnspan=3, sticky="w", pady=(6, 0), padx=(8, 0))
        ttk.Label(
            settings,
            text="тест запускается только для зелёных серверов",
            style="Dim.TLabel",
        ).grid(row=1, column=6, columnspan=7, sticky="w", pady=(6, 0), padx=(8, 0))

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill="both", expand=True)
        columns = (
            "number",
            "protocol",
            "endpoint",
            "name",
            "latency",
            "speed",
            "service",
            "passes",
        )
        self.table = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "number": "#",
            "protocol": "Тип",
            "endpoint": "Адрес",
            "name": "Имя / ошибка",
            "latency": "Пинг",
            "speed": "Скорость",
            "service": self.service_var.get(),
            "passes": "Прогоны",
        }
        self.column_headings = headings
        widths = {
            "number": 45,
            "protocol": 100,
            "endpoint": 220,
            "name": 285,
            "latency": 90,
            "speed": 110,
            "service": 145,
            "passes": 80,
        }
        for column in columns:
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
        self.table.tag_configure("fast", foreground="#60d35f")
        self.table.tag_configure("active", foreground="#d8ce43")
        self.table.tag_configure("dead", foreground="#e26b6b")
        self.table.tag_configure("pending", foreground="#a0a0a0")
        table_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=table_scroll.set)
        self.table.bind("<<TreeviewSelect>>", self._selection_changed)
        self.table.bind("<Control-c>", self._copy_selected_event)
        self.table.pack(side="left", fill="both", expand=True)
        table_scroll.pack(side="right", fill="y")

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
    ) -> None:
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.grid(row=0, column=column, sticky="w", padx=(0, 18))
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
        self._cancel_auto_timer()
        self.running = True
        self.activity = "ping"
        self.report = None
        self.speed_results.clear()
        self.service_results.clear()
        self.service_result_name = None
        self.cancel_event = threading.Event()
        self.progress_var.set(0)
        self.summary_var.set("Подготовка конфигураций…")
        self.status_var.set("Читаю подписку…")
        self._clear_table()
        self._clear_log()
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

    def _stop(self) -> None:
        if self.running:
            self.auto_enabled_var.set(False)
            self._cancel_auto_timer()
            self.cancel_event.set()
            self.stop_button.configure(state="disabled")
            self.status_var.set("Останавливаю проверку…")

    def _service_changed(self, _event: object | None = None) -> None:
        if self.running:
            return
        self.service_results.clear()
        self.service_result_name = None
        self.column_headings["service"] = self.service_var.get()
        self._refresh_sort_headers()
        for index in tuple(self.table_items):
            self._set_service_cell(index, "—")
        self.status_var.set(f"Выбран сервис: {self.service_var.get()}")

    def _start_service_test(self) -> None:
        if self.running or self.report is None:
            return
        targets = tuple(result.target for result in self.report.fast_results(self._latency_limit()))
        if not targets:
            messagebox.showinfo(APP_TITLE, "Нет зелёных серверов для проверки сайта.")
            return
        binary = find_sing_box()
        if binary is None:
            messagebox.showerror(APP_TITLE, "Не найден вложенный sing-box.")
            return
        service_name = self.service_var.get()
        if service_name not in local_checker.SERVICE_DEFINITIONS_BY_NAME:
            messagebox.showerror(APP_TITLE, "Выберите сервис из списка.")
            return
        try:
            timeout = max(5, min(60, int(self.timeout_var.get())))
            workers = max(1, min(16, int(self.workers_var.get())))
        except (ValueError, tk.TclError):
            timeout, workers = 15, 16

        self._cancel_auto_timer()
        self.running = True
        self.activity = "service"
        self.cancel_event = threading.Event()
        self.service_results.clear()
        self.service_result_name = service_name
        self.progress_var.set(0)
        self.status_var.set(
            f"Подготовка проверки {service_name} для {len(targets)} зелёных серверов…"
        )
        self._set_running_controls(True)
        for target in targets:
            self._set_service_cell(target.index, "ожидание…")
        self._log(
            f"Проверка доступа к {service_name}: {len(targets)} зелёных серверов."
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
                    service_name=service_name,
                    workers=workers,
                    timeout=float(timeout),
                    progress_callback=progress,
                    cancel_event=self.cancel_event,
                )
                self.events.put(("service_done", service_name, results))
            except (local_checker.LocalCheckError, healthcheck.HealthCheckError, OSError) as exc:
                self.events.put(("service_error", service_name, str(exc)))
            except Exception as exc:
                self.events.put(
                    (
                        "service_error",
                        service_name,
                        f"Непредвиденная ошибка: {type(exc).__name__}: {exc}",
                    )
                )

        threading.Thread(target=work, name="wireveil-service", daemon=True).start()

    def _start_speed_test(self) -> None:
        if self.running or self.report is None:
            return
        targets = tuple(result.target for result in self.report.fast_results(self._latency_limit()))
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

        self._cancel_auto_timer()
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
            return f"доступен{delay}"
        if result.http_status is not None:
            return f"HTTP {result.http_status}{delay}"
        return "нет доступа"

    def _set_service_cell(self, index: int, value: str) -> None:
        item = self.table_items.get(index)
        if not item:
            return
        values = list(self.table.item(item, "values"))
        if len(values) >= 8:
            values[6] = value
            self.table.item(item, values=values)
            self._schedule_resort()

    def _update_service_result(self, result: local_checker.ServiceResult) -> None:
        self.service_results[result.target.index] = result
        self._set_service_cell(result.target.index, self._format_service(result))

    def _restore_result_buttons(self) -> None:
        if self.report is None:
            return
        active = self.report.active_results
        fast = self.report.fast_results(self._latency_limit())
        self.active_button.configure(state="normal" if active else "disabled")
        state = "normal" if fast else "disabled"
        self.fast_button.configure(state=state)
        self.copy_button.configure(state=state)
        self.speed_button.configure(state=state)
        self.service_button.configure(state=state)

    def _finish_service_test(
        self,
        service_name: str,
        results: tuple[local_checker.ServiceResult, ...],
    ) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(100)
        self._set_running_controls(False)
        for result in results:
            self._update_service_result(result)
        available = [result for result in results if result.available]
        self.status_var.set(f"Проверка {service_name} завершена")
        self.summary_var.set(
            f"{service_name}: доступен через {len(available)} из {len(results)} зелёных серверов"
        )
        self._log(
            f"Проверка {service_name} завершена: доступно {len(available)}/{len(results)}."
        )
        self._restore_result_buttons()
        self._schedule_auto_check()

    def _fail_service_test(self, service_name: str, detail: str) -> None:
        self.running = False
        self.activity = None
        self.progress_var.set(0)
        self._set_running_controls(False)
        if "cancelled" in detail.lower():
            self.status_var.set(f"Проверка {service_name} остановлена")
            self._log(f"Проверка {service_name} остановлена пользователем.")
        else:
            self.status_var.set(f"Ошибка проверки {service_name}")
            self._log(f"Ошибка проверки {service_name}: {detail}")
            if not self.closing:
                messagebox.showerror(APP_TITLE, detail)
        self._restore_result_buttons()
        if not self.closing and self.auto_enabled_var.get():
            self._schedule_auto_check()

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
        self._schedule_auto_check()

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
        self._restore_result_buttons()
        if not self.closing and self.auto_enabled_var.get():
            self._schedule_auto_check()

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
        self.active_button.configure(state="normal" if active else "disabled")
        state = "normal" if fast else "disabled"
        self.fast_button.configure(state=state)
        self.copy_button.configure(state=state)
        self.speed_button.configure(state=state)
        self.service_button.configure(state=state)
        self._schedule_auto_check()

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
        if not self.closing and self.auto_enabled_var.get():
            self._schedule_auto_check()

    def _set_running_controls(self, running: bool) -> None:
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.file_button.configure(state="disabled" if running else "normal")
        self.paste_button.configure(state="disabled" if running else "normal")
        self.service_combo.configure(state="disabled" if running else "readonly")
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
                    self._format_service(self.service_results.get(result.target.index)),
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
        positions = {
            "number": 0,
            "protocol": 1,
            "endpoint": 2,
            "name": 3,
            "latency": 4,
            "speed": 5,
            "service": 6,
            "passes": 7,
        }
        raw = str(values[positions[column]]).strip()
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
        if column == "service":
            match = re.search(r"(\d+)\s*ms$", raw, re.IGNORECASE)
            if raw.casefold().startswith("доступен"):
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
            self._save_results(self.report.fast_results(self._latency_limit()), "wireveil-good.txt")

    def _copy_fast(self) -> None:
        if not self.report:
            return
        results = self.report.fast_results(self._latency_limit())
        value = "\n".join(result.target.uri for result in results)
        if value:
            value += "\n"
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update_idletasks()
        self.status_var.set(f"Годных ключей скопировано в буфер: {len(results)}")
        self._log(f"В буфер обмена экспортировано годных ключей: {len(results)}.")

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
            self._log("Автопроверка выключена.")
            return
        try:
            interval = int(self.auto_interval_var.get())
        except (ValueError, tk.TclError):
            interval = 0
        if not 1 <= interval <= 1440:
            self.auto_enabled_var.set(False)
            messagebox.showerror(APP_TITLE, "Интервал автопроверки должен быть от 1 до 1440 минут.")
            return
        if self.running:
            self._log(f"Автопроверка включена: следующий запуск через {interval} мин после текущего.")
        elif self.report is not None:
            self._schedule_auto_check()
        else:
            self._log("Автопроверка включена и начнёт отсчёт после первого ручного запуска.")

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
        self._log(f"Следующая автоматическая проверка через {interval} мин.")

    def _cancel_auto_timer(self) -> None:
        if self.auto_job is not None:
            try:
                self.after_cancel(self.auto_job)
            except tk.TclError:
                pass
            self.auto_job = None

    def _run_auto_check(self) -> None:
        self.auto_job = None
        if self.auto_enabled_var.get() and not self.running and not self.closing:
            self._log("Запуск автоматической проверки.")
            self._start()

    def _on_close(self) -> None:
        self._cancel_auto_timer()
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
