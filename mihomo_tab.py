"""Tkinter tab for batch Mihomo/OpenClash diagnostics."""

from __future__ import annotations

import json
import queue
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from scripts import mihomo_checker
from wireveil_paths import user_data_file


SOURCES_FILENAME = "WireVeilChecker.mihomo-sources.json"
UI_SETTINGS_FILENAME = "WireVeilChecker.mihomo-ui.json"


def load_ui_settings(path: Path) -> dict[str, object]:
    defaults: dict[str, object] = {
        "font_size": 11,
        "workers": mihomo_checker.BASE_WORKERS_DEFAULT,
        "sample_mode": "Репрезентативно: 500",
        "sampling_seed": "wireveil-default",
        "base_policy": "Строго 2/2",
        "table_mode": "Обзор",
    }
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return defaults
    if not isinstance(raw, dict):
        return defaults
    font_size = raw.get("font_size")
    workers = raw.get("workers")
    sample_mode = raw.get("sample_mode")
    base_policy = raw.get("base_policy")
    table_mode = raw.get("table_mode")
    return {
        "font_size": font_size if isinstance(font_size, int) and 10 <= font_size <= 15 else 11,
        "workers": workers if workers in mihomo_checker.BASE_WORKERS_ALLOWED else mihomo_checker.BASE_WORKERS_DEFAULT,
        "sample_mode": sample_mode if sample_mode in {
            "Репрезентативно: 50", "Репрезентативно: 100", "Репрезентативно: 500",
            "20 на источник", "100 на источник", "Все узлы",
        } else "Репрезентативно: 500",
        "sampling_seed": mihomo_checker.sanitize_text(raw.get("sampling_seed", "wireveil-default"), 80) or "wireveil-default",
        "base_policy": base_policy if base_policy in {"Строго 2/2", "Достаточно 1/2"} else "Строго 2/2",
        "table_mode": table_mode if table_mode in {"Обзор", "Подробно"} else "Обзор",
    }


def save_ui_settings(path: Path, settings: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def find_mihomo() -> Path | None:
    roots = [
        Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)),
        Path(sys.executable).resolve().parent,
        Path(__file__).resolve().parent,
    ]
    for root in roots:
        for name in ("mihomo.exe", "mihomo"):
            candidate = root / name
            if candidate.is_file():
                return candidate
    development = Path(__file__).resolve().parent / ".wireveil-mihomo-1.19.33"
    if development.is_dir():
        matches = sorted(development.rglob("mihomo.exe"))
        if matches:
            return matches[0]
    return None


class _MultilineDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        prompt: str,
        *,
        multiline: bool = True,
    ):
        super().__init__(parent)
        self.result: str | None = None
        self.multiline = multiline
        self.title(title)
        self.geometry("720x430" if multiline else "720x210")
        self.minsize(520, 320 if multiline else 190)
        self.transient(parent.winfo_toplevel())
        self.configure(background="#0f151c")
        ttk.Label(self, text=prompt, wraplength=680, justify="left").pack(
            fill="x", padx=12, pady=(12, 6)
        )
        self.text = tk.Text(
            self,
            wrap="none",
            undo=True,
            background="#101821",
            foreground="#eaf2f7",
            insertbackground="#ffffff",
            selectbackground="#166f9c",
            relief="flat",
            padx=9,
            pady=7,
        )
        self.text.pack(fill="both", expand=True, padx=12)
        self.text.bind("<Control-KeyPress>", self._keyboard_shortcut)
        self.text.bind("<Control-Insert>", self._copy_event)
        self.text.bind("<Shift-Insert>", self._paste_event)
        self.text.bind("<Button-3>", self._show_context_menu)
        if not multiline:
            self.text.bind("<Return>", self._accept_event)

        self.context_menu = tk.Menu(
            self,
            tearoff=False,
            background="#202a35",
            foreground="#ffffff",
            activebackground="#166f9c",
            activeforeground="#ffffff",
        )
        self.context_menu.add_command(label="Вставить", command=self._paste_clipboard)
        self.context_menu.add_command(label="Копировать", command=self._copy_selection)
        self.context_menu.add_command(label="Вырезать", command=self._cut_selection)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Выделить всё", command=self._select_all)

        controls = ttk.Frame(self)
        controls.pack(fill="x", padx=12, pady=12)
        ttk.Button(
            controls,
            text="Вставить из буфера",
            command=self._paste_clipboard,
        ).pack(side="left")
        ttk.Button(controls, text="Отмена", command=self.destroy).pack(side="right")
        ttk.Button(controls, text="Добавить", command=self._accept, style="Accent.TButton").pack(
            side="right", padx=(0, 6)
        )
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.bind("<Escape>", lambda _event: self.destroy())
        self.after_idle(self.text.focus_set)
        self.grab_set()

    @staticmethod
    def _shortcut_action(event: object) -> str | None:
        """Map physical Windows keys and Tk keysyms in EN/RU layouts."""
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

    def _copy_selection(self) -> bool:
        selection = self.text.tag_ranges("sel")
        if not selection:
            return False
        self.clipboard_clear()
        self.clipboard_append(self.text.get(selection[0], selection[1]))
        self.update_idletasks()
        return True

    def _paste_clipboard(self) -> None:
        try:
            value = self.clipboard_get()
        except tk.TclError:
            return
        selection = self.text.tag_ranges("sel")
        if selection:
            self.text.delete(selection[0], selection[1])
        if not self.multiline:
            value = " ".join(value.splitlines())
        self.text.insert("insert", value)
        self.text.see("insert")

    def _cut_selection(self) -> None:
        selection = self.text.tag_ranges("sel")
        if selection and self._copy_selection():
            self.text.delete(selection[0], selection[1])

    def _select_all(self) -> None:
        self.text.tag_add("sel", "1.0", "end-1c")
        self.text.mark_set("insert", "end-1c")
        self.text.see("insert")

    def _keyboard_shortcut(self, event: object) -> str | None:
        action = self._shortcut_action(event)
        if action == "copy":
            self._copy_selection()
        elif action == "paste":
            self._paste_clipboard()
        elif action == "cut":
            self._cut_selection()
        elif action == "select_all":
            self._select_all()
        else:
            return None
        return "break"

    def _copy_event(self, _event: object | None = None) -> str:
        self._copy_selection()
        return "break"

    def _paste_event(self, _event: object | None = None) -> str:
        self._paste_clipboard()
        return "break"

    def _show_context_menu(self, event: object) -> str:
        self.text.focus_set()
        try:
            self.text.mark_set("insert", f"@{event.x},{event.y}")
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
        return "break"

    def _accept_event(self, _event: object | None = None) -> str:
        self._accept()
        return "break"

    def _accept(self) -> None:
        value = self.text.get("1.0", "end-1c")
        if not value.strip():
            return
        self.result = value
        self.destroy()


class MihomoCheckerTab(ttk.Frame):
    """UI controller kept independent from the legacy sing-box tab."""

    SOURCE_COLUMNS = (
        "name", "status", "size", "protocols", "total", "good", "partial", "failed",
        "unsupported", "not_tested", "error", "checked"
    )
    NODE_COLUMNS = (
        "source", "name", "protocol", "status", "base", "endpoint", "latency",
        *(service.key for service in mihomo_checker.SERVICE_DEFINITIONS),
        "error",
    )
    OVERVIEW_COLUMNS = (
        "source", "name", "protocol", "status", "base", "chatgpt", "instagram", "spotify", "error"
    )

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, padding=10)
        self.sources_path = user_data_file(SOURCES_FILENAME)
        self.ui_settings_path = user_data_file(UI_SETTINGS_FILENAME)
        saved_ui = load_ui_settings(self.ui_settings_path)
        self.sources = mihomo_checker.load_source_specs(self.sources_path)
        self.events: queue.Queue[tuple[object, ...]] = queue.Queue()
        self.runner: mihomo_checker.BatchRunner | None = None
        self.report: mihomo_checker.BatchReport | None = None
        self.parsed_by_id: dict[str, mihomo_checker.ParsedSource] = {}
        self.live_results: dict[str, mihomo_checker.NodeResult] = {}
        self.pending_node_results: dict[str, mihomo_checker.NodeResult] = {}
        self.active_progress: mihomo_checker.ProgressUpdate | None = None
        self.active_progress_received_at = 0.0
        self.node_sort_column: str | None = None
        self.node_sort_descending = False
        self.source_sort_column: str | None = None
        self.source_sort_descending = False
        self.running = False
        self.stop_requested = False
        self.closing = False
        self.execution_log_entries: list[tuple[str, bool, str]] = []

        self.attempts_var = tk.IntVar(value=2)
        self.timeout_var = tk.IntVar(value=8)
        self.workers_var = tk.IntVar(value=int(saved_ui["workers"]))
        self.node_limit_var = tk.StringVar(value=str(saved_ui["sample_mode"]))
        self.sampling_seed_var = tk.StringVar(value=str(saved_ui["sampling_seed"]))
        self.base_policy_var = tk.StringVar(value=str(saved_ui["base_policy"]))
        self.table_mode_var = tk.StringVar(value=str(saved_ui["table_mode"]))
        self.font_size = int(saved_ui["font_size"])
        self.service_vars = {
            item.name: tk.BooleanVar(value=item.name in mihomo_checker.DEFAULT_SERVICES)
            for item in mihomo_checker.SERVICE_DEFINITIONS
        }
        self.status_var = tk.StringVar(value="Добавьте один или несколько Mihomo/Clash YAML источников.")
        self.summary_var = tk.StringVar(value="Свежих результатов нет")
        self.progress_var = tk.DoubleVar(value=0)
        self.source_filter_var = tk.StringVar(value="Все источники")
        self.status_filter_var = tk.StringVar(value="Все статусы")
        self.service_filter_var = tk.StringVar(value="Все сервисы")
        self.log_stage_filter_var = tk.StringVar(value="Все этапы")
        self.log_error_only_var = tk.BooleanVar(value=False)
        self.state_var = tk.StringVar(value="Нет новых результатов")
        self.kpi_vars = {
            key: tk.StringVar(value=value)
            for key, value in {
                "sources": "Источники 0 / ошибки 0",
                "nodes": "Узлы 0",
                "https": "HTTPS 0",
                "statuses": "G 0 · P 0 · F 0 · U 0 · — 0",
                "checked": "Проверено 0/0",
                "rate": "Скорость —",
                "eta": "ETA —",
            }.items()
        }

        self._configure_styles()
        self._build_ui()
        self._refresh_source_tree()
        self.poll_job: str | None = self.after(100, self._poll_events)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        size = self.font_size
        style.configure("Mihomo.TFrame", background="#0d1117")
        style.configure("Mihomo.Panel.TFrame", background="#161b22", borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid")
        style.configure("Mihomo.TLabelframe", background="#161b22", bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid")
        style.configure("Mihomo.TLabelframe.Label", background="#0d1117", foreground="#c9d1d9", font=("Segoe UI Semibold", size))
        style.configure("Mihomo.TLabel", background="#0d1117", foreground="#f0f6fc", font=("Segoe UI", size))
        style.configure("Mihomo.Panel.TLabel", background="#161b22", foreground="#f0f6fc", font=("Segoe UI", size))
        style.configure("Mihomo.Dim.TLabel", background="#0d1117", foreground="#8b949e", font=("Segoe UI", max(9, size - 1)))
        style.configure("Mihomo.Kpi.TLabel", background="#161b22", foreground="#c9d1d9", font=("Segoe UI Semibold", size), padding=(7, 5))
        style.configure("Mihomo.State.TLabel", background="#1f6feb", foreground="#ffffff", font=("Segoe UI Semibold", size), padding=(8, 4))
        style.configure("Mihomo.TButton", font=("Segoe UI", size), padding=(9, 6), background="#21262d", foreground="#f0f6fc", borderwidth=1, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid")
        style.map("Mihomo.TButton", background=[("active", "#30363d"), ("pressed", "#1f6feb"), ("disabled", "#161b22")], foreground=[("disabled", "#6e7681")], bordercolor=[("active", "#8b949e"), ("disabled", "#21262d")])
        style.configure("Mihomo.Accent.TButton", font=("Segoe UI Semibold", size), padding=(11, 7), background="#238636", foreground="#ffffff", borderwidth=1, bordercolor="#2ea043", lightcolor="#2ea043", darkcolor="#2ea043", relief="solid")
        style.map("Mihomo.Accent.TButton", background=[("active", "#2ea043"), ("pressed", "#196c2e"), ("disabled", "#1b4725")], foreground=[("disabled", "#7d8590")])
        style.configure("Mihomo.TCheckbutton", background="#161b22", foreground="#f0f6fc", font=("Segoe UI", size))
        style.map("Mihomo.TCheckbutton", background=[("active", "#161b22")], foreground=[("disabled", "#6e7681")])
        style.configure("Mihomo.TCombobox", font=("Segoe UI", size), fieldbackground="#0d1117", background="#21262d", foreground="#f0f6fc", arrowcolor="#c9d1d9", selectbackground="#1f6feb", selectforeground="#ffffff", bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", padding=4)
        style.map("Mihomo.TCombobox", fieldbackground=[("readonly", "#0d1117")], foreground=[("readonly", "#f0f6fc")], selectbackground=[("readonly", "#0d1117")], selectforeground=[("readonly", "#f0f6fc")])
        style.configure("Mihomo.TSpinbox", font=("Segoe UI", size), fieldbackground="#0d1117", background="#21262d", foreground="#f0f6fc", arrowcolor="#c9d1d9", insertcolor="#f0f6fc", bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", arrowsize=max(14, size + 4), padding=4)
        style.configure("Mihomo.TEntry", font=("Segoe UI", size), fieldbackground="#0d1117", foreground="#f0f6fc", insertcolor="#f0f6fc", bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", padding=4)
        style.configure("Mihomo.Treeview", font=("Segoe UI", size), rowheight=size + 16, background="#0d1117", fieldbackground="#0d1117", foreground="#c9d1d9", borderwidth=0)
        style.configure("Mihomo.Treeview.Heading", font=("Segoe UI Semibold", max(9, size - 1)), padding=(6, 7), background="#161b22", foreground="#c9d1d9", relief="flat")
        style.map("Mihomo.Treeview", background=[("selected", "#1f6feb")], foreground=[("selected", "#ffffff")])
        style.map("Mihomo.Treeview.Heading", background=[("active", "#21262d")])
        style.configure("Mihomo.TNotebook", background="#0d1117", borderwidth=0, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d")
        style.configure("Mihomo.TNotebook.Tab", font=("Segoe UI Semibold", size), padding=(14, 7), background="#0d1117", foreground="#8b949e", borderwidth=0, bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d")
        style.map("Mihomo.TNotebook.Tab", background=[("selected", "#21262d"), ("active", "#161b22")], foreground=[("selected", "#f0f6fc"), ("active", "#c9d1d9")])

    def _build_ui(self) -> None:
        self.configure(style="Mihomo.TFrame")
        header = ttk.Frame(self, style="Mihomo.TFrame")
        header.pack(fill="x", pady=(0, 6))
        header.columnconfigure(0, weight=1)
        self.header_frame = header
        title = ttk.Frame(header, style="Mihomo.TFrame")
        title.grid(row=0, column=0, sticky="w")
        self.header_title = title
        ttk.Label(title, text="Mihomo / OpenClash", style="Mihomo.TLabel", font=("Segoe UI Semibold", self.font_size + 3)).pack(anchor="w")
        ttk.Label(title, text="Массовый аудит реального HTTPS-трафика через отдельный локальный Mihomo", style="Mihomo.Dim.TLabel").pack(anchor="w")
        text_controls = ttk.Frame(header, style="Mihomo.TFrame")
        text_controls.grid(row=0, column=1, padx=(8, 6))
        self.text_controls = text_controls
        ttk.Label(text_controls, text="Текст", style="Mihomo.Dim.TLabel").pack(side="left")
        ttk.Button(text_controls, text="−", width=3, command=lambda: self._change_font(-1), style="Mihomo.TButton").pack(side="left", padx=3)
        ttk.Button(text_controls, text="+", width=3, command=lambda: self._change_font(1), style="Mihomo.TButton").pack(side="left")
        exports = ttk.Frame(header, style="Mihomo.TFrame")
        exports.grid(row=1, column=0, columnspan=2, sticky="e", pady=(4, 0))
        self.exports_frame = exports
        self.export_report_button = ttk.Button(exports, text="Диагностический ZIP…", command=self._export_report, state="disabled", style="Mihomo.Accent.TButton")
        self.export_report_button.pack(side="left", padx=3)
        self.export_yaml_button = ttk.Button(exports, text="Рабочие YAML…", command=self._export_private, state="disabled", style="Mihomo.TButton")
        self.export_yaml_button.pack(side="left", padx=3)
        self.export_sources_button = ttk.Button(exports, text="YAML по источникам…", command=self._export_private_by_source, state="disabled", style="Mihomo.TButton")
        self.export_sources_button.pack(side="left", padx=3)

        controls = ttk.Frame(self, style="Mihomo.TFrame")
        controls.pack(fill="x", pady=(0, 6))
        controls.columnconfigure(0, weight=1)
        self.controls_frame = controls
        source_panel = ttk.LabelFrame(controls, text="Источники", padding=(8, 6), style="Mihomo.TLabelframe")
        source_panel.grid(row=0, column=0, sticky="nsew", pady=(0, 3))
        self.source_panel = source_panel
        for index, (text, command) in enumerate((
            ("Добавить URL", self._add_url), ("URL списком", self._add_urls),
            ("Файлы / каталог…", self._add_files), ("Вставить YAML", self._add_text),
            ("Переименовать", self._rename_selected), ("Удалить", self._delete_selected),
            ("Очистить", self._clear_sources),
        )):
            ttk.Button(source_panel, text=text, command=command, style="Mihomo.TButton").grid(
                row=index // 4, column=index % 4, sticky="ew", padx=2, pady=2
            )
        for column in range(4):
            source_panel.columnconfigure(column, weight=1)

        check_panel = ttk.LabelFrame(controls, text="Настройки проверки", padding=(8, 6), style="Mihomo.TLabelframe")
        check_panel.grid(row=1, column=0, sticky="nsew", pady=(3, 0))
        self.check_panel = check_panel
        labels = (("Прогоны", 0), ("Тайм-аут", 2), ("HTTPS потоков", 4))
        for text, column in labels:
            ttk.Label(check_panel, text=text, style="Mihomo.Panel.TLabel").grid(row=0, column=column, sticky="w", padx=(2, 3))
        ttk.Spinbox(check_panel, from_=2, to=5, width=4, textvariable=self.attempts_var, style="Mihomo.TSpinbox").grid(row=0, column=1, sticky="w")
        ttk.Spinbox(check_panel, from_=1, to=60, width=4, textvariable=self.timeout_var, style="Mihomo.TSpinbox").grid(row=0, column=3, sticky="w")
        self.worker_combo = ttk.Combobox(check_panel, width=5, textvariable=self.workers_var, values=mihomo_checker.BASE_WORKERS_ALLOWED, state="readonly", style="Mihomo.TCombobox")
        self.worker_combo.grid(row=0, column=5, sticky="w")
        ttk.Label(check_panel, text="Выборка", style="Mihomo.Panel.TLabel").grid(row=1, column=0, sticky="w", padx=(2, 3), pady=(4, 0))
        self.node_limit = ttk.Combobox(
            check_panel, textvariable=self.node_limit_var, state="readonly", width=23,
            values=("Репрезентативно: 50", "Репрезентативно: 100", "Репрезентативно: 500", "20 на источник", "100 на источник", "Все узлы"),
            style="Mihomo.TCombobox",
        )
        self.node_limit.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(4, 0))
        self.base_policy = ttk.Combobox(check_panel, textvariable=self.base_policy_var, state="readonly", width=16, values=("Строго 2/2", "Достаточно 1/2"), style="Mihomo.TCombobox")
        self.base_policy.grid(row=1, column=4, columnspan=2, sticky="ew", padx=(6, 0), pady=(4, 0))
        services_menu = tk.Menu(self, tearoff=False)
        for service in mihomo_checker.SERVICE_DEFINITIONS:
            services_menu.add_checkbutton(label=service.name, variable=self.service_vars[service.name])
        services_button = ttk.Menubutton(check_panel, text="Выбрать сервисы", menu=services_menu, style="Mihomo.TButton")
        services_button.grid(row=2, column=0, columnspan=2, sticky="ew", padx=2, pady=(4, 0))
        self.start_all_button = ttk.Button(check_panel, text="▶ Проверить все", command=self._start_all, style="Mihomo.Accent.TButton")
        self.start_all_button.grid(row=2, column=2, sticky="ew", padx=2, pady=(4, 0))
        self.start_selected_button = ttk.Button(check_panel, text="Проверить выбранные", command=self._start_selected, style="Mihomo.TButton")
        self.start_selected_button.grid(row=2, column=3, columnspan=2, sticky="ew", padx=2, pady=(4, 0))
        self.stop_button = ttk.Button(check_panel, text="■ Стоп", command=self.stop, state="disabled", style="Mihomo.TButton")
        self.stop_button.grid(row=2, column=5, sticky="ew", padx=2, pady=(4, 0))
        ttk.Label(check_panel, text="Seed выборки", style="Mihomo.Panel.TLabel").grid(row=3, column=0, sticky="w", padx=2, pady=(4, 0))
        ttk.Entry(check_panel, textvariable=self.sampling_seed_var, style="Mihomo.TEntry").grid(row=3, column=1, columnspan=3, sticky="ew", padx=2, pady=(4, 0))
        ttk.Label(check_panel, text="Сервисы ≤ 8 потоков", style="Mihomo.Dim.TLabel").grid(row=3, column=4, columnspan=2, sticky="e", padx=2, pady=(4, 0))
        for column in range(6):
            check_panel.columnconfigure(column, weight=1)

        kpi = ttk.Frame(self, style="Mihomo.Panel.TFrame", padding=(4, 3))
        kpi.pack(fill="x", pady=(0, 6))
        for column, key in enumerate(("sources", "nodes", "https", "statuses", "checked", "rate", "eta")):
            ttk.Label(kpi, textvariable=self.kpi_vars[key], style="Mihomo.Kpi.TLabel", anchor="center").grid(row=0, column=column, sticky="ew", padx=1)
            kpi.columnconfigure(column, weight=1)

        self.views = ttk.Notebook(self, style="Mihomo.TNotebook")
        self.views.pack(fill="both", expand=True)
        sources_page = ttk.Frame(self.views, style="Mihomo.TFrame")
        nodes_page = ttk.Frame(self.views, style="Mihomo.TFrame")
        log_page = ttk.Frame(self.views, style="Mihomo.TFrame")
        self.views.add(sources_page, text="Источники")
        self.views.add(nodes_page, text="Узлы — обзор")
        self.views.add(log_page, text="Журнал")
        self.log_page = log_page

        self.source_tree = ttk.Treeview(sources_page, columns=self.SOURCE_COLUMNS, show="headings", selectmode="extended", style="Mihomo.Treeview", height=4)
        source_headings = {
            "name": "Имя / provenance", "status": "Загрузка / разбор", "size": "Размер", "protocols": "Протоколы",
            "total": "Всего", "good": "Good", "partial": "Partial", "failed": "Failed", "unsupported": "Unsupported",
            "not_tested": "Not tested", "error": "Причина", "checked": "Проверено",
        }
        source_widths = {"name": 190, "status": 120, "size": 70, "protocols": 145, "total": 55, "good": 55, "partial": 60, "failed": 55, "unsupported": 80, "not_tested": 80, "error": 190, "checked": 130}
        for column in self.SOURCE_COLUMNS:
            self.source_tree.heading(column, text=source_headings[column], command=lambda selected=column: self._sort_source_tree(selected))
            self.source_tree.column(column, width=source_widths[column], minwidth=55, stretch=column in {"name", "protocols", "error"})
        self.source_tree.configure(displaycolumns=tuple(column for column in self.SOURCE_COLUMNS if column != "checked"))
        self.source_tree.bind("<Double-1>", lambda _event: self._show_source_details())
        source_y = ttk.Scrollbar(sources_page, orient="vertical", command=self.source_tree.yview)
        source_x = ttk.Scrollbar(sources_page, orient="horizontal", command=self.source_tree.xview)
        self.source_tree.configure(yscrollcommand=source_y.set, xscrollcommand=source_x.set)
        sources_page.columnconfigure(0, weight=1); sources_page.rowconfigure(0, weight=1)
        self.source_tree.grid(row=0, column=0, sticky="nsew"); source_y.grid(row=0, column=1, sticky="ns"); source_x.grid(row=1, column=0, sticky="ew")

        filters = ttk.Frame(nodes_page, style="Mihomo.Panel.TFrame", padding=(6, 4))
        filters.pack(fill="x")
        ttk.Label(filters, text="Источник", style="Mihomo.Panel.TLabel").grid(row=0, column=0, padx=(0, 3))
        self.source_filter = ttk.Combobox(filters, textvariable=self.source_filter_var, state="readonly", width=24, style="Mihomo.TCombobox")
        self.source_filter.grid(row=0, column=1, padx=(0, 5), sticky="ew")
        ttk.Label(filters, text="Статус", style="Mihomo.Panel.TLabel").grid(row=0, column=2, padx=(0, 3))
        self.status_filter = ttk.Combobox(filters, textvariable=self.status_filter_var, state="readonly", width=14, values=("Все статусы", "good", "partial", "failed", "unsupported", "not_tested"), style="Mihomo.TCombobox")
        self.status_filter.grid(row=0, column=3, padx=(0, 5))
        service_filter_values = ["Все сервисы"]
        for service in mihomo_checker.SERVICE_DEFINITIONS:
            service_filter_values.extend((f"{service.name}: доступен", f"{service.name}: ошибка"))
        self.service_filter = ttk.Combobox(filters, textvariable=self.service_filter_var, state="readonly", width=23, values=service_filter_values, style="Mihomo.TCombobox")
        self.service_filter.grid(row=0, column=4, padx=(0, 5))
        self.table_mode = ttk.Combobox(filters, textvariable=self.table_mode_var, state="readonly", width=10, values=("Обзор", "Подробно"), style="Mihomo.TCombobox")
        self.table_mode.grid(row=0, column=5, padx=(0, 5))
        self.column_menu = tk.Menu(self, tearoff=False)
        self.column_visibility = {column: tk.BooleanVar(value=column in self.OVERVIEW_COLUMNS) for column in self.NODE_COLUMNS}
        for column in self.NODE_COLUMNS:
            self.column_menu.add_checkbutton(label=column, variable=self.column_visibility[column], command=self._apply_visible_columns)
        ttk.Menubutton(filters, text="Столбцы", menu=self.column_menu, style="Mihomo.TButton").grid(row=0, column=6)
        filters.columnconfigure(1, weight=1)
        for widget in (self.source_filter, self.status_filter, self.service_filter):
            widget.bind("<<ComboboxSelected>>", lambda _event: self._refresh_node_tree())
        self.table_mode.bind("<<ComboboxSelected>>", self._table_mode_changed)

        node_frame = ttk.Frame(nodes_page, style="Mihomo.TFrame")
        node_frame.pack(fill="both", expand=True)
        self.node_tree = ttk.Treeview(node_frame, columns=self.NODE_COLUMNS, show="headings", selectmode="extended", style="Mihomo.Treeview", height=4)
        self.node_headings = {"source": "Источник", "name": "Имя", "protocol": "Протокол", "endpoint": "Endpoint", "status": "Статус", "base": "HTTPS", "latency": "мс", "error": "Причина"}
        self.node_headings.update({item.key: item.name for item in mihomo_checker.SERVICE_DEFINITIONS})
        widths = {"source": 190, "name": 190, "protocol": 80, "status": 100, "base": 85, "endpoint": 180, "latency": 70, "error": 250}
        for column in self.NODE_COLUMNS:
            self.node_tree.heading(column, text=self.node_headings[column], command=lambda selected=column: self._sort_node_tree(selected))
            self.node_tree.column(column, width=widths.get(column, 95), minwidth=55, stretch=column in {"source", "name", "error"})
        for tag, color in (("good", "#72df72"), ("partial", "#f2d86f"), ("failed", "#ff817a"), ("unsupported", "#b89bea"), ("not_tested", "#9baab6")):
            self.node_tree.tag_configure(tag, foreground=color)
        self.node_tree.bind("<Double-1>", self._show_node_details)
        node_y = ttk.Scrollbar(node_frame, orient="vertical", command=self.node_tree.yview)
        node_x = ttk.Scrollbar(node_frame, orient="horizontal", command=self.node_tree.xview)
        self.node_tree.configure(yscrollcommand=node_y.set, xscrollcommand=node_x.set)
        node_frame.columnconfigure(0, weight=1); node_frame.rowconfigure(0, weight=1)
        self.node_tree.grid(row=0, column=0, sticky="nsew"); node_y.grid(row=0, column=1, sticky="ns"); node_x.grid(row=1, column=0, sticky="ew")
        self._table_mode_changed()

        log_actions = ttk.Frame(log_page, style="Mihomo.Panel.TFrame", padding=(6, 4))
        log_actions.pack(fill="x")
        ttk.Label(log_actions, text="Этап", style="Mihomo.Panel.TLabel").pack(side="left")
        stage_values = ("Все этапы", *mihomo_checker.STAGE_LABELS.values())
        log_filter = ttk.Combobox(log_actions, textvariable=self.log_stage_filter_var, values=stage_values, state="readonly", width=24, style="Mihomo.TCombobox")
        log_filter.pack(side="left", padx=5)
        log_filter.bind("<<ComboboxSelected>>", lambda _event: self._render_execution_log())
        ttk.Checkbutton(log_actions, text="Только ошибки", variable=self.log_error_only_var, command=self._render_execution_log, style="Mihomo.TCheckbutton").pack(side="left", padx=5)
        ttk.Button(log_actions, text="Экспорт безопасного журнала…", command=self._export_execution_log, style="Mihomo.TButton").pack(side="right", padx=3)
        ttk.Button(log_actions, text="Копировать", command=self._copy_execution_log, style="Mihomo.TButton").pack(side="right", padx=3)
        log_frame = ttk.Frame(log_page, style="Mihomo.TFrame")
        log_frame.pack(fill="both", expand=True)
        self.execution_log = tk.Text(log_frame, wrap="word", state="disabled", height=4, background="#101821", foreground="#e7f0f5", insertbackground="#ffffff", selectbackground="#166f9c", relief="flat", padx=9, pady=7, font=("Consolas", max(10, self.font_size - 1)))
        log_y = ttk.Scrollbar(log_frame, orient="vertical", command=self.execution_log.yview)
        self.execution_log.configure(yscrollcommand=log_y.set)
        self.execution_log.pack(side="left", fill="both", expand=True); log_y.pack(side="right", fill="y")

        ttk.Progressbar(self, variable=self.progress_var, maximum=100).pack(fill="x", pady=(6, 3))
        status_bar = ttk.Frame(self, style="Mihomo.TFrame")
        status_bar.pack(fill="x")
        ttk.Label(status_bar, textvariable=self.state_var, style="Mihomo.State.TLabel").pack(side="left", padx=(0, 6))
        ttk.Label(status_bar, textvariable=self.status_var, style="Mihomo.TLabel").pack(side="left", fill="x", expand=True)
        ttk.Button(status_bar, text="Показать журнал", command=self._show_log, style="Mihomo.TButton").pack(side="right", padx=(6, 0))
        ttk.Label(self, text="Без TUN и системного proxy. Диагностический ZIP обезличен; приватный YAML храните локально.", style="Mihomo.Dim.TLabel").pack(fill="x", pady=(3, 0))
        self.bind("<Configure>", self._adapt_control_layout, add=True)

    def _adapt_control_layout(self, event: object | None = None) -> None:
        width = int(getattr(event, "width", self.winfo_width()))
        scaling = float(self.tk.call("tk", "scaling"))
        wide_threshold = max(1120, int(960 * scaling), self.font_size * 98)
        wide = width >= wide_threshold
        current = bool(getattr(self, "_wide_controls", False))
        if wide == current:
            return
        self._wide_controls = wide
        self.source_panel.grid_forget()
        self.check_panel.grid_forget()
        if wide:
            self.exports_frame.grid_forget()
            self.exports_frame.grid(row=0, column=2, sticky="e")
            self.controls_frame.columnconfigure(1, weight=1)
            self.source_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 3))
            self.check_panel.grid(row=0, column=1, sticky="nsew", padx=(3, 0))
        else:
            self.exports_frame.grid_forget()
            self.exports_frame.grid(row=1, column=0, columnspan=2, sticky="e", pady=(4, 0))
            self.controls_frame.columnconfigure(1, weight=0)
            self.source_panel.grid(row=0, column=0, sticky="nsew", pady=(0, 3))
            self.check_panel.grid(row=1, column=0, sticky="nsew", pady=(3, 0))

    def _clear_execution_log(self) -> None:
        self.execution_log_entries.clear()
        self.execution_log.configure(state="normal")
        self.execution_log.delete("1.0", "end")
        self.execution_log.configure(state="disabled")

    def _append_progress_log(self, update: mihomo_checker.ProgressUpdate) -> None:
        label = mihomo_checker.STAGE_LABELS.get(update.stage, update.stage)
        count = f"{update.processed}/{update.total}" if update.total else "—"
        safe_message = mihomo_checker.sanitize_text(update.message, 300)
        line = (
            f"[{update.total_elapsed_seconds:8.2f} с] {label}: {count} · "
            f"этап {update.stage_elapsed_seconds:.2f} с · {update.overall_percent:.1f}% — "
            f"{safe_message}\n"
        )
        is_error = any(token in safe_message.upper() for token in ("ОШИБ", "FAILED", "TIMEOUT", "503", "ОТКЛОН"))
        self.execution_log_entries.append((label, is_error, line))
        if len(self.execution_log_entries) > 2_000:
            self.execution_log_entries = self.execution_log_entries[-1_800:]
        selected_stage = self.log_stage_filter_var.get()
        if (selected_stage in {"Все этапы", label}) and (not self.log_error_only_var.get() or is_error):
            self.execution_log.configure(state="normal")
            self.execution_log.insert("end", line)
            self.execution_log.see("end")
            self.execution_log.configure(state="disabled")

    def _render_execution_log(self) -> None:
        selected_stage = self.log_stage_filter_var.get()
        error_only = self.log_error_only_var.get()
        lines = [
            line for stage, is_error, line in self.execution_log_entries
            if (selected_stage in {"Все этапы", stage}) and (not error_only or is_error)
        ]
        self.execution_log.configure(state="normal")
        self.execution_log.delete("1.0", "end")
        self.execution_log.insert("1.0", "".join(lines))
        self.execution_log.see("end")
        self.execution_log.configure(state="disabled")

    def _copy_execution_log(self) -> None:
        value = self.execution_log.get("1.0", "end-1c")
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update_idletasks()
        self.status_var.set("Безопасный журнал выполнения скопирован в буфер обмена.")

    def _export_execution_log(self) -> None:
        value = self.execution_log.get("1.0", "end-1c")
        if not value:
            return
        filename = filedialog.asksaveasfilename(
            parent=self,
            title="Экспорт безопасного журнала",
            defaultextension=".log",
            initialfile="WireVeil-Mihomo-safe.log",
            filetypes=(("LOG", "*.log"), ("TXT", "*.txt")),
        )
        if not filename:
            return
        try:
            Path(filename).write_text(value + "\n", encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось сохранить журнал: {exc}")
            return
        self.state_var.set("Экспортировано")
        self.status_var.set("Безопасный журнал экспортирован.")

    def _show_log(self) -> None:
        self.views.select(self.log_page)

    def _change_font(self, delta: int) -> None:
        new_size = min(15, max(10, self.font_size + delta))
        if new_size == self.font_size:
            return
        self.font_size = new_size
        self._configure_styles()
        self.execution_log.configure(font=("Consolas", max(10, self.font_size - 1)))
        self._save_ui_settings()

    def _save_ui_settings(self) -> None:
        try:
            save_ui_settings(
                self.ui_settings_path,
                {
                    "font_size": self.font_size,
                    "workers": int(self.workers_var.get()),
                    "sample_mode": self.node_limit_var.get(),
                    "sampling_seed": self.sampling_seed_var.get(),
                    "base_policy": self.base_policy_var.get(),
                    "table_mode": self.table_mode_var.get(),
                },
            )
        except (OSError, ValueError, tk.TclError):
            pass

    def _table_mode_changed(self, _event: object | None = None) -> None:
        overview = self.table_mode_var.get() == "Обзор"
        for column, variable in self.column_visibility.items():
            variable.set(column in self.OVERVIEW_COLUMNS if overview else True)
        self._apply_visible_columns()
        self._save_ui_settings()

    def _apply_visible_columns(self) -> None:
        columns = [column for column in self.NODE_COLUMNS if self.column_visibility[column].get()]
        for pinned in ("source", "name"):
            if pinned not in columns:
                columns.insert(0 if pinned == "source" else min(1, len(columns)), pinned)
                self.column_visibility[pinned].set(True)
        self.node_tree.configure(displaycolumns=columns)

    def _show_node_details(self, _event: object | None = None) -> None:
        selected = self.node_tree.selection()
        if not selected:
            return
        iid = selected[0]
        try:
            source_id, node_id = iid.split(":", 1)
        except ValueError:
            return
        result = self.live_results.get(node_id)
        if result is None and self.report is not None:
            result = next((item for item in self.report.node_results if item.node.node_id == node_id), None)
        if result is None:
            return
        source = next((item for item in self.sources if item.source_id == source_id), None)
        base_lines = []
        for key in ("gstatic", "cloudflare"):
            attempts = result.base_endpoint_results.get(key, [])
            success = sum(item.success for item in attempts)
            errors = ", ".join(item.error_code or "ошибка" for item in attempts if not item.success)
            base_lines.append(f"{key}: {success}/{len(attempts)}" + (f" — {errors}" if errors else ""))
        service_lines = [
            f"{name}: {value.status}; {value.error_code or (str(value.latency_ms) + ' ms' if value.latency_ms is not None else 'ok')}"
            for name, value in result.services.items()
        ]
        detail = "\n".join((
            f"ID: {result.node.node_id[:16]}",
            f"Источник: {source.name if source else source_id}",
            f"Узел: {result.node.source_original_names.get(source_id, '—')}",
            f"Протокол: {result.node.protocol}",
            f"Статус: {result.overall_status}",
            *base_lines,
            *(service_lines or ["Сервисы: не проверялись"]),
            f"Категория: {result.error_category or mihomo_checker.error_category_for_code(result.error_code) or '—'}",
            f"Код: {result.error_code or '—'}",
            f"Причина: {mihomo_checker.sanitize_text(result.error_summary or '—')}",
        ))
        messagebox.showinfo("Безопасные детали узла", detail, parent=self)

    def _show_source_details(self) -> None:
        selected = self._selected_source_ids()
        if len(selected) != 1:
            return
        source_id = next(iter(selected))
        source = next((item for item in self.sources if item.source_id == source_id), None)
        parsed = self.parsed_by_id.get(source_id)
        if source is None:
            return
        metadata = "\n".join(f"{key}: {mihomo_checker.sanitize_text(value, 160)}" for key, value in source.metadata.items()) or "—"
        protocols = ", ".join(f"{key}: {value}" for key, value in sorted((parsed.protocol_counts if parsed else {}).items())) or "—"
        age_days = mihomo_checker.source_age_days(source.metadata)
        messagebox.showinfo(
            "Источник",
            f"ID: {source.source_id}\nИмя: {source.name}\nТип: {source.kind}\nИсточник: {source.display}\n"
            f"Статус: {(parsed.fetch_status + ' / ' + parsed.parse_status) if parsed else 'не проверен'}\n"
            f"Размер: {parsed.download_bytes if parsed and parsed.download_bytes is not None else '—'} байт\n"
            f"Протоколы: {protocols}\nВозраст данных: {age_days if age_days is not None else '—'} дней\n"
            f"Последняя проверка: {parsed.checked_at if parsed else '—'}\n\nProvenance:\n{metadata}",
            parent=self,
        )

    def _dialog_text(
        self,
        title: str,
        prompt: str,
        *,
        multiline: bool = True,
    ) -> str | None:
        dialog = _MultilineDialog(self, title, prompt, multiline=multiline)
        self.wait_window(dialog)
        return dialog.result

    def _append_sources(self, additions: list[mihomo_checker.SourceSpec]) -> None:
        existing_urls = {
            mihomo_checker.canonical_source_url(item.value)
            for item in self.sources
            if item.kind == "url"
        }
        accepted: list[mihomo_checker.SourceSpec] = []
        duplicate_names: list[str] = []
        for item in additions:
            if item.kind == "url":
                canonical = mihomo_checker.canonical_source_url(item.value)
                if canonical in existing_urls:
                    duplicate_names.append(item.name)
                    continue
                existing_urls.add(canonical)
            accepted.append(item)
        if duplicate_names:
            sample = ", ".join(mihomo_checker.sanitize_text(name, 80) for name in duplicate_names[:5])
            messagebox.showwarning(
                "Дубли источников",
                f"Пропущено повторных URL: {len(duplicate_names)}. {sample}",
                parent=self,
            )
        if not accepted:
            return
        if len(self.sources) + len(accepted) > mihomo_checker.MAX_SOURCES:
            messagebox.showerror("WireVeil Checker", "Допускается не более 200 источников.")
            return
        self.sources.extend(accepted)
        self._save_sources()
        self._refresh_source_tree()
        self.state_var.set("Нет новых результатов")
        self.status_var.set(f"Добавлено источников: {len(accepted)}. Всего: {len(self.sources)}.")

    def _add_url(self) -> None:
        value = self._dialog_text(
            "Добавить URL",
            "URL Mihomo/Clash YAML подписки:",
            multiline=False,
        )
        if not value or not value.strip():
            return
        url = value.strip()
        if mihomo_checker.subscription_urls_from_text(url) is None:
            messagebox.showerror("WireVeil Checker", "Нужен корректный HTTP(S) URL подписки.", parent=self)
            return
        self._append_sources([mihomo_checker.SourceSpec(mihomo_checker.new_source_id(), mihomo_checker.source_name_from_url(url), "url", url)])

    def _add_urls(self) -> None:
        value = self._dialog_text("Добавить URLs списком", "Вставьте URL: один адрес на строку. Пустые строки и строки с # игнорируются.")
        if not value:
            return
        urls = mihomo_checker.subscription_urls_from_text(value)
        if urls is None:
            messagebox.showerror(
                "WireVeil Checker",
                "Список должен содержать только HTTP(S) URL: один адрес на строку; комментарии начинаются с #.",
                parent=self,
            )
            return
        additions: list[mihomo_checker.SourceSpec] = []
        for url in urls:
            additions.append(mihomo_checker.SourceSpec(mihomo_checker.new_source_id(), mihomo_checker.source_name_from_url(url), "url", url))
        if additions:
            self._append_sources(additions)

    def _add_files(self) -> None:
        names = filedialog.askopenfilenames(
            parent=self,
            title="Добавить Mihomo/Clash YAML",
            filetypes=(("Подписки и каталоги", "*.yaml *.yml *.txt *.csv"), ("Все файлы", "*.*")),
        )
        additions: list[mihomo_checker.SourceSpec] = []
        errors: list[str] = []
        for name in names:
            try:
                additions.extend(mihomo_checker.source_specs_from_file(Path(name)))
            except mihomo_checker.MihomoCheckError as exc:
                errors.append(f"{Path(name).name}: {exc.summary}")
        if additions:
            self._append_sources(additions)
        if errors:
            messagebox.showwarning("WireVeil Checker", "\n".join(errors))

    def _add_text(self) -> None:
        name = simpledialog.askstring("Имя источника", "Имя / метка вставленной подписки:", parent=self)
        if not name or not name.strip():
            return
        value = self._dialog_text("Вставить подписку", "Вставьте Mihomo/Clash YAML. Содержимое будет сохранено локально и может содержать секреты.")
        if value:
            self._append_sources([mihomo_checker.SourceSpec(mihomo_checker.new_source_id(), name.strip(), "text", value)])

    def _selected_source_ids(self) -> set[str]:
        return set(self.source_tree.selection())

    def _rename_selected(self) -> None:
        selected = list(self._selected_source_ids())
        if len(selected) != 1:
            return
        source = next((item for item in self.sources if item.source_id == selected[0]), None)
        if source is None:
            return
        name = simpledialog.askstring("Переименовать источник", "Новое имя:", initialvalue=source.name, parent=self)
        if not name or not name.strip():
            return
        self.sources = [
            mihomo_checker.SourceSpec(item.source_id, name.strip(), item.kind, item.value, dict(item.metadata))
            if item.source_id == source.source_id else item
            for item in self.sources
        ]
        self._save_sources()
        self._refresh_source_tree()

    def _delete_selected(self) -> None:
        selected = self._selected_source_ids()
        if not selected or self.running:
            return
        self.sources = [item for item in self.sources if item.source_id not in selected]
        self._save_sources()
        self._refresh_source_tree()

    def _clear_sources(self) -> None:
        if self.running or not self.sources:
            return
        if not messagebox.askyesno(
            "Очистить сохранённые источники",
            "Удалить список URL, путей и вставленного YAML из локальных настроек? Исходные файлы удалены не будут.",
            parent=self,
        ):
            return
        self.sources.clear()
        self.report = None
        self.parsed_by_id.clear()
        try:
            self.sources_path.unlink(missing_ok=True)
        except OSError as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось очистить настройки: {exc}")
        self._refresh_source_tree()
        self._refresh_node_tree()
        self._set_export_buttons(False)

    def _save_sources(self) -> None:
        try:
            mihomo_checker.save_source_specs(self.sources_path, self.sources)
        except OSError as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось сохранить локальный список источников: {exc}")

    def _refresh_source_tree(self) -> None:
        selected = self._selected_source_ids() if hasattr(self, "source_tree") else set()
        self.source_tree.delete(*self.source_tree.get_children())
        report_sources: dict[str, mihomo_checker.ParsedSource] = {}
        report_counts: dict[str, dict[str, int]] = {}
        if self.report is not None:
            report_sources = {
                item.spec.source_id: item for item in self.report.sources
            }
            for result in self.report.node_results:
                for source_id in result.node.source_ids:
                    counts = report_counts.setdefault(
                        source_id,
                        {"good": 0, "partial": 0, "failed": 0, "unsupported": 0, "not_tested": 0},
                    )
                    if result.overall_status in counts:
                        counts[result.overall_status] += 1
        for source in self.sources:
            row = report_sources.get(source.source_id)
            live = self.parsed_by_id.get(source.source_id)
            if row is None and live is None:
                values = (source.name, "не проверен", "—", "—", "—", "—", "—", "—", "—", "—", "—", "—")
            elif row is None:
                assert live is not None
                protocols = ", ".join(f"{key}:{value}" for key, value in sorted(live.protocol_counts.items())) or "—"
                values = (
                    source.name,
                    f"{live.fetch_status} / {live.parse_status}",
                    self._format_bytes(live.download_bytes),
                    protocols,
                    live.total_entries,
                    "—", "—", "—", "—", "—",
                    " · ".join(item for item in (live.error_code, mihomo_checker.sanitize_text(live.error_summary, 100) if live.error_summary else None) if item) or "—",
                    live.checked_at or "—",
                )
            else:
                counts = report_counts.get(
                    source.source_id,
                    {"good": 0, "partial": 0, "failed": 0, "unsupported": 0, "not_tested": 0},
                )
                protocols = ", ".join(f"{key}:{value}" for key, value in sorted(row.protocol_counts.items())) or "—"
                values = (
                    source.name,
                    f"{row.fetch_status} / {row.parse_status}",
                    self._format_bytes(row.download_bytes),
                    protocols,
                    row.total_entries,
                    counts["good"],
                    counts["partial"],
                    counts["failed"],
                    counts["unsupported"],
                    counts["not_tested"],
                    " · ".join(item for item in (row.error_code, mihomo_checker.sanitize_text(row.error_summary, 100) if row.error_summary else None) if item) or "—",
                    row.checked_at or "—",
                )
            self.source_tree.insert("", "end", iid=source.source_id, values=values)
        for source_id in selected:
            if self.source_tree.exists(source_id):
                self.source_tree.selection_add(source_id)
        labels = ["Все источники", *(f"{item.name} [{item.source_id}]" for item in self.sources)]
        self.source_filter.configure(values=labels)
        if self.source_filter_var.get() not in labels:
            self.source_filter_var.set("Все источники")
        if self.source_sort_column is not None:
            self._apply_tree_sort(
                self.source_tree, self.source_sort_column, self.source_sort_descending
            )
        parsed_rows = list(report_sources.values()) or list(self.parsed_by_id.values())
        source_errors = sum(item.fetch_status == "failed" or item.parse_status in {"failed", "unsupported"} for item in parsed_rows)
        self.kpi_vars["sources"].set(f"Источники {len(parsed_rows) or len(self.sources)} / ошибки {source_errors}")

    @staticmethod
    def _format_bytes(value: int | None) -> str:
        if value is None:
            return "—"
        if value >= 1024 * 1024:
            return f"{value / (1024 * 1024):.1f} МБ"
        if value >= 1024:
            return f"{value / 1024:.1f} КБ"
        return f"{value} Б"

    @staticmethod
    def _service_cell(result: mihomo_checker.ServiceResult | None) -> str:
        if result is None:
            return "—"
        if result.status == "reachable":
            return f"● {result.latency_ms}" if result.latency_ms is not None else "●"
        return f"× {result.error_code or 'ошибка'}"

    def _passes_node_filters(self, result: mihomo_checker.NodeResult, source_id: str) -> bool:
        source_filter = self.source_filter_var.get()
        if source_filter != "Все источники" and not source_filter.endswith(f"[{source_id}]"):
            return False
        status_filter = self.status_filter_var.get()
        if status_filter != "Все статусы" and result.overall_status != status_filter:
            return False
        service_filter = self.service_filter_var.get()
        if service_filter != "Все сервисы":
            name, expected_label = service_filter.rsplit(": ", 1)
            service = result.services.get(name)
            expected_status = "reachable" if expected_label == "доступен" else "failed"
            if service is None or service.status != expected_status:
                return False
        return True

    def _node_row_values(
        self,
        result: mihomo_checker.NodeResult,
        source_id: str,
        source_names: dict[str, str],
    ) -> tuple[object, ...]:
        node = result.node
        values: list[object] = [
            source_names.get(source_id, source_id),
            node.source_original_names.get(source_id, "—"),
            node.protocol,
            result.overall_status,
            f"{result.base_successes}/{result.base_attempts}" if result.base_attempts else "—",
            f"{node.server}:{node.port or '—'}",
            result.base_latency_ms if result.base_latency_ms is not None else "—",
        ]
        values.extend(
            self._service_cell(result.services.get(item.name))
            for item in mihomo_checker.SERVICE_DEFINITIONS
        )
        category = result.error_category or mihomo_checker.error_category_for_code(result.error_code)
        summary = mihomo_checker.sanitize_text(result.error_summary, 120) if result.error_summary else None
        values.append(" · ".join(item for item in (category, result.error_code, summary) if item) or "—")
        return tuple(values)

    def _update_node_rows(self, results: list[mihomo_checker.NodeResult]) -> None:
        if not results:
            return
        source_names = {item.source_id: item.name for item in self.sources}
        for result in results:
            for source_id in result.node.source_ids:
                iid = f"{source_id}:{result.node.node_id}"
                if not self._passes_node_filters(result, source_id):
                    if self.node_tree.exists(iid):
                        self.node_tree.delete(iid)
                    continue
                values = self._node_row_values(result, source_id, source_names)
                if self.node_tree.exists(iid):
                    self.node_tree.item(
                        iid,
                        values=values,
                        tags=(result.overall_status,),
                    )
                else:
                    self.node_tree.insert(
                        "",
                        "end",
                        iid=iid,
                        values=values,
                        tags=(result.overall_status,),
                    )

    def _refresh_node_tree(self) -> None:
        self.node_tree.delete(*self.node_tree.get_children())
        source_names = {item.source_id: item.name for item in self.sources}
        results = (
            self.report.node_results
            if self.report is not None
            else list(self.live_results.values())
        )
        for result in results:
            for source_id in result.node.source_ids:
                if not self._passes_node_filters(result, source_id):
                    continue
                iid = f"{source_id}:{result.node.node_id}"
                self.node_tree.insert(
                    "",
                    "end",
                    iid=iid,
                    values=self._node_row_values(result, source_id, source_names),
                    tags=(result.overall_status,),
                )
        if self.node_sort_column is not None:
            self._apply_tree_sort(
                self.node_tree, self.node_sort_column, self.node_sort_descending
            )

    @staticmethod
    def _tree_sort_value(value: object) -> tuple[object, ...]:
        text = str(value).strip()
        if text in {"", "—", "не проверен"}:
            return (4, "")
        if text.isdigit():
            return (0, int(text))
        latency = None
        for token in text.replace("·", " ").split():
            if token.isdigit():
                latency = int(token)
        if ("доступен" in text or text.startswith("●")) and latency is not None:
            return (0, latency)
        status_order = {"good": 0, "partial": 1, "failed": 2, "unsupported": 3, "not_tested": 4}
        if text in status_order:
            return (1, status_order[text])
        return (2, text.casefold())

    @classmethod
    def _apply_tree_sort(cls, tree: ttk.Treeview, column: str, descending: bool) -> None:
        rows = list(tree.get_children(""))
        rows.sort(
            key=lambda item: cls._tree_sort_value(tree.set(item, column)),
            reverse=descending,
        )
        for position, item in enumerate(rows):
            tree.move(item, "", position)

    def _sort_node_tree(self, column: str) -> None:
        if self.node_sort_column == column:
            self.node_sort_descending = not self.node_sort_descending
        else:
            self.node_sort_column = column
            self.node_sort_descending = False
        self._apply_tree_sort(self.node_tree, column, self.node_sort_descending)

    def _sort_source_tree(self, column: str) -> None:
        if self.source_sort_column == column:
            self.source_sort_descending = not self.source_sort_descending
        else:
            self.source_sort_column = column
            self.source_sort_descending = False
        self._apply_tree_sort(self.source_tree, column, self.source_sort_descending)

    def _settings(self) -> tuple[int, int, int, int | None, int | None, str, str] | None:
        try:
            attempts = int(self.attempts_var.get())
            timeout = int(self.timeout_var.get())
            workers = int(self.workers_var.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("WireVeil Checker", "Проверьте числовые параметры Mihomo.")
            return None
        sample_mode = self.node_limit_var.get()
        sample_settings = {
            "Репрезентативно: 50": (50, None),
            "Репрезентативно: 100": (100, None),
            "Репрезентативно: 500": (500, None),
            "20 на источник": (None, 20),
            "100 на источник": (None, 100),
            "Все узлы": (None, None),
        }
        node_limit, per_source_limit = sample_settings.get(sample_mode, (-1, None))
        seed = mihomo_checker.sanitize_text(self.sampling_seed_var.get(), 80) or "wireveil-default"
        base_policy = "strict" if self.base_policy_var.get() == "Строго 2/2" else "one_ok"
        if (
            not 2 <= attempts <= 5
            or not 1 <= timeout <= 60
            or workers not in mihomo_checker.BASE_WORKERS_ALLOWED
            or node_limit == -1
        ):
            messagebox.showerror(
                "WireVeil Checker",
                "HTTPS-прогоны: 2–5, тайм-аут: 1–60 сек, параллельность: 8/16/24.",
            )
            return None
        return attempts, timeout, workers, node_limit, per_source_limit, seed, base_policy

    def _start_all(self) -> None:
        self._start(tuple(self.sources))

    def _start_selected(self) -> None:
        selected = self._selected_source_ids()
        self._start(tuple(item for item in self.sources if item.source_id in selected))

    def _start(self, sources: tuple[mihomo_checker.SourceSpec, ...]) -> None:
        if self.running:
            return
        if not sources:
            messagebox.showinfo("WireVeil Checker", "Добавьте или выберите хотя бы один источник.")
            return
        settings = self._settings()
        if settings is None:
            return
        binary = find_mihomo()
        if binary is None:
            messagebox.showerror(
                "WireVeil Checker",
                "Не найден mihomo.exe. В портативной сборке он должен находиться рядом с приложением.",
            )
            return
        attempts, timeout, workers, node_limit, per_source_limit, seed, base_policy = settings
        if node_limit is None and per_source_limit is None and not messagebox.askyesno(
            "Полная проверка",
            "Проверить весь пул без лимита? Для тысяч узлов это может занять много времени.",
            parent=self,
        ):
            return
        services = tuple(name for name, variable in self.service_vars.items() if variable.get())
        self.runner = mihomo_checker.BatchRunner()
        self.report = None
        self.parsed_by_id.clear()
        self.live_results.clear()
        self.pending_node_results.clear()
        self._refresh_node_tree()
        self._clear_execution_log()
        self.active_progress = None
        self.stop_requested = False
        self.running = True
        self.progress_var.set(0)
        self.state_var.set("Выполняется")
        self._set_running_controls(True)
        self._set_export_buttons(False)
        limit_label = self.node_limit_var.get().casefold()
        self.status_var.set(
            f"Загрузка {len(sources)} источников; режим проверки: {limit_label}…"
        )
        self._save_ui_settings()

        def work() -> None:
            assert self.runner is not None
            try:
                report = self.runner.run(
                    binary=binary,
                    source_specs=sources,
                    selected_services=services,
                    attempts=attempts,
                    timeout_ms=timeout * 1000,
                    workers=workers,
                    node_limit=node_limit,
                    per_source_limit=per_source_limit,
                    sampling_seed=seed,
                    base_policy=base_policy,
                    source_callback=lambda parsed: self.events.put(("source", parsed)),
                    node_callback=lambda done, total, result: self.events.put(("node", done, total, result)),
                    progress_callback=lambda update: self.events.put(("progress", update)),
                )
                self.events.put(("done", report))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=work, name="wireveil-mihomo-check", daemon=True).start()

    def stop(self) -> None:
        runner = self.runner
        if runner is not None:
            self.status_var.set("Остановка локального Mihomo и отмена проверок…")
            self.state_var.set("Остановка…")
            self.stop_button.configure(state="disabled")
            self.stop_requested = True
            self.active_progress = None
            runner.stop()

    @staticmethod
    def _format_eta(seconds: float | None) -> str:
        if seconds is None:
            return "—"
        seconds = max(0, int(seconds))
        minutes, tail = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours}:{minutes:02}:{tail:02}" if hours else f"{minutes}:{tail:02}"

    def _update_kpis(self, progress: mihomo_checker.ProgressUpdate | None = None) -> None:
        results = self.report.node_results if self.report is not None else list(self.live_results.values())
        statuses = [item.overall_status for item in results]
        https_passed = sum(item.base_attempts > 0 and item.base_successes == item.base_attempts for item in results)
        checked = sum(item.overall_status != "not_tested" for item in results)
        self.kpi_vars["nodes"].set(f"Узлы {len(results)}")
        self.kpi_vars["https"].set(f"HTTPS {https_passed}")
        self.kpi_vars["statuses"].set(
            f"G {statuses.count('good')} · P {statuses.count('partial')} · F {statuses.count('failed')} · "
            f"U {statuses.count('unsupported')} · — {statuses.count('not_tested')}"
        )
        total = len(results)
        if progress is not None and progress.stage in {"https", "services"} and progress.total:
            checked = progress.processed
            total = progress.total
        self.kpi_vars["checked"].set(f"Проверено {checked}/{total}")
        if progress is not None and progress.rate_per_minute is not None:
            self.kpi_vars["rate"].set(f"Скорость {progress.rate_per_minute:.0f}/мин")
            self.kpi_vars["eta"].set(
                f"ETA {self._format_eta(progress.eta_low_seconds)}–{self._format_eta(progress.eta_high_seconds)}"
            )
        elif not self.running:
            self.kpi_vars["rate"].set("Скорость —")
            self.kpi_vars["eta"].set("ETA —")

    def _poll_events(self) -> None:
        self.poll_job = None
        if self.closing:
            return
        refresh_sources = False
        finish_report: mihomo_checker.BatchReport | None = None
        failure: object | None = None
        processed_events = 0
        while processed_events < 300:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            processed_events += 1
            kind = event[0]
            if kind == "source":
                parsed = event[1]
                assert isinstance(parsed, mihomo_checker.ParsedSource)
                self.parsed_by_id[parsed.spec.source_id] = parsed
                refresh_sources = True
            elif kind == "node":
                result = event[3]
                assert isinstance(result, mihomo_checker.NodeResult)
                self.live_results[result.node.node_id] = result
                self.pending_node_results[result.node.node_id] = result
            elif kind == "progress":
                update = event[1]
                assert isinstance(update, mihomo_checker.ProgressUpdate)
                self.progress_var.set(update.overall_percent)
                self._append_progress_log(update)
                if not self.stop_requested:
                    self.active_progress = update
                    self.active_progress_received_at = time.monotonic()
                self._update_kpis(update)
            elif kind == "done":
                report = event[1]
                assert isinstance(report, mihomo_checker.BatchReport)
                finish_report = report
            elif kind == "error":
                failure = event[1]

        if refresh_sources:
            self._refresh_source_tree()
        if self.pending_node_results:
            pending = list(self.pending_node_results.values())
            self.pending_node_results.clear()
            self._update_node_rows(pending)
            self._update_kpis(self.active_progress)
        if finish_report is not None:
            self._finish(finish_report)
        elif failure is not None:
            self._fail(failure)
        if self.running and self.active_progress is not None:
            update = self.active_progress
            since_update = max(0.0, time.monotonic() - self.active_progress_received_at)
            label = mihomo_checker.STAGE_LABELS.get(update.stage, update.stage)
            count = f"{update.processed} / {update.total}" if update.total else "—"
            self.status_var.set(
                f"{label}: {count} · этап {update.stage_elapsed_seconds + since_update:.1f} с · "
                f"всего {update.total_elapsed_seconds + since_update:.1f} с — {update.message}"
            )
        delay = 10 if not self.events.empty() else 100
        self.poll_job = self.after(delay, self._poll_events)

    def _finish(self, report: mihomo_checker.BatchReport) -> None:
        self.report = report
        self.running = False
        self.stop_requested = False
        self.active_progress = None
        self.runner = None
        self.progress_var.set(100)
        self._set_running_controls(False)
        self._set_export_buttons(True)
        self._refresh_source_tree()
        self._update_kpis()
        missing = [
            result
            for result in report.node_results
            if result.node.node_id not in self.live_results
        ]
        for result in missing:
            self.live_results[result.node.node_id] = result
        self._update_node_rows(missing)
        if self.node_sort_column is not None:
            self._apply_tree_sort(
                self.node_tree,
                self.node_sort_column,
                self.node_sort_descending,
            )
        statuses = [result.overall_status for result in report.node_results]
        totals = {
            "unique_nodes": len(report.node_results),
            "good": statuses.count("good"),
            "partial": statuses.count("partial"),
            "failed": statuses.count("failed"),
            "not_tested": statuses.count("not_tested"),
            "unsupported": statuses.count("unsupported"),
        }
        cancelled = any(
            result.error_code == "CANCELLED" for result in report.node_results
        ) or any(parsed.fetch_status == "cancelled" for parsed in report.sources)
        if cancelled:
            self.state_var.set("Отменено")
            self.status_var.set(
                "Проверка остановлена. Доступные частичные результаты можно экспортировать."
            )
        else:
            self.state_var.set("Завершено")
            self.status_var.set(
                "Пакетная проверка завершена. Результаты относятся к текущей сети ПК."
            )
        self.summary_var.set(
            f"Узлов {totals['unique_nodes']} · good {totals['good']} · partial {totals['partial']} · failed {totals['failed']} · unsupported {totals['unsupported']} · not tested {totals['not_tested']}"  # type: ignore[index]
        )

    def _fail(self, error: object) -> None:
        self.running = False
        self.stop_requested = False
        self.active_progress = None
        self.runner = None
        self._set_running_controls(False)
        if isinstance(error, mihomo_checker.MihomoCheckError):
            detail = f"{error.code}: {error.summary}"
        else:
            detail = mihomo_checker.sanitize_text(error)
        self._append_progress_log(
            mihomo_checker.ProgressUpdate(
                stage="completion",
                processed=0,
                total=1,
                stage_elapsed_seconds=0.0,
                total_elapsed_seconds=0.0,
                overall_percent=float(self.progress_var.get()),
                message=f"Ошибка выполнения: {detail}",
            )
        )
        self.status_var.set(f"Ошибка: {detail}")
        self.state_var.set("Ошибка")
        messagebox.showerror("WireVeil Checker", detail)

    def _set_running_controls(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        self.start_all_button.configure(state=state)
        self.start_selected_button.configure(state=state)
        self.stop_button.configure(state="normal" if running else "disabled")
        self.node_limit.configure(state="disabled" if running else "readonly")
        self.worker_combo.configure(state="disabled" if running else "readonly")
        self.base_policy.configure(state="disabled" if running else "readonly")

    def _set_export_buttons(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.export_report_button.configure(state=state)
        self.export_yaml_button.configure(state=state)
        self.export_sources_button.configure(state=state)

    def _export_report(self) -> None:
        if self.report is None:
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = filedialog.asksaveasfilename(
            parent=self,
            title="Экспорт обезличенного диагностического отчёта",
            defaultextension=".zip",
            initialfile=f"WireVeil-Mihomo-Report-{stamp}.zip",
            filetypes=(("ZIP", "*.zip"),),
        )
        if not filename:
            return
        try:
            path = mihomo_checker.export_report_zip(self.report, Path(filename))
        except OSError as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось сохранить отчёт: {exc}")
            return
        self.status_var.set(f"Безопасный диагностический ZIP сохранён: {path.name}")
        self.state_var.set("Экспортировано")

    def _export_private(self) -> None:
        if self.report is None:
            return
        if not messagebox.askokcancel(
            "Приватный экспорт",
            "Файл будет содержать UUID, пароли и ключи прокси. Храните его локально и не отправляйте посторонним.",
            parent=self,
        ):
            return
        filename = filedialog.asksaveasfilename(
            parent=self,
            title="Экспорт рабочих узлов (ПРИВАТНЫЙ)",
            defaultextension=".yaml",
            initialfile="WireVeil-Mihomo-working-private.yaml",
            filetypes=(("YAML", "*.yaml"),),
        )
        if not filename:
            return
        try:
            mihomo_checker.export_private_yaml(self.report, Path(filename))
        except (OSError, mihomo_checker.MihomoCheckError) as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось сохранить YAML: {exc}")
            return
        self.status_var.set("Приватный YAML рабочих узлов сохранён отдельно от отчёта.")
        self.state_var.set("Экспортировано")

    def _export_private_by_source(self) -> None:
        if self.report is None:
            return
        if not messagebox.askokcancel(
            "Приватный экспорт по источникам",
            "Файлы будут содержать полные секретные параметры узлов. Они не входят в диагностический ZIP.",
            parent=self,
        ):
            return
        directory = filedialog.askdirectory(parent=self, title="Папка для приватных YAML по источникам")
        if not directory:
            return
        try:
            paths = mihomo_checker.export_private_yaml_by_source(self.report, Path(directory))
        except (OSError, mihomo_checker.MihomoCheckError) as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось сохранить YAML: {exc}")
            return
        self.status_var.set(f"Сохранено приватных YAML по источникам: {len(paths)}.")
        self.state_var.set("Экспортировано")

    def close(self) -> None:
        self.closing = True
        if self.poll_job is not None:
            try:
                self.after_cancel(self.poll_job)
            except tk.TclError:
                pass
            self.poll_job = None
        runner = self.runner
        if runner is not None:
            runner.stop()
        self._save_sources()
        self._save_ui_settings()
