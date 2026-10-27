"""Tkinter tab for batch Mihomo/OpenClash diagnostics."""

from __future__ import annotations

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


SOURCES_FILENAME = "WireVeilChecker.mihomo-sources.json"


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


def _application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


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
        "name", "kind", "status", "total", "good", "partial", "failed", "error", "checked"
    )
    NODE_COLUMNS = (
        "source", "name", "protocol", "endpoint", "status", "latency",
        *(service.key for service in mihomo_checker.SERVICE_DEFINITIONS),
        "error",
    )

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, padding=10)
        self.sources_path = _application_root() / SOURCES_FILENAME
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

        self.attempts_var = tk.IntVar(value=2)
        self.timeout_var = tk.IntVar(value=8)
        self.workers_var = tk.IntVar(value=8)
        self.node_limit_var = tk.StringVar(value="Все")
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

        self._build_ui()
        self._refresh_source_tree()
        self.after(100, self._poll_events)

    def _build_ui(self) -> None:
        header = ttk.Frame(self, style="Header.TFrame", padding=(12, 9))
        header.pack(fill="x")
        title = ttk.Frame(header, style="Header.TFrame")
        title.pack(side="left")
        ttk.Label(title, text="Mihomo / OpenClash", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(
            title,
            text="Пакетная HTTPS-проверка из текущей сети этого компьютера",
            style="Subtitle.TLabel",
        ).pack(anchor="w")
        self.export_sources_button = ttk.Button(
            header,
            text="Приватный YAML по источникам…",
            command=self._export_private_by_source,
            state="disabled",
            style="Secondary.TButton",
        )
        self.export_sources_button.pack(side="right")
        self.export_yaml_button = ttk.Button(
            header,
            text="Приватный YAML рабочих…",
            command=self._export_private,
            state="disabled",
            style="Secondary.TButton",
        )
        self.export_yaml_button.pack(side="right", padx=(0, 5))
        self.export_report_button = ttk.Button(
            header,
            text="Экспорт отчёта…",
            command=self._export_report,
            state="disabled",
            style="Accent.TButton",
        )
        self.export_report_button.pack(side="right", padx=(0, 5))

        actions = ttk.Frame(self, style="Card.TFrame", padding=(10, 8))
        actions.pack(fill="x", pady=(8, 6))
        for text, command in (
            ("Добавить URL", self._add_url),
            ("Добавить URLs списком", self._add_urls),
            ("Добавить файлы…", self._add_files),
            ("Вставить подписку", self._add_text),
            ("Переименовать", self._rename_selected),
            ("Удалить выбранные", self._delete_selected),
            ("Очистить список", self._clear_sources),
        ):
            ttk.Button(actions, text=text, command=command, style="Secondary.TButton").pack(
                side="left", padx=(0, 4)
            )

        run_bar = ttk.Frame(self, style="Hero.TFrame", padding=(10, 8))
        run_bar.pack(fill="x", pady=(0, 6))
        self.start_all_button = ttk.Button(
            run_bar, text="▶ Проверить все", command=self._start_all, style="Launch.TButton"
        )
        self.start_all_button.pack(side="left")
        self.start_selected_button = ttk.Button(
            run_bar, text="Проверить выбранные источники", command=self._start_selected
        )
        self.start_selected_button.pack(side="left", padx=(6, 0))
        self.stop_button = ttk.Button(
            run_bar, text="■ Стоп", command=self.stop, state="disabled", style="Secondary.TButton"
        )
        self.stop_button.pack(side="left", padx=(6, 0))
        ttk.Label(
            run_bar,
            text="Mihomo запускается локально без TUN, системного прокси и изменений OpenClash",
            style="PanelDim.TLabel",
        ).pack(side="right")

        settings = ttk.Frame(self, style="Panel.TFrame", padding=(10, 6))
        settings.pack(fill="x", pady=(0, 6))
        for label, variable, start, end in (
            ("HTTPS-прогонов", self.attempts_var, 2, 5),
            ("Тайм-аут, сек", self.timeout_var, 1, 60),
            ("Параллельность", self.workers_var, 1, 32),
        ):
            ttk.Label(settings, text=label, style="Panel.TLabel").pack(side="left", padx=(0, 4))
            ttk.Spinbox(settings, from_=start, to=end, textvariable=variable, width=5).pack(
                side="left", padx=(0, 12)
            )
        ttk.Label(settings, text="Узлов", style="Panel.TLabel").pack(side="left", padx=(0, 4))
        self.node_limit = ttk.Combobox(
            settings,
            textvariable=self.node_limit_var,
            state="readonly",
            width=7,
            values=("50", "100", "500", "Все"),
        )
        self.node_limit.pack(side="left", padx=(0, 12))
        ttk.Label(settings, text="Сервисы:", style="PanelTitle.TLabel").pack(side="left", padx=(4, 5))
        for service in mihomo_checker.SERVICE_DEFINITIONS:
            ttk.Checkbutton(
                settings,
                text=service.name,
                variable=self.service_vars[service.name],
                style="Panel.TCheckbutton",
            ).pack(side="left", padx=(0, 5))

        views = ttk.Notebook(self)
        views.pack(fill="both", expand=True)
        sources_page = ttk.Frame(views)
        nodes_page = ttk.Frame(views)
        log_page = ttk.Frame(views)
        views.add(sources_page, text="Источники")
        views.add(nodes_page, text="Узлы")
        views.add(log_page, text="Журнал выполнения")

        self.source_tree = ttk.Treeview(
            sources_page, columns=self.SOURCE_COLUMNS, show="headings", selectmode="extended"
        )
        source_headings = {
            "name": "Имя / метка", "kind": "Тип", "status": "Загрузка / разбор",
            "total": "Всего", "good": "Рабочих", "partial": "Частичных",
            "failed": "Нерабочих", "error": "Ошибка", "checked": "Последняя проверка",
        }
        source_widths = {
            "name": 220, "kind": 80, "status": 130, "total": 60, "good": 70,
            "partial": 80, "failed": 90, "error": 210, "checked": 145,
        }
        for column in self.SOURCE_COLUMNS:
            self.source_tree.heading(
                column,
                text=source_headings[column],
                command=lambda selected=column: self._sort_source_tree(selected),
            )
            self.source_tree.column(column, width=source_widths[column], minwidth=45, stretch=column in {"name", "error"})
        self.source_tree.bind("<Double-1>", lambda _event: self._rename_selected())
        source_y = ttk.Scrollbar(sources_page, orient="vertical", command=self.source_tree.yview)
        source_x = ttk.Scrollbar(sources_page, orient="horizontal", command=self.source_tree.xview)
        self.source_tree.configure(yscrollcommand=source_y.set, xscrollcommand=source_x.set)
        sources_page.columnconfigure(0, weight=1)
        sources_page.rowconfigure(0, weight=1)
        self.source_tree.grid(row=0, column=0, sticky="nsew")
        source_y.grid(row=0, column=1, sticky="ns")
        source_x.grid(row=1, column=0, sticky="ew")

        filters = ttk.Frame(nodes_page, style="Panel.TFrame", padding=(6, 4))
        filters.pack(fill="x")
        ttk.Label(filters, text="Фильтры:", style="Panel.TLabel").pack(side="left")
        self.source_filter = ttk.Combobox(
            filters, textvariable=self.source_filter_var, state="readonly", width=24
        )
        self.source_filter.pack(side="left", padx=(5, 5))
        self.status_filter = ttk.Combobox(
            filters,
            textvariable=self.status_filter_var,
            state="readonly",
            width=16,
            values=("Все статусы", "good", "partial", "failed", "unsupported", "not_tested"),
        )
        self.status_filter.pack(side="left", padx=(0, 5))
        service_filter_values = ["Все сервисы"]
        for service in mihomo_checker.SERVICE_DEFINITIONS:
            service_filter_values.extend((f"{service.name}: доступен", f"{service.name}: ошибка"))
        self.service_filter = ttk.Combobox(
            filters,
            textvariable=self.service_filter_var,
            state="readonly",
            width=25,
            values=service_filter_values,
        )
        self.service_filter.pack(side="left")
        for widget in (self.source_filter, self.status_filter, self.service_filter):
            widget.bind("<<ComboboxSelected>>", lambda _event: self._refresh_node_tree())

        node_frame = ttk.Frame(nodes_page)
        node_frame.pack(fill="both", expand=True)
        self.node_tree = ttk.Treeview(
            node_frame, columns=self.NODE_COLUMNS, show="headings", selectmode="extended"
        )
        node_headings = {
            "source": "Источник", "name": "Имя", "protocol": "Протокол",
            "endpoint": "Endpoint", "status": "Статус", "latency": "HTTPS, мс",
            "error": "Причина",
        }
        node_headings.update({item.key: item.name for item in mihomo_checker.SERVICE_DEFINITIONS})
        for column in self.NODE_COLUMNS:
            self.node_tree.heading(
                column,
                text=node_headings[column],
                command=lambda selected=column: self._sort_node_tree(selected),
            )
            width = 135 if column not in {"source", "name", "endpoint", "error"} else 190
            self.node_tree.column(column, width=width, minwidth=55, stretch=column in {"name", "error"})
        for tag, color in (("good", "#60d35f"), ("partial", "#e1c95c"), ("failed", "#ee716c"), ("unsupported", "#9a82cc"), ("not_tested", "#718292")):
            self.node_tree.tag_configure(tag, foreground=color)
        node_y = ttk.Scrollbar(node_frame, orient="vertical", command=self.node_tree.yview)
        node_x = ttk.Scrollbar(node_frame, orient="horizontal", command=self.node_tree.xview)
        self.node_tree.configure(yscrollcommand=node_y.set, xscrollcommand=node_x.set)
        node_frame.columnconfigure(0, weight=1)
        node_frame.rowconfigure(0, weight=1)
        self.node_tree.grid(row=0, column=0, sticky="nsew")
        node_y.grid(row=0, column=1, sticky="ns")
        node_x.grid(row=1, column=0, sticky="ew")

        log_actions = ttk.Frame(log_page, style="Panel.TFrame", padding=(6, 4))
        log_actions.pack(fill="x")
        ttk.Label(
            log_actions,
            text="Безопасный журнал этапов — секреты и полные URL не записываются",
            style="PanelDim.TLabel",
        ).pack(side="left")
        ttk.Button(
            log_actions,
            text="Копировать журнал",
            command=self._copy_execution_log,
            style="Secondary.TButton",
        ).pack(side="right")
        log_frame = ttk.Frame(log_page)
        log_frame.pack(fill="both", expand=True)
        self.execution_log = tk.Text(
            log_frame,
            wrap="word",
            state="disabled",
            background="#101821",
            foreground="#d7e4ec",
            insertbackground="#ffffff",
            selectbackground="#166f9c",
            relief="flat",
            padx=9,
            pady=7,
        )
        log_y = ttk.Scrollbar(log_frame, orient="vertical", command=self.execution_log.yview)
        self.execution_log.configure(yscrollcommand=log_y.set)
        self.execution_log.pack(side="left", fill="both", expand=True)
        log_y.pack(side="right", fill="y")

        notice = ttk.Label(
            self,
            text=(
                "Отчёт ZIP не содержит ключей и токенов. Приватный YAML содержит полные настройки — не отправляйте его в чат. "
                "Проверка сайта не гарантирует авторизацию, CDN, видео, UDP/QUIC; маршрутизация и VPN Windows влияют на результат."
            ),
            style="Dim.TLabel",
            wraplength=1150,
            justify="left",
        )
        notice.pack(fill="x", pady=(6, 3))
        ttk.Progressbar(self, variable=self.progress_var, maximum=100).pack(fill="x", pady=(2, 3))
        status_bar = ttk.Frame(self)
        status_bar.pack(fill="x")
        ttk.Label(status_bar, textvariable=self.status_var).pack(side="left")
        ttk.Label(status_bar, textvariable=self.summary_var, style="Summary.TLabel").pack(side="right")

    def _clear_execution_log(self) -> None:
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
        self.execution_log.configure(state="normal")
        self.execution_log.insert("end", line)
        try:
            line_count = int(self.execution_log.index("end-1c").split(".", 1)[0])
        except (ValueError, tk.TclError):
            line_count = 0
        if line_count > 2_000:
            self.execution_log.delete("1.0", f"{line_count - 1_800}.0")
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
        if len(self.sources) + len(additions) > mihomo_checker.MAX_SOURCES:
            messagebox.showerror("WireVeil Checker", "Допускается не более 200 источников.")
            return
        self.sources.extend(additions)
        self._save_sources()
        self._refresh_source_tree()
        self.status_var.set(f"Добавлено источников: {len(additions)}. Всего: {len(self.sources)}.")

    def _add_url(self) -> None:
        value = self._dialog_text(
            "Добавить URL",
            "URL Mihomo/Clash YAML подписки:",
            multiline=False,
        )
        if not value or not value.strip():
            return
        url = value.strip()
        try:
            host = urllib.parse.urlsplit(url).hostname or "Подписка"
        except ValueError:
            host = "Подписка"
        self._append_sources([mihomo_checker.SourceSpec(mihomo_checker.new_source_id(), host, "url", url)])

    def _add_urls(self) -> None:
        value = self._dialog_text("Добавить URLs списком", "Вставьте URL: один адрес на строку. Пустые строки и строки с # игнорируются.")
        if not value:
            return
        additions: list[mihomo_checker.SourceSpec] = []
        for line in value.splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            try:
                name = urllib.parse.urlsplit(url).hostname or f"Подписка {len(additions) + 1}"
            except ValueError:
                name = f"Подписка {len(additions) + 1}"
            additions.append(mihomo_checker.SourceSpec(mihomo_checker.new_source_id(), name, "url", url))
        if additions:
            self._append_sources(additions)

    def _add_files(self) -> None:
        names = filedialog.askopenfilenames(
            parent=self,
            title="Добавить Mihomo/Clash YAML",
            filetypes=(("Подписки", "*.yaml *.yml *.txt"), ("Все файлы", "*.*")),
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
            mihomo_checker.SourceSpec(item.source_id, name.strip(), item.kind, item.value)
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
                        {"good": 0, "partial": 0, "failed": 0},
                    )
                    if result.overall_status in counts:
                        counts[result.overall_status] += 1
        for source in self.sources:
            row = report_sources.get(source.source_id)
            live = self.parsed_by_id.get(source.source_id)
            if row is None and live is None:
                values = (source.name, source.kind, "не проверен", "—", "—", "—", "—", "—", "—")
            elif row is None:
                assert live is not None
                values = (
                    source.name,
                    source.kind,
                    f"{live.fetch_status} / {live.parse_status}",
                    live.total_entries,
                    "—", "—", "—",
                    live.error_code or "—",
                    live.checked_at or "—",
                )
            else:
                counts = report_counts.get(
                    source.source_id,
                    {"good": 0, "partial": 0, "failed": 0},
                )
                values = (
                    source.name,
                    source.kind,
                    f"{row.fetch_status} / {row.parse_status}",
                    row.total_entries,
                    counts["good"],
                    counts["partial"],
                    counts["failed"],
                    row.error_code or "—",
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

    @staticmethod
    def _service_cell(result: mihomo_checker.ServiceResult | None) -> str:
        if result is None:
            return "—"
        if result.status == "reachable":
            return f"доступен · {result.latency_ms} ms" if result.latency_ms is not None else "доступен"
        return result.error_code or "ошибка"

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
            f"{node.server}:{node.port or '—'}",
            result.overall_status,
            result.base_latency_ms if result.base_latency_ms is not None else "—",
        ]
        values.extend(
            self._service_cell(result.services.get(item.name))
            for item in mihomo_checker.SERVICE_DEFINITIONS
        )
        values.append(result.error_code or "—")
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
        if "доступен" in text and latency is not None:
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

    def _settings(self) -> tuple[int, int, int, int | None] | None:
        try:
            attempts = int(self.attempts_var.get())
            timeout = int(self.timeout_var.get())
            workers = int(self.workers_var.get())
            limit_text = self.node_limit_var.get()
            node_limit = None if limit_text == "Все" else int(limit_text)
        except (ValueError, tk.TclError):
            messagebox.showerror("WireVeil Checker", "Проверьте числовые параметры Mihomo.")
            return None
        if (
            not 2 <= attempts <= 5
            or not 1 <= timeout <= 60
            or not 1 <= workers <= 32
            or node_limit not in {None, 50, 100, 500}
        ):
            messagebox.showerror(
                "WireVeil Checker",
                "HTTPS-прогоны: 2–5, тайм-аут: 1–60 сек, параллельность: 1–32, узлов: 50/100/500/Все.",
            )
            return None
        return attempts, timeout, workers, node_limit

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
        attempts, timeout, workers, node_limit = settings
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
        self._set_running_controls(True)
        self._set_export_buttons(False)
        limit_label = "всех узлов" if node_limit is None else f"первых {node_limit} узлов"
        self.status_var.set(
            f"Загрузка {len(sources)} источников; режим проверки: {limit_label}…"
        )

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
            self.stop_button.configure(state="disabled")
            self.stop_requested = True
            self.active_progress = None
            runner.stop()

    def _poll_events(self) -> None:
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
        self.after(delay, self._poll_events)

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
        }
        cancelled = any(
            result.error_code == "CANCELLED" for result in report.node_results
        ) or any(parsed.fetch_status == "cancelled" for parsed in report.sources)
        if cancelled:
            self.status_var.set(
                "Проверка остановлена. Доступные частичные результаты можно экспортировать."
            )
        else:
            self.status_var.set(
                "Пакетная проверка завершена. Результаты относятся к текущей сети ПК."
            )
        self.summary_var.set(
            f"Узлов {totals['unique_nodes']} · good {totals['good']} · partial {totals['partial']} · failed {totals['failed']} · not tested {totals['not_tested']}"  # type: ignore[index]
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
        messagebox.showerror("WireVeil Checker", detail)

    def _set_running_controls(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        self.start_all_button.configure(state=state)
        self.start_selected_button.configure(state=state)
        self.stop_button.configure(state="normal" if running else "disabled")
        self.node_limit.configure(state="disabled" if running else "readonly")

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

    def close(self) -> None:
        self.closing = True
        runner = self.runner
        if runner is not None:
            runner.stop()
        self._save_sources()
