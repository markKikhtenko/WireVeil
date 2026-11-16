"""Tkinter tab for building a checked local Mihomo router subscription."""

from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from mihomo_tab import _MultilineDialog, find_mihomo
from router_subscription import (
    DEFAULT_PORT,
    RouterSubscriptionServer,
    build_router_yaml,
    new_subscription_token,
    valid_subscription_token,
)
from scripts import mihomo_checker
from wireveil_paths import user_data_file


SOURCES_FILENAME = "WireVeilChecker.router-sources.json"
SETTINGS_FILENAME = "WireVeilChecker.router-ui.json"
OUTPUT_FILENAME = "WireVeilChecker.router-subscription.yaml"


def load_router_settings(path: Path) -> dict[str, object]:
    raw: dict[str, object] = {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            raw = loaded
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
    port = raw.get("port")
    attempts = raw.get("attempts")
    timeout = raw.get("timeout")
    workers = raw.get("workers")
    token = raw.get("token")
    enabled = raw.get("enabled_source_ids")
    return {
        "port": port if isinstance(port, int) and 1 <= port <= 65535 else DEFAULT_PORT,
        "attempts": attempts if isinstance(attempts, int) and 2 <= attempts <= 5 else 2,
        "timeout": timeout if isinstance(timeout, int) and 1 <= timeout <= 60 else 8,
        "workers": workers if workers in mihomo_checker.BASE_WORKERS_ALLOWED else mihomo_checker.BASE_WORKERS_DEFAULT,
        "token": token if valid_subscription_token(token) else new_subscription_token(),
        "server_enabled": (
            raw.get("server_enabled")
            if isinstance(raw.get("server_enabled"), bool)
            else True
        ),
        "enabled_source_ids": (
            [item for item in enabled if isinstance(item, str)]
            if isinstance(enabled, list)
            else None
        ),
    }


def save_router_settings(path: Path, settings: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


class RouterSubscriptionTab(ttk.Frame):
    """Build and serve a merged Mihomo YAML subscription without network probes."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, padding=6)
        self.sources_path = user_data_file(SOURCES_FILENAME)
        self.settings_path = user_data_file(SETTINGS_FILENAME)
        self.output_path = user_data_file(OUTPUT_FILENAME)
        self.sources = mihomo_checker.load_source_specs(self.sources_path)
        saved = load_router_settings(self.settings_path)
        saved_enabled = saved["enabled_source_ids"]
        self.enabled_source_ids = (
            set(saved_enabled) if isinstance(saved_enabled, list)
            else {item.source_id for item in self.sources}
        )
        self.server_enabled = bool(saved["server_enabled"])
        self.token = str(saved["token"])
        self.server = RouterSubscriptionServer(self.token)
        self.events: queue.Queue[tuple[object, ...]] = queue.Queue()
        self.runner: mihomo_checker.BatchRunner | None = None
        self.report: mihomo_checker.BatchReport | None = None
        self.running = False
        self.stop_requested = False
        self.closing = False
        self.poll_job: str | None = None

        self.port_var = tk.IntVar(value=int(saved["port"]))
        self.progress_var = tk.DoubleVar(value=0)
        self.status_var = tk.StringVar(value="Выберите источники и соберите локальную подписку.")
        self.summary_var = tk.StringVar(value="Рабочий YAML ещё не собран")
        self.output_var = tk.StringVar(value=str(self.output_path))
        self.url_var = tk.StringVar(value="Сервер остановлен")

        self._configure_styles()
        self._build_ui()
        self._refresh_sources()
        self._load_existing_output()
        self.poll_job = self.after(100, self._poll_events)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.configure("Router.TFrame", background="#0d1117")
        style.configure(
            "Router.Panel.TFrame", background="#161b22", borderwidth=1,
            bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d", relief="solid",
        )
        style.configure("Router.PanelBody.TFrame", background="#161b22")
        style.configure("Router.TLabel", background="#0d1117", foreground="#f0f6fc", font=("Segoe UI", 10))
        style.configure("Router.Dim.TLabel", background="#0d1117", foreground="#8b949e", font=("Segoe UI", 9))
        style.configure("Router.Panel.TLabel", background="#161b22", foreground="#f0f6fc", font=("Segoe UI", 10))
        style.configure("Router.PanelDim.TLabel", background="#161b22", foreground="#8b949e", font=("Segoe UI", 9))
        style.configure("Router.Section.TLabel", background="#161b22", foreground="#f0f6fc", font=("Segoe UI Semibold", 11))
        style.configure("Router.TButton", font=("Segoe UI", 10), padding=(9, 6))
        style.configure("Router.Accent.TButton", font=("Segoe UI Semibold", 10), padding=(11, 7))
        style.configure(
            "Router.TEntry", font=("Segoe UI", 10), padding=4,
            fieldbackground="#0d1117", foreground="#f0f6fc", insertcolor="#f0f6fc",
            bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d",
        )
        style.map(
            "Router.TEntry",
            fieldbackground=[("readonly", "#0d1117"), ("disabled", "#0d1117")],
            foreground=[("readonly", "#c9d1d9"), ("disabled", "#6e7681")],
        )
        style.configure(
            "Router.TSpinbox", font=("Segoe UI", 10), padding=4,
            fieldbackground="#0d1117", foreground="#f0f6fc", insertcolor="#f0f6fc",
            background="#21262d", arrowcolor="#c9d1d9",
            bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d",
        )
        style.map(
            "Router.TSpinbox",
            fieldbackground=[("disabled", "#0d1117")],
            foreground=[("disabled", "#6e7681")],
        )
        style.configure(
            "Router.TCombobox", font=("Segoe UI", 10), padding=4,
            fieldbackground="#0d1117", foreground="#f0f6fc", background="#21262d",
            arrowcolor="#c9d1d9", selectbackground="#1f6feb", selectforeground="#ffffff",
            bordercolor="#30363d", lightcolor="#30363d", darkcolor="#30363d",
        )
        style.map(
            "Router.TCombobox",
            fieldbackground=[("readonly", "#0d1117"), ("disabled", "#0d1117")],
            foreground=[("readonly", "#f0f6fc"), ("disabled", "#6e7681")],
            selectbackground=[("readonly", "#0d1117")],
            selectforeground=[("readonly", "#f0f6fc")],
        )
        style.configure(
            "Router.Treeview", font=("Segoe UI", 10), rowheight=28,
            background="#0d1117", fieldbackground="#0d1117", foreground="#c9d1d9", borderwidth=0,
        )
        style.configure(
            "Router.Treeview.Heading", font=("Segoe UI Semibold", 9), padding=(6, 7),
            background="#161b22", foreground="#c9d1d9", relief="flat",
        )
        style.map("Router.Treeview", background=[("selected", "#1f6feb")], foreground=[("selected", "#ffffff")])

    def _build_ui(self) -> None:
        self.configure(style="Router.TFrame")
        header = ttk.Frame(self, style="Router.TFrame")
        header.pack(fill="x", pady=(0, 5))
        ttk.Label(
            header, text="Сборка подписки для роутера", style="Router.TLabel",
            font=("Segoe UI Semibold", 13),
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Объединяет выбранные источники без сетевой проверки и собирает Mihomo-конфиг с группами AUTO, MANUAL и PROXY.",
            style="Router.Dim.TLabel",
        ).pack(anchor="w")

        source_panel = ttk.Frame(self, style="Router.Panel.TFrame", padding=(9, 7))
        source_panel.pack(fill="both", expand=True, pady=(0, 6))
        toolbar = ttk.Frame(source_panel, style="Router.PanelBody.TFrame")
        toolbar.pack(fill="x", pady=(0, 6))
        ttk.Label(toolbar, text="1. Источники", style="Router.Section.TLabel").pack(side="left")
        self.add_menu = tk.Menu(
            self, tearoff=False, background="#161b22", foreground="#f0f6fc",
            activebackground="#1f6feb", activeforeground="#ffffff",
        )
        for label, command in (
            ("Один URL", self._add_url),
            ("Несколько URL", self._add_urls),
            ("Файл или каталог…", self._add_files),
            ("Вставить YAML", self._add_text),
        ):
            self.add_menu.add_command(label=label, command=command)
        self.add_button = ttk.Menubutton(toolbar, text="＋ Добавить", menu=self.add_menu, style="Router.TButton")
        self.add_button.pack(side="right")
        self.delete_button = ttk.Button(toolbar, text="Удалить", command=self._delete_selected, style="Router.TButton")
        self.delete_button.pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text="Снять все", command=lambda: self._select_sources(False), style="Router.TButton").pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text="Выбрать все", command=lambda: self._select_sources(True), style="Router.TButton").pack(side="right", padx=(6, 0))

        tree_frame = ttk.Frame(source_panel, style="Router.PanelBody.TFrame")
        tree_frame.pack(fill="both", expand=True)
        self.source_tree = ttk.Treeview(
            tree_frame, columns=("enabled", "name", "kind", "source"), show="headings",
            height=2, selectmode="extended", style="Router.Treeview",
        )
        for column, text, width, anchor in (
            ("enabled", "В сборку", 80, "center"),
            ("name", "Название", 250, "w"),
            ("kind", "Тип", 80, "center"),
            ("source", "Источник", 520, "w"),
        ):
            self.source_tree.heading(column, text=text)
            self.source_tree.column(column, width=width, minwidth=60, anchor=anchor, stretch=column in {"name", "source"})
        source_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.source_tree.yview)
        self.source_tree.configure(yscrollcommand=source_scroll.set)
        self.source_tree.pack(side="left", fill="both", expand=True)
        source_scroll.pack(side="right", fill="y")
        self.source_tree.bind("<Button-1>", self._source_click, add="+")
        self.source_tree.bind("<Double-1>", self._source_double_click, add="+")
        self.source_tree.bind("<<TreeviewSelect>>", lambda _event: self._update_controls())
        ttk.Label(
            source_panel,
            text="Нажмите в столбце «В сборку» или дважды по строке, чтобы включить/исключить источник.",
            style="Router.PanelDim.TLabel",
        ).pack(anchor="w", pady=(5, 0))

        run_panel = ttk.Frame(self, style="Router.Panel.TFrame", padding=(9, 7))
        run_panel.pack(fill="x", pady=(0, 6))
        ttk.Label(run_panel, text="2. Подготовка и сборка", style="Router.Section.TLabel").grid(row=0, column=0, sticky="w")
        settings = ttk.Frame(run_panel, style="Router.PanelBody.TFrame")
        settings.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(
            settings,
            text="Без сетевой проверки · доступность узлов определит AUTO на роутере",
            style="Router.PanelDim.TLabel",
        ).pack(side="left")
        self.stop_button = ttk.Button(settings, text="Остановить", command=self.stop, state="disabled", style="Router.TButton")
        self.stop_button.pack(side="right")
        self.build_button = ttk.Button(settings, text="Собрать подписку", command=self._start_build, style="Router.Accent.TButton")
        self.build_button.pack(side="right", padx=(0, 6))
        ttk.Progressbar(run_panel, variable=self.progress_var, maximum=100).grid(row=2, column=0, sticky="ew", pady=(8, 3))
        ttk.Label(run_panel, textvariable=self.status_var, style="Router.PanelDim.TLabel").grid(row=3, column=0, sticky="w")
        ttk.Label(run_panel, textvariable=self.summary_var, style="Router.Panel.TLabel").grid(row=4, column=0, sticky="w", pady=(3, 0))
        run_panel.columnconfigure(0, weight=1)

        output_panel = ttk.Frame(self, style="Router.Panel.TFrame", padding=(9, 7))
        output_panel.pack(fill="x")
        ttk.Label(output_panel, text="3. Готовая подписка", style="Router.Section.TLabel").grid(row=0, column=0, columnspan=5, sticky="w")
        ttk.Label(output_panel, text="YAML-файл", style="Router.Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(7, 0))
        ttk.Entry(output_panel, textvariable=self.output_var, state="readonly", style="Router.TEntry").grid(row=1, column=1, columnspan=2, sticky="ew", padx=7, pady=(7, 0))
        self.save_button = ttk.Button(output_panel, text="Сохранить как…", command=self._save_as, state="disabled", style="Router.TButton")
        self.save_button.grid(row=1, column=3, columnspan=2, sticky="e", pady=(7, 0))
        ttk.Label(output_panel, text="Порт", style="Router.Panel.TLabel").grid(row=2, column=0, sticky="w", pady=(7, 0))
        self.port_box = ttk.Spinbox(output_panel, from_=1024, to=65535, textvariable=self.port_var, width=8, style="Router.TSpinbox")
        self.port_box.grid(row=2, column=1, sticky="w", padx=7, pady=(7, 0))
        self.server_button = ttk.Button(output_panel, text="Запустить сервер", command=self._toggle_server, state="disabled", style="Router.TButton")
        self.server_button.grid(row=2, column=2, sticky="w", pady=(7, 0))
        self.copy_button = ttk.Button(output_panel, text="Копировать URL", command=self._copy_url, state="disabled", style="Router.TButton")
        self.copy_button.grid(row=2, column=3, sticky="e", padx=(7, 0), pady=(7, 0))
        ttk.Entry(output_panel, textvariable=self.url_var, state="readonly", style="Router.TEntry").grid(row=3, column=0, columnspan=5, sticky="ew", pady=(7, 0))
        ttk.Label(
            output_panel,
            text="URL доступен роутеру только пока WireVeil Checker запущен. Разрешайте доступ в брандмауэре только для частной сети.",
            style="Router.PanelDim.TLabel",
        ).grid(row=4, column=0, columnspan=5, sticky="w", pady=(5, 0))
        output_panel.columnconfigure(2, weight=1)
        output_panel.columnconfigure(1, weight=1)

    def _dialog_text(
        self,
        title: str,
        prompt: str,
        *,
        multiline: bool = True,
        submit_on_enter: bool = False,
    ) -> str | None:
        dialog = _MultilineDialog(
            self, title, prompt, multiline=multiline, submit_on_enter=submit_on_enter,
        )
        self.wait_window(dialog)
        return dialog.result

    def _append_sources(self, additions: list[mihomo_checker.SourceSpec]) -> None:
        existing_urls = {
            mihomo_checker.canonical_source_url(item.value)
            for item in self.sources if item.kind == "url"
        }
        accepted: list[mihomo_checker.SourceSpec] = []
        for item in additions:
            if item.kind == "url":
                canonical = mihomo_checker.canonical_source_url(item.value)
                if canonical in existing_urls:
                    continue
                existing_urls.add(canonical)
            accepted.append(item)
        if len(self.sources) + len(accepted) > mihomo_checker.MAX_SOURCES:
            messagebox.showerror("WireVeil Checker", "Допускается не более 200 источников.", parent=self)
            return
        self.sources.extend(accepted)
        self.enabled_source_ids.update(item.source_id for item in accepted)
        self._save_sources()
        self._save_settings()
        self._refresh_sources()
        self.status_var.set(f"Добавлено источников: {len(accepted)}.")

    def _add_url(self) -> None:
        value = self._dialog_text("Добавить URL", "URL Mihomo/Clash YAML подписки:", multiline=False)
        if not value:
            return
        url = value.strip()
        if mihomo_checker.subscription_urls_from_text(url) is None:
            messagebox.showerror("WireVeil Checker", "Нужен корректный HTTP(S) URL подписки.", parent=self)
            return
        self._append_sources([
            mihomo_checker.SourceSpec(
                mihomo_checker.new_source_id(), mihomo_checker.source_name_from_url(url), "url", url,
            )
        ])

    def _add_urls(self) -> None:
        value = self._dialog_text(
            "Добавить URLs списком", "По одному HTTP(S) URL на строку.", submit_on_enter=True,
        )
        if not value:
            return
        urls = mihomo_checker.subscription_urls_from_text(value)
        if urls is None:
            messagebox.showerror("WireVeil Checker", "Список содержит некорректный URL.", parent=self)
            return
        self._append_sources([
            mihomo_checker.SourceSpec(
                mihomo_checker.new_source_id(), mihomo_checker.source_name_from_url(url), "url", url,
            )
            for url in urls
        ])

    def _add_files(self) -> None:
        names = filedialog.askopenfilenames(
            parent=self, title="Добавить Mihomo/Clash YAML",
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
            messagebox.showwarning("WireVeil Checker", "\n".join(errors), parent=self)

    def _add_text(self) -> None:
        name = simpledialog.askstring("Имя источника", "Имя / метка подписки:", parent=self)
        if not name or not name.strip():
            return
        value = self._dialog_text("Вставить подписку", "Вставьте Mihomo/Clash YAML. Данные сохраняются только локально.")
        if value:
            self._append_sources([
                mihomo_checker.SourceSpec(mihomo_checker.new_source_id(), name.strip(), "text", value)
            ])

    def _source_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if self.running or self.source_tree.identify_column(event.x) != "#1":
            return
        source_id = self.source_tree.identify_row(event.y)
        if source_id:
            self._toggle_source(source_id)

    def _source_double_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if self.running:
            return
        source_id = self.source_tree.identify_row(event.y)
        if source_id:
            self._toggle_source(source_id)

    def _toggle_source(self, source_id: str) -> None:
        if source_id in self.enabled_source_ids:
            self.enabled_source_ids.remove(source_id)
        else:
            self.enabled_source_ids.add(source_id)
        self._save_settings()
        self._refresh_sources()

    def _select_sources(self, enabled: bool) -> None:
        if self.running:
            return
        self.enabled_source_ids = {item.source_id for item in self.sources} if enabled else set()
        self._save_settings()
        self._refresh_sources()

    def _delete_selected(self) -> None:
        selected = set(self.source_tree.selection())
        if self.running or not selected:
            return
        self.sources = [item for item in self.sources if item.source_id not in selected]
        self.enabled_source_ids.difference_update(selected)
        self._save_sources()
        self._save_settings()
        self._refresh_sources()

    def _refresh_sources(self) -> None:
        selected = set(self.source_tree.selection()) if hasattr(self, "source_tree") else set()
        self.source_tree.delete(*self.source_tree.get_children())
        valid_ids = {item.source_id for item in self.sources}
        self.enabled_source_ids.intersection_update(valid_ids)
        for source in self.sources:
            self.source_tree.insert(
                "", "end", iid=source.source_id,
                values=("✓" if source.source_id in self.enabled_source_ids else "—", source.name, source.kind.upper(), source.display),
            )
        for source_id in selected:
            if self.source_tree.exists(source_id):
                self.source_tree.selection_add(source_id)
        self._update_controls()

    def _update_controls(self) -> None:
        editable = not self.running
        enabled_count = len(self.enabled_source_ids)
        self.add_button.configure(state="normal" if editable else "disabled")
        self.delete_button.configure(state="normal" if editable and self.source_tree.selection() else "disabled")
        self.build_button.configure(state="normal" if editable and enabled_count else "disabled")
        self.stop_button.configure(state="normal" if self.running else "disabled")

    def _start_build(self) -> None:
        if self.running:
            return
        sources = tuple(item for item in self.sources if item.source_id in self.enabled_source_ids)
        if not sources:
            messagebox.showinfo("WireVeil Checker", "Выберите хотя бы один источник.", parent=self)
            return
        binary = find_mihomo()
        if binary is None:
            messagebox.showerror(
                "WireVeil Checker", "Не найден mihomo.exe. В сборке он должен находиться рядом с приложением.", parent=self,
            )
            return
        self._save_settings()
        self.runner = mihomo_checker.BatchRunner()
        self.running = True
        self.stop_requested = False
        self.report = None
        self.progress_var.set(0)
        self.status_var.set("Загружаю и объединяю выбранные источники…")
        self.summary_var.set(f"Источников в сборке: {len(sources)} · сетевая проверка отключена")
        self._update_controls()

        def work() -> None:
            assert self.runner is not None
            try:
                report = self.runner.run(
                    binary=binary,
                    source_specs=sources,
                    selected_services=(),
                    node_limit=None,
                    per_source_limit=None,
                    check_connectivity=False,
                    progress_callback=lambda update: self.events.put(("progress", update)),
                )
                self.events.put(("done", report))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=work, name="wireveil-router-build", daemon=True).start()

    def stop(self) -> None:
        if self.runner is not None:
            self.stop_requested = True
            self.status_var.set("Останавливаю проверку…")
            self.runner.stop()

    def _poll_events(self) -> None:
        self.poll_job = None
        if self.closing:
            return
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    update = event[1]
                    assert isinstance(update, mihomo_checker.ProgressUpdate)
                    self.progress_var.set(update.overall_percent)
                    self.status_var.set(update.message)
                elif event[0] == "done":
                    report = event[1]
                    assert isinstance(report, mihomo_checker.BatchReport)
                    self._finish_build(report)
                elif event[0] == "error":
                    self._finish_error(event[1])
        except queue.Empty:
            pass
        self.poll_job = self.after(75 if self.running else 200, self._poll_events)

    def _finish_build(self, report: mihomo_checker.BatchReport) -> None:
        self.running = False
        self.runner = None
        self.report = report
        if self.stop_requested:
            self.status_var.set("Проверка остановлена. Предыдущая подписка не изменена.")
            self.summary_var.set("Сборка отменена")
            self._update_controls()
            return
        try:
            payload = build_router_yaml(report, self.output_path)
        except (OSError, mihomo_checker.MihomoCheckError) as exc:
            self.status_var.set("Проверка завершена, но собрать YAML не удалось.")
            self.summary_var.set(str(exc))
            self._update_controls()
            messagebox.showerror("WireVeil Checker", f"Не удалось собрать подписку: {exc}", parent=self)
            return
        self.server.set_content(payload)
        included = sum(
            item.overall_status in {"good", "ready"}
            for item in report.node_results
        )
        total = len(report.node_results)
        self.progress_var.set(100)
        self.status_var.set("Конфиг с группами AUTO / MANUAL / PROXY собран без сетевой проверки; локальный сервер запускается.")
        self.summary_var.set(f"Готово: добавлено {included} из {total} уникальных узлов")
        self.save_button.configure(state="normal")
        self.server_button.configure(state="normal")
        self._start_server(show_error=False)
        self._update_controls()

    def _finish_error(self, error: object) -> None:
        self.running = False
        self.runner = None
        self.status_var.set("Сборка завершилась с ошибкой.")
        self.summary_var.set(mihomo_checker.sanitize_text(error))
        self._update_controls()
        messagebox.showerror("WireVeil Checker", f"Не удалось проверить источники: {error}", parent=self)

    def _load_existing_output(self) -> None:
        try:
            payload = self.output_path.read_bytes()
        except OSError:
            return
        if not payload:
            return
        try:
            self.server.set_content(payload)
        except ValueError:
            return
        self.summary_var.set("Найдена ранее собранная локальная подписка")
        self.save_button.configure(state="normal")
        self.server_button.configure(state="normal")
        if self.server_enabled:
            self._start_server(show_error=False)

    def _toggle_server(self) -> None:
        if self.server.running:
            self.server.stop()
            self.server_enabled = False
            self.url_var.set("Сервер остановлен")
            self.server_button.configure(text="Запустить сервер")
            self.copy_button.configure(state="disabled")
            self.port_box.configure(state="normal")
            self._save_settings()
            return
        self._start_server(show_error=True)

    def _start_server(self, *, show_error: bool) -> None:
        try:
            port = int(self.port_var.get())
            url = self.server.start(port)
        except (OSError, ValueError, tk.TclError) as exc:
            self.url_var.set("Сервер не запущен")
            if show_error:
                messagebox.showerror(
                    "WireVeil Checker",
                    f"Не удалось запустить сервер на выбранном порту: {exc}",
                    parent=self,
                )
            else:
                self.status_var.set(f"YAML сохранён, но HTTP-сервер не запущен: {exc}")
            return
        self.url_var.set(url)
        self.server_enabled = True
        self.server_button.configure(text="Остановить сервер", state="normal")
        self.copy_button.configure(state="normal")
        self.port_box.configure(state="disabled")
        self._save_settings()

    def _copy_url(self) -> None:
        url = self.server.url
        if not url:
            return
        self.clipboard_clear()
        self.clipboard_append(url)
        self.status_var.set("URL локальной подписки скопирован.")

    def _save_as(self) -> None:
        if not self.output_path.is_file():
            return
        filename = filedialog.asksaveasfilename(
            parent=self, title="Сохранить подписку для роутера",
            defaultextension=".yaml", initialfile="WireVeil-router.yaml",
            filetypes=(("Mihomo YAML", "*.yaml *.yml"), ("Все файлы", "*.*")),
        )
        if not filename:
            return
        try:
            Path(filename).write_bytes(self.output_path.read_bytes())
        except OSError as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось сохранить YAML: {exc}", parent=self)
            return
        self.status_var.set(f"YAML сохранён: {filename}")

    def _save_sources(self) -> None:
        try:
            mihomo_checker.save_source_specs(self.sources_path, self.sources)
        except OSError as exc:
            messagebox.showerror("WireVeil Checker", f"Не удалось сохранить источники: {exc}", parent=self)

    def _save_settings(self) -> None:
        try:
            save_router_settings(
                self.settings_path,
                {
                    "port": int(self.port_var.get()),
                    "token": self.token,
                    "server_enabled": self.server_enabled,
                    "enabled_source_ids": sorted(self.enabled_source_ids),
                },
            )
        except (OSError, ValueError, tk.TclError):
            pass

    def close(self) -> None:
        self.closing = True
        if self.poll_job is not None:
            try:
                self.after_cancel(self.poll_job)
            except tk.TclError:
                pass
            self.poll_job = None
        if self.runner is not None:
            self.runner.stop()
        self.server.stop()
        self._save_sources()
        self._save_settings()
