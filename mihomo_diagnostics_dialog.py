"""Tkinter window for the isolated Mihomo self-diagnostic runner."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scripts import mihomo_diagnostics
from wireveil_version import APP_VERSION


class MihomoDiagnosticsDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        binary_finder: Callable[[], Path | None],
        *,
        on_closed: Callable[[], None] | None = None,
    ):
        super().__init__(parent)
        self.binary_finder = binary_finder
        self.on_closed = on_closed
        self.runner: mihomo_diagnostics.MihomoDiagnosticRunner | None = None
        self.report: mihomo_diagnostics.DiagnosticReport | None = None
        self.events: queue.Queue[tuple[object, ...]] = queue.Queue()
        self._closed = False
        self._poll_job: str | None = None

        self.title("Диагностика Mihomo — WireVeil")
        self.geometry("1080x680")
        self.minsize(820, 520)
        self.transient(parent.winfo_toplevel())
        self.configure(background="#0d1117")
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._build_ui()
        self._poll_job = self.after(50, self._poll_events)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=14, style="Mihomo.TFrame")
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root, style="Mihomo.TFrame")
        header.pack(fill="x", pady=(0, 10))
        copy = ttk.Frame(header, style="Mihomo.TFrame")
        copy.pack(side="left", fill="x", expand=True)
        ttk.Label(
            copy,
            text="Диагностика Mihomo",
            style="Mihomo.TLabel",
            font=("Segoe UI Semibold", 14),
        ).pack(anchor="w")
        ttk.Label(
            copy,
            text=(
                "Изолированная проверка ядра, локального API и пяти HTTPS-сайтов. "
                "Подписки и системный прокси не используются."
            ),
            style="Mihomo.Dim.TLabel",
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))
        self.start_button = ttk.Button(
            header,
            text="▶ Запустить диагностику",
            command=self.start,
            style="Mihomo.Accent.TButton",
        )
        self.start_button.pack(side="right", padx=(10, 0))

        progress_panel = ttk.Frame(root, padding=(12, 9), style="Mihomo.Card.TFrame")
        progress_panel.pack(fill="x", pady=(0, 10))
        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(
            progress_panel,
            variable=self.progress_var,
            maximum=mihomo_diagnostics.MihomoDiagnosticRunner.TOTAL_CHECKS,
            mode="determinate",
        )
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Готово к запуску.")
        ttk.Label(
            progress_panel,
            textvariable=self.status_var,
            style="Mihomo.PanelDim.TLabel",
        ).pack(anchor="w", pady=(5, 0))

        table_panel = ttk.Frame(root, style="Mihomo.Card.TFrame")
        table_panel.pack(fill="both", expand=True)
        table_panel.columnconfigure(0, weight=1)
        table_panel.rowconfigure(0, weight=1)
        columns = ("group", "check", "status", "http", "elapsed", "detail")
        self.table = ttk.Treeview(
            table_panel,
            columns=columns,
            show="headings",
            style="Mihomo.Treeview",
        )
        headings = {
            "group": "Раздел",
            "check": "Проверка",
            "status": "Статус",
            "http": "HTTP",
            "elapsed": "Время",
            "detail": "Причина / результат",
        }
        widths = {
            "group": 80,
            "check": 225,
            "status": 82,
            "http": 70,
            "elapsed": 84,
            "detail": 460,
        }
        for column in columns:
            self.table.heading(column, text=headings[column])
            self.table.column(
                column,
                width=widths[column],
                minwidth=60,
                stretch=column in {"check", "detail"},
                anchor="w" if column not in {"status", "http", "elapsed"} else "center",
            )
        self.table.tag_configure("PASS", foreground="#3fb950")
        self.table.tag_configure("FAIL", foreground="#f85149")
        self.table.tag_configure("TIMEOUT", foreground="#ff7b72")
        self.table.tag_configure("WARNING", foreground="#d29922")
        self.table.tag_configure("SKIPPED", foreground="#8b949e")
        y_scroll = ttk.Scrollbar(table_panel, orient="vertical", command=self.table.yview)
        x_scroll = ttk.Scrollbar(table_panel, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        conclusion_panel = ttk.Frame(root, padding=(12, 9), style="Mihomo.Card.TFrame")
        conclusion_panel.pack(fill="x", pady=(10, 0))
        ttk.Label(
            conclusion_panel,
            text="Заключение",
            style="Mihomo.Section.TLabel",
        ).pack(anchor="w")
        self.conclusion_var = tk.StringVar(value="Заключение появится после завершения.")
        ttk.Label(
            conclusion_panel,
            textvariable=self.conclusion_var,
            style="Mihomo.PanelDim.TLabel",
            wraplength=980,
            justify="left",
        ).pack(anchor="w", fill="x", pady=(3, 0))

        actions = ttk.Frame(root, style="Mihomo.TFrame")
        actions.pack(fill="x", pady=(10, 0))
        self.copy_button = ttk.Button(
            actions,
            text="Скопировать отчёт",
            command=self._copy_report,
            state="disabled",
            style="Mihomo.TButton",
        )
        self.copy_button.pack(side="left")
        self.save_button = ttk.Button(
            actions,
            text="Сохранить отчёт",
            command=self._save_report,
            state="disabled",
            style="Mihomo.TButton",
        )
        self.save_button.pack(side="left", padx=(6, 0))
        ttk.Button(
            actions,
            text="Закрыть",
            command=self.close,
            style="Mihomo.TButton",
        ).pack(side="right")

    def start(self) -> None:
        if self.runner is not None:
            return
        self.report = None
        self.progress_var.set(0)
        self.conclusion_var.set("Диагностика выполняется…")
        self.status_var.set("Подготовка изолированного экземпляра Mihomo…")
        self.copy_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        for item in self.table.get_children(""):
            self.table.delete(item)

        runner = mihomo_diagnostics.MihomoDiagnosticRunner(
            self.binary_finder(),
            APP_VERSION,
        )
        self.runner = runner

        def progress(
            result: mihomo_diagnostics.DiagnosticResult,
            completed: int,
            total: int,
        ) -> None:
            self.events.put(("result", result, completed, total))

        def worker() -> None:
            try:
                report = runner.run(progress)
            except BaseException as exc:
                self.events.put(("error", exc))
            else:
                self.events.put(("complete", report))

        threading.Thread(target=worker, name="mihomo-diagnostics", daemon=True).start()

    def _poll_events(self) -> None:
        self._poll_job = None
        if self._closed:
            return
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            kind = event[0]
            if kind == "result":
                result = event[1]
                assert isinstance(result, mihomo_diagnostics.DiagnosticResult)
                completed = int(event[2])
                total = int(event[3])
                self._append_result(result)
                self.progress.configure(maximum=total)
                self.progress_var.set(completed)
                self.status_var.set(f"Выполнено {completed} из {total}: {result.check}")
            elif kind == "complete":
                report = event[1]
                assert isinstance(report, mihomo_diagnostics.DiagnosticReport)
                self.report = report
                self.runner = None
                self.progress_var.set(mihomo_diagnostics.MihomoDiagnosticRunner.TOTAL_CHECKS)
                self.status_var.set("Диагностика завершена; временный процесс и файлы удалены.")
                self.conclusion_var.set(report.conclusion)
                self.copy_button.configure(state="normal")
                self.save_button.configure(state="normal")
                self.start_button.configure(state="normal")
            elif kind == "error":
                self.runner = None
                self.start_button.configure(state="normal")
                detail = str(event[1])
                self.status_var.set(f"Ошибка диагностики: {detail}")
                self.conclusion_var.set("Диагностика не завершена.")
                messagebox.showerror("Диагностика Mihomo", detail, parent=self)
        if not self._closed:
            self._poll_job = self.after(50, self._poll_events)

    def _append_result(self, result: mihomo_diagnostics.DiagnosticResult) -> None:
        self.table.insert(
            "",
            "end",
            values=(
                result.group,
                result.check,
                result.status,
                result.http_status if result.http_status is not None else "—",
                f"{result.elapsed_ms} ms" if result.elapsed_ms is not None else "—",
                result.detail,
            ),
            tags=(result.status,),
        )
        children = self.table.get_children("")
        if children:
            self.table.see(children[-1])

    def _copy_report(self) -> None:
        if self.report is None:
            return
        self.clipboard_clear()
        self.clipboard_append(self.report.to_text())
        self.update_idletasks()
        self.status_var.set("Отчёт скопирован в буфер обмена.")

    def _save_report(self) -> None:
        if self.report is None:
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = filedialog.asksaveasfilename(
            parent=self,
            title="Сохранить отчёт диагностики Mihomo",
            defaultextension=".txt",
            initialfile=f"WireVeil-Mihomo-Diagnostics-{stamp}.txt",
            filetypes=(("Текстовый отчёт", "*.txt"), ("JSON", "*.json")),
        )
        if not filename:
            return
        path = Path(filename)
        content = self.report.to_json() if path.suffix.casefold() == ".json" else self.report.to_text()
        try:
            path.write_text(content, encoding="utf-8", newline="\n")
        except OSError as exc:
            messagebox.showerror(
                "Диагностика Mihomo",
                f"Не удалось сохранить отчёт: {exc}",
                parent=self,
            )
            return
        self.status_var.set(f"Отчёт сохранён: {path.name}")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        runner = self.runner
        if runner is not None:
            runner.cancel()
        if self._poll_job is not None:
            try:
                self.after_cancel(self._poll_job)
            except tk.TclError:
                pass
            self._poll_job = None
        callback = self.on_closed
        self.on_closed = None
        try:
            self.destroy()
        finally:
            if callback is not None:
                callback()
