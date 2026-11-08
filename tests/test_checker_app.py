import json
import queue
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from tkinter import ttk
from unittest import mock

from checker_app import (
    DEFAULT_SORT_COLUMN,
    DEFAULT_SORT_DESCENDING,
    SERVICE_COLUMN_BY_NAME,
    TABLE_COLUMN_POSITIONS,
    TABLE_COLUMNS,
    _UpdateDialog,
    WireVeilChecker,
    find_app_icon,
    load_checker_settings,
    load_checker_results,
    write_checker_results,
    write_checker_settings,
)
from scripts import app_updater, healthcheck, local_checker, network_check
from wireveil_version import APP_VERSION


class TableSortTests(unittest.TestCase):
    @staticmethod
    def row(service_name: str, value: str) -> tuple[str, ...]:
        values = ["—"] * len(TABLE_COLUMNS)
        values[TABLE_COLUMN_POSITIONS[SERVICE_COLUMN_BY_NAME[service_name]]] = value
        return tuple(values)

    def test_service_column_sorts_available_by_latency(self):
        column = SERVICE_COLUMN_BY_NAME["ChatGPT"]
        fast = self.row("ChatGPT", "доступен · 95 ms")
        slow = self.row("ChatGPT", "доступен · 240 ms")
        self.assertLess(
            WireVeilChecker._column_sort_value(column, fast),
            WireVeilChecker._column_sort_value(column, slow),
        )

    def test_service_restriction_sorts_after_available(self):
        column = SERVICE_COLUMN_BY_NAME["YouTube"]
        available = self.row("YouTube", "доступен · 95 ms")
        restricted = self.row("YouTube", "HTTP 403 · 70 ms")
        self.assertLess(
            WireVeilChecker._column_sort_value(column, available),
            WireVeilChecker._column_sort_value(column, restricted),
        )

    def test_reached_chatgpt_domain_sorts_as_available(self):
        column = SERVICE_COLUMN_BY_NAME["ChatGPT"]
        reached = self.row("ChatGPT", "домен отвечает · HTTP 403 · 70 ms")
        restricted = self.row("ChatGPT", "HTTP 403 · 50 ms")
        self.assertLess(
            WireVeilChecker._column_sort_value(column, reached),
            WireVeilChecker._column_sort_value(column, restricted),
        )

    def test_reached_chatgpt_domain_has_clear_label(self):
        result = local_checker.ServiceResult(
            mock.Mock(),
            "ChatGPT",
            available=True,
            latency_ms=70,
            http_status=403,
        )
        self.assertEqual(
            "✓ 403 · 70",
            WireVeilChecker._format_service(result),
        )

    @staticmethod
    def ranked_row(
        *, number: int, passes: str, speed: str, latency: str, chatgpt: str
    ) -> tuple[str, ...]:
        values = ["—"] * len(TABLE_COLUMNS)
        values[TABLE_COLUMN_POSITIONS["number"]] = str(number)
        values[TABLE_COLUMN_POSITIONS["passes"]] = passes
        values[TABLE_COLUMN_POSITIONS["speed"]] = speed
        values[TABLE_COLUMN_POSITIONS["latency"]] = latency
        values[
            TABLE_COLUMN_POSITIONS[SERVICE_COLUMN_BY_NAME["ChatGPT"]]
        ] = chatgpt
        return tuple(values)

    def test_smart_quality_prioritizes_site_access_before_speed_and_ping(self):
        full = self.ranked_row(
            number=1,
            passes="2/2",
            speed="12.0",
            latency="240 ms",
            chatgpt="✓ 220",
        )
        partial = self.ranked_row(
            number=2,
            passes="2/2",
            speed="80.0",
            latency="40 ms",
            chatgpt="✕ 403",
        )
        self.assertLess(
            WireVeilChecker._smart_sort_value(full),
            WireVeilChecker._smart_sort_value(partial),
        )

    def test_smart_quality_uses_speed_then_ping(self):
        fast = self.ranked_row(
            number=1,
            passes="2/2",
            speed="60.0",
            latency="180 ms",
            chatgpt="✓ 100",
        )
        slow = self.ranked_row(
            number=2,
            passes="2/2",
            speed="20.0",
            latency="40 ms",
            chatgpt="✓ 100",
        )
        self.assertLess(
            WireVeilChecker._smart_sort_value(fast),
            WireVeilChecker._smart_sort_value(slow),
        )

        equally_fast = list(fast)
        equally_fast[TABLE_COLUMN_POSITIONS["speed"]] = "20.0"
        self.assertGreater(
            WireVeilChecker._smart_sort_value(tuple(equally_fast)),
            WireVeilChecker._smart_sort_value(slow),
        )


class UiResponsivenessTests(unittest.TestCase):
    def test_event_poll_yields_with_a_large_backlog(self):
        checker = object.__new__(WireVeilChecker)
        checker.events = queue.Queue()
        for index in range(100):
            checker.events.put(("network_state", index))
        checker.poll_job = None
        checker.closing = False
        checker._apply_network_status = mock.Mock()
        checker.after = mock.Mock(return_value="next-poll")

        with mock.patch("checker_app.time.perf_counter", return_value=0.0):
            checker._poll_events()

        self.assertEqual(64, checker._apply_network_status.call_count)
        self.assertEqual(36, checker.events.qsize())
        checker.after.assert_called_once_with(16, checker._poll_events)

    def test_live_updates_do_not_schedule_full_table_sort(self):
        checker = object.__new__(WireVeilChecker)
        checker.running = True
        checker.sort_column = "quality"
        checker.sort_job = None
        checker.after = mock.Mock()

        checker._schedule_resort()

        checker.after.assert_not_called()

    def test_pending_rows_are_inserted_in_bounded_batches(self):
        checker = object.__new__(WireVeilChecker)
        checker.pending_table_job = None
        checker.pending_table_lines = ()
        checker.pending_table_attempts = 0
        checker.pending_table_position = 0
        checker.table_items = {}
        checker.item_uris = {}
        checker.closing = False
        checker.running = True
        checker.sort_column = "quality"
        checker.sort_job = None
        checker.after_cancel = mock.Mock()
        checker.after_idle = mock.Mock(return_value="initial-fill")
        checker.after = mock.Mock(return_value="next-fill")
        checker.table = mock.Mock()
        checker.table.insert.side_effect = [f"row-{index}" for index in range(65)]
        lines = tuple(
            f"vless://550e8400-e29b-41d4-a716-446655440000@node-{index}.example.com:443?security=tls"
            for index in range(65)
        )

        checker._show_pending(lines, 2)
        with mock.patch("checker_app.time.perf_counter", return_value=0.0):
            checker._insert_pending_table_batch()

        self.assertEqual(64, checker.table.insert.call_count)
        self.assertEqual(64, checker.pending_table_position)
        checker.after.assert_called_once_with(16, checker._insert_pending_table_batch)


class AppIconTests(unittest.TestCase):
    def test_multisize_windows_icon_is_available(self):
        icon = find_app_icon()
        self.assertIsNotNone(icon)
        self.assertEqual("wireveil-icon.ico", icon.name)
        self.assertGreater(icon.stat().st_size, 0)


class MainUiLayoutTests(unittest.TestCase):
    def test_magic_tooltip_closes_when_switching_to_mihomo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch(
                    "checker_app.checker_settings_path",
                    return_value=root / "settings.json",
                ),
                mock.patch(
                    "checker_app.checker_results_path",
                    return_value=root / "results.json",
                ),
                mock.patch.object(
                    WireVeilChecker, "_refresh_network_status", return_value=None
                ),
            ):
                try:
                    checker = WireVeilChecker()
                except tk.TclError as exc:
                    self.skipTest(f"Tk is unavailable: {exc}")
                try:
                    checker._show_magic_button_label()
                    checker.update()
                    self.assertIsNotNone(checker.magic_tooltip)
                    self.assertIsNotNone(checker.magic_tooltip_job)

                    checker._show_engine_page("mihomo")
                    checker.update()

                    self.assertIsNone(checker.magic_tooltip)
                    self.assertIsNone(checker.magic_tooltip_job)
                finally:
                    checker._on_close()

    def test_logo_triple_click_opens_self_closing_easter_egg(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch(
                    "checker_app.checker_settings_path",
                    return_value=root / "settings.json",
                ),
                mock.patch(
                    "checker_app.checker_results_path",
                    return_value=root / "results.json",
                ),
                mock.patch.object(
                    WireVeilChecker, "_refresh_network_status", return_value=None
                ),
            ):
                try:
                    checker = WireVeilChecker()
                except tk.TclError as exc:
                    self.skipTest(f"Tk is unavailable: {exc}")
                try:
                    self.assertTrue(
                        checker.brand_mark.bind("<Triple-Button-1>")
                    )
                    checker._show_rkn_easter_egg()
                    checker.update()
                    self.assertIsNotNone(checker.easter_window)
                    canvas = checker.easter_window.winfo_children()[0]
                    self.assertTrue(canvas.find_withtag("rkn"))
                    self.assertTrue(canvas.find_withtag("bat_line"))
                    checker._close_rkn_easter_egg()
                    self.assertIsNone(checker.easter_window)
                    self.assertIsNone(checker.easter_job)
                finally:
                    checker._on_close()

    def test_settings_window_does_not_displace_main_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch(
                    "checker_app.checker_settings_path",
                    return_value=root / "settings.json",
                ),
                mock.patch(
                    "checker_app.checker_results_path",
                    return_value=root / "results.json",
                ),
                mock.patch.object(
                    WireVeilChecker, "_refresh_network_status", return_value=None
                ),
            ):
                try:
                    checker = WireVeilChecker()
                except tk.TclError as exc:
                    self.skipTest(f"Tk is unavailable: {exc}")
                try:
                    checker.geometry("960x680")
                    checker.update()
                    before = (
                        checker.results_header.winfo_y(),
                        checker.table_frame.winfo_y(),
                        checker.table_frame.winfo_height(),
                    )

                    checker._toggle_advanced_settings(persist=False)
                    checker.update()
                    after = (
                        checker.results_header.winfo_y(),
                        checker.table_frame.winfo_y(),
                        checker.table_frame.winfo_height(),
                    )

                    self.assertEqual(before, after)
                    self.assertTrue(checker.advanced_window.winfo_ismapped())
                    self.assertTrue(checker.schedule_frame.winfo_ismapped())
                    self.assertTrue(checker.log_toggle_button.winfo_ismapped())

                    checker._toggle_log()
                    checker.update()
                    self.assertTrue(checker.log_frame.winfo_ismapped())
                    self.assertTrue(checker.log_toggle_button.winfo_ismapped())
                finally:
                    checker._on_close()

    def test_table_columns_fill_all_available_width(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch(
                    "checker_app.checker_settings_path",
                    return_value=root / "settings.json",
                ),
                mock.patch(
                    "checker_app.checker_results_path",
                    return_value=root / "results.json",
                ),
                mock.patch.object(
                    WireVeilChecker, "_refresh_network_status", return_value=None
                ),
            ):
                try:
                    checker = WireVeilChecker()
                except tk.TclError as exc:
                    self.skipTest(f"Tk is unavailable: {exc}")
                try:
                    for variable in checker.service_vars.values():
                        variable.set(True)
                    checker._service_selection_changed()
                    checker.geometry("1240x720")
                    checker.update()
                    checker.geometry("1620x720")
                    checker.update()
                    checker.after(100, checker.quit)
                    checker.mainloop()
                    displayed = tuple(
                        str(column) for column in checker.table["displaycolumns"]
                    )
                    used = sum(
                        int(checker.table.column(column, "width"))
                        for column in displayed
                    )
                    available = checker.table.winfo_width() - 4
                    self.assertLessEqual(abs(used - available), 2)
                    self.assertTrue(checker.table.column("endpoint", "stretch"))
                    self.assertTrue(checker.table.column("name", "stretch"))
                finally:
                    checker._on_close()


class UpdateUiTests(unittest.TestCase):
    @staticmethod
    def release() -> app_updater.ReleaseUpdate:
        return app_updater.ReleaseUpdate(
            version="1.9.99",
            tag="checker-v1.9.99",
            page_url=(
                "https://github.com/markKikhtenko/WireVeil/"
                "releases/tag/checker-v1.9.99"
            ),
            notes="## What's Changed\n* Faster updates",
            installer_url=(
                "https://github.com/markKikhtenko/WireVeil/releases/download/"
                "checker-v1.9.99/WireVeilChecker-Setup-x64.exe"
            ),
            checksum_url=(
                "https://github.com/markKikhtenko/WireVeil/releases/download/"
                "checker-v1.9.99/WireVeilChecker-Setup-x64.exe.sha256"
            ),
        )

    def test_update_confirmation_receives_release_notes(self):
        checker = object.__new__(WireVeilChecker)
        checker.update_busy = True
        checker._ask_to_install_update = mock.Mock(return_value=False)
        checker._configure_update_buttons = mock.Mock()
        checker.status_var = mock.Mock()
        checker._log = mock.Mock()
        release = self.release()

        checker._finish_update_check(release)

        checker._ask_to_install_update.assert_called_once_with(release)
        self.assertFalse(checker.update_busy)
        checker.status_var.set.assert_called_once_with(
            f"Доступна версия {release.version}"
        )

    def test_update_dialog_shows_release_notes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch(
                    "checker_app.checker_settings_path",
                    return_value=root / "settings.json",
                ),
                mock.patch(
                    "checker_app.checker_results_path",
                    return_value=root / "results.json",
                ),
                mock.patch.object(
                    WireVeilChecker,
                    "_refresh_network_status",
                    return_value=None,
                ),
            ):
                try:
                    checker = WireVeilChecker()
                except tk.TclError as exc:
                    self.skipTest(f"Tk is unavailable: {exc}")
                dialog = None
                try:
                    checker.tk.call("tk", "scaling", 1.5)
                    dialog = _UpdateDialog(checker, self.release())
                    checker.update()
                    notes = dialog.notes_text.get("1.0", "end-1c")
                    self.assertIn("Что изменилось", notes)
                    self.assertIn("Faster updates", notes)
                    self.assertEqual(
                        "Скачать и установить",
                        dialog.install_button.cget("text"),
                    )
                    self.assertTrue(dialog.install_button.winfo_ismapped())
                    button_bottom = (
                        dialog.install_button.winfo_rooty()
                        + dialog.install_button.winfo_height()
                    )
                    dialog_bottom = dialog.winfo_rooty() + dialog.winfo_height()
                    self.assertLessEqual(button_bottom, dialog_bottom)
                finally:
                    if dialog is not None and dialog.winfo_exists():
                        dialog.destroy()
                    checker._on_close()

    def test_known_download_size_updates_progress_bar_and_percentage(self):
        checker = object.__new__(WireVeilChecker)
        checker.progress = mock.Mock()
        checker.progress_var = mock.Mock()
        checker.status_var = mock.Mock()
        checker.update_progress_indeterminate = True

        checker._show_update_progress(5 * 1024 * 1024, 20 * 1024 * 1024, "1.9.99")

        checker.progress.stop.assert_called_once_with()
        checker.progress.configure.assert_called_once_with(
            mode="determinate", maximum=100
        )
        checker.progress_var.set.assert_called_once_with(25.0)
        checker.status_var.set.assert_called_once_with(
            "Скачиваем версию 1.9.99: 5.0 / 20.0 МБ — 25%"
        )

    @mock.patch("checker_app.app_updater.launch_in_place_update")
    def test_verified_package_starts_in_place_update(self, launch_update):
        checker = object.__new__(WireVeilChecker)
        checker._set_update_progress = mock.Mock()
        checker._configure_update_buttons = mock.Mock()
        checker.status_var = mock.Mock()
        checker._log = mock.Mock()
        checker.after = mock.Mock()
        checker._on_close = mock.Mock()
        checker.closing = False
        package = Path("WireVeilChecker-windows-x64.zip")

        checker._finish_update_download(package, "1.9.99")

        launch_update.assert_called_once_with(
            package,
            current_version=APP_VERSION,
            new_version="1.9.99",
        )
        self.assertTrue(checker.closing)
        checker.after.assert_called_once_with(150, checker._on_close)

    def test_ctrl_c_and_ctrl_v_work_with_russian_keyboard_layout(self):
        checker = object.__new__(WireVeilChecker)
        checker.table = mock.sentinel.table
        widget = mock.Mock(spec=ttk.Entry)
        widget.cget.return_value = "normal"

        copy_event = mock.Mock(
            keycode=67,
            keysym="Cyrillic_es",
            widget=widget,
        )
        paste_event = mock.Mock(
            keycode=86,
            keysym="Cyrillic_em",
            widget=widget,
        )

        self.assertEqual(
            "break", checker._application_clipboard_shortcut(copy_event)
        )
        self.assertEqual(
            "break", checker._application_clipboard_shortcut(paste_event)
        )
        self.assertEqual(
            [mock.call("<<Copy>>"), mock.call("<<Paste>>")],
            widget.event_generate.call_args_list,
        )

    def test_table_copy_shortcut_works_with_physical_ctrl_c(self):
        checker = object.__new__(WireVeilChecker)
        checker._copy_selected = mock.Mock()
        event = mock.Mock(keycode=67, keysym="Cyrillic_es")

        self.assertEqual("break", checker._table_keyboard_shortcut(event))
        checker._copy_selected.assert_called_once_with()


class QualifiedExportTests(unittest.TestCase):
    def test_low_ping_is_excluded_when_selected_service_is_unavailable(self):
        targets = tuple(
            healthcheck.ProbeTarget(
                index,
                f"wv-{index:04d}",
                f"vless://00000000-0000-4000-8000-00000000000{index}@node{index}.example:443",
                "vless",
                {},
            )
            for index in range(2)
        )
        probe_results = tuple(
            healthcheck.ProbeResult(
                target,
                True,
                50 + target.index,
                attempts=2,
                successes=2,
            )
            for target in targets
        )
        checker = object.__new__(WireVeilChecker)
        checker.report = local_checker.CheckReport(
            candidates=tuple(target.uri for target in targets),
            results=probe_results,
            conversion_unsupported={},
            runtime_rejected={},
            engine_version="test",
            attempts=2,
        )
        checker.latency_var = mock.Mock()
        checker.latency_var.get.return_value = 500
        checker.service_vars = {
            service.name: mock.Mock()
            for service in local_checker.SERVICE_DEFINITIONS
        }
        for name, variable in checker.service_vars.items():
            variable.get.return_value = name == "ChatGPT"
        checker.service_results = {
            (0, "ChatGPT"): local_checker.ServiceResult(
                targets[0], "ChatGPT", available=False, http_status=403
            ),
            (1, "ChatGPT"): local_checker.ServiceResult(
                targets[1], "ChatGPT", available=True, http_status=200
            ),
        }
        self.assertEqual((probe_results[1],), checker._qualified_results())


class AutoCheckTests(unittest.TestCase):
    @staticmethod
    def watch_report(
        *, active: bool = True, delay_ms: int | None = 900
    ) -> local_checker.CheckReport:
        uri = "vless://00000000-0000-4000-8000-000000000000@node.example:443"
        target = healthcheck.ProbeTarget(0, "wv-0000", uri, "vless", {})
        result = healthcheck.ProbeResult(
            target,
            active,
            delay_ms if active else None,
            attempts=1,
            successes=1 if active else 0,
        )
        return local_checker.CheckReport(
            candidates=(uri,),
            results=(result,),
            conversion_unsupported={},
            runtime_rejected={},
            engine_version="sing-box test",
            attempts=1,
        )

    def test_countdown_formats_minutes_and_hours(self):
        self.assertEqual("00:01", WireVeilChecker._format_countdown(0.1))
        self.assertEqual("29:59", WireVeilChecker._format_countdown(1798.2))
        self.assertEqual("1:01:01", WireVeilChecker._format_countdown(3660.1))

    @mock.patch("checker_app.time.monotonic", return_value=1000.0)
    def test_watch_schedule_records_real_deadline(self, _monotonic):
        checker = object.__new__(WireVeilChecker)
        checker.watch_job = None
        checker.watch_due_at = None
        checker.watch_enabled_var = mock.Mock()
        checker.watch_enabled_var.get.return_value = True
        checker.watch_interval_var = mock.Mock()
        checker.watch_interval_var.get.return_value = 30
        checker.watched_uris = ("vless://saved-one",)
        checker.closing = False
        checker.after = mock.Mock(return_value="timer-id")
        checker._log = mock.Mock()

        checker._schedule_watch_check()

        checker.after.assert_called_once_with(1_800_000, checker._run_watch_check)
        self.assertEqual("timer-id", checker.watch_job)
        self.assertEqual(2800.0, checker.watch_due_at)

    def test_offline_watch_keeps_previous_results_while_waiting_for_network(self):
        checker = object.__new__(WireVeilChecker)
        previous_report = object()
        checker.report = previous_report
        checker.running = True
        checker.activity = "watch"
        checker.progress_var = mock.Mock()
        checker.status_var = mock.Mock()
        checker._set_running_controls = mock.Mock()
        checker._clear_table = mock.Mock()
        checker._schedule_network_refresh = mock.Mock()
        checker._log = mock.Mock()
        checker.watch_waiting_for_network = False

        checker._defer_watch_until_online()

        self.assertIs(previous_report, checker.report)
        checker._clear_table.assert_not_called()
        self.assertFalse(checker.running)
        self.assertIsNone(checker.activity)
        self.assertTrue(checker.watch_waiting_for_network)
        checker._schedule_network_refresh.assert_called_once_with()
        checker.status_var.set.assert_called_once_with(
            "Контроль доступности ждёт восстановления сети"
        )

    def test_network_restore_starts_deferred_watch_immediately(self):
        checker = object.__new__(WireVeilChecker)
        checker.network_check_in_progress = True
        checker.network_status_var = mock.Mock()
        checker.network_status_label = mock.Mock()
        checker._schedule_network_refresh = mock.Mock()
        checker.watch_waiting_for_network = True
        checker.watch_enabled_var = mock.Mock()
        checker.watch_enabled_var.get.return_value = True
        checker.watched_uris = ("vless://saved-one",)
        checker.running = False
        checker.closing = False
        checker._log = mock.Mock()
        checker.after_idle = mock.Mock()

        checker._apply_network_status(network_check.NetworkStatus(online=True))

        self.assertFalse(checker.watch_waiting_for_network)
        checker.after_idle.assert_called_once_with(checker._start_watch_check)

    def test_waiting_watch_rechecks_network_quickly(self):
        checker = object.__new__(WireVeilChecker)
        checker.network_job = "old-network-timer"
        checker.watch_waiting_for_network = True
        checker.closing = False
        checker.after_cancel = mock.Mock()
        checker.after = mock.Mock(return_value="fast-network-timer")

        checker._schedule_network_refresh()

        checker.after_cancel.assert_called_once_with("old-network-timer")
        checker.after.assert_called_once_with(3_000, checker._refresh_network_status)
        self.assertEqual("fast-network-timer", checker.network_job)

    @mock.patch("checker_app.time.monotonic", return_value=1000.0)
    def test_restored_results_recreate_missing_auto_timer(self, _monotonic):
        checker = object.__new__(WireVeilChecker)
        checker.countdown_job = None
        checker.closing = False
        checker.auto_enabled_var = mock.Mock()
        checker.auto_enabled_var.get.return_value = True
        checker.auto_interval_var = mock.Mock()
        checker.auto_interval_var.get.return_value = 120
        checker.auto_job = None
        checker.auto_due_at = None
        checker.running = False
        checker.one_click_mode = False
        checker.report = object()
        checker.watch_enabled_var = mock.Mock()
        checker.watch_enabled_var.get.return_value = False
        checker.watched_uris = ()
        checker.watch_due_at = None
        checker.auto_countdown_var = mock.Mock()
        checker.watch_countdown_var = mock.Mock()
        checker.after = mock.Mock(side_effect=("auto-timer", "countdown-timer"))
        checker._log = mock.Mock()

        checker._update_countdowns()

        self.assertEqual("auto-timer", checker.auto_job)
        self.assertEqual(8200.0, checker.auto_due_at)
        checker.auto_countdown_var.set.assert_called_once_with(
            "● следующий запуск через 2:00:00"
        )

    def test_auto_check_runs_the_full_one_click_workflow(self):
        checker = object.__new__(WireVeilChecker)
        checker.auto_job = "scheduled"
        checker.auto_enabled_var = mock.Mock()
        checker.auto_enabled_var.get.return_value = True
        checker.running = False
        checker.closing = False
        checker._log = mock.Mock()
        checker._start_one_click = mock.Mock()

        checker._run_auto_check()

        self.assertIsNone(checker.auto_job)
        checker._start_one_click.assert_called_once_with()

    def test_watch_check_runs_only_the_saved_green_set(self):
        checker = object.__new__(WireVeilChecker)
        checker.watch_job = "scheduled"
        checker.watch_enabled_var = mock.Mock()
        checker.watch_enabled_var.get.return_value = True
        checker.watched_uris = ("vless://saved-one", "trojan://saved-two")
        checker.running = False
        checker.closing = False
        checker._start_watch_check = mock.Mock()

        checker._run_watch_check()

        self.assertIsNone(checker.watch_job)
        checker._start_watch_check.assert_called_once_with()

    @mock.patch("checker_app.threading.Thread")
    @mock.patch("checker_app.find_sing_box", return_value=Path("sing-box.exe"))
    def test_watch_speed_checks_all_accessible_servers(
        self, _find_sing_box, thread_class
    ):
        report = self.watch_report(active=True, delay_ms=900)
        target = report.active_results[0].target
        checker = object.__new__(WireVeilChecker)
        checker.running = False
        checker.report = report
        checker._qualified_results = mock.Mock(return_value=())
        checker.timeout_var = mock.Mock()
        checker.timeout_var.get.return_value = 15
        checker.workers_var = mock.Mock()
        checker.workers_var.get.return_value = 8
        checker._cancel_watch_timer = mock.Mock()
        checker.progress_var = mock.Mock()
        checker.status_var = mock.Mock()
        checker._set_running_controls = mock.Mock()
        checker._set_speed_cell = mock.Mock()
        checker._log = mock.Mock()

        checker._start_speed_test(watch_cycle=True)

        self.assertTrue(checker.running)
        self.assertEqual("watch_speed", checker.activity)
        checker._qualified_results.assert_not_called()
        checker._set_speed_cell.assert_called_once_with(target.index, "ожидание…")
        checker._cancel_watch_timer.assert_called_once_with()
        thread_class.return_value.start.assert_called_once_with()

    def test_watch_availability_continues_with_speed_before_rescheduling(self):
        report = self.watch_report()
        checker = object.__new__(WireVeilChecker)
        checker.running = True
        checker.activity = "watch"
        checker.progress_var = mock.Mock()
        checker._set_running_controls = mock.Mock()
        checker._populate_table = mock.Mock()
        checker._latency_limit = mock.Mock(return_value=500)
        checker.status_var = mock.Mock()
        checker.summary_var = mock.Mock()
        checker.watched_uris = report.candidates
        checker._log = mock.Mock()
        checker._restore_result_buttons = mock.Mock()
        checker._save_last_results = mock.Mock()
        checker._start_speed_test = mock.Mock()
        checker._schedule_watch_check = mock.Mock()

        checker._finish_watch_check(report)

        checker._start_speed_test.assert_called_once_with(watch_cycle=True)
        checker._schedule_watch_check.assert_not_called()
        checker._save_last_results.assert_called_once_with(mode="watch")

    def test_watch_without_accessible_servers_reschedules_without_speed(self):
        report = self.watch_report(active=False)
        checker = object.__new__(WireVeilChecker)
        checker.running = True
        checker.activity = "watch"
        checker.progress_var = mock.Mock()
        checker._set_running_controls = mock.Mock()
        checker._populate_table = mock.Mock()
        checker._latency_limit = mock.Mock(return_value=500)
        checker.status_var = mock.Mock()
        checker.summary_var = mock.Mock()
        checker.watched_uris = report.candidates
        checker._log = mock.Mock()
        checker._restore_result_buttons = mock.Mock()
        checker._save_last_results = mock.Mock()
        checker._start_speed_test = mock.Mock()
        checker._schedule_watch_check = mock.Mock()

        checker._finish_watch_check(report)

        checker._start_speed_test.assert_not_called()
        checker._schedule_watch_check.assert_called_once_with()

    def test_watch_reschedules_only_after_speed_results_are_saved(self):
        report = self.watch_report()
        target = report.active_results[0].target
        speed = local_checker.SpeedResult(
            target,
            speed_mbps=12.5,
            bytes_received=1_000_000,
            duration_ms=640,
        )
        checker = object.__new__(WireVeilChecker)
        checker.running = True
        checker.activity = "watch_speed"
        checker.report = report
        checker.watched_uris = report.candidates
        checker.progress_var = mock.Mock()
        checker._set_running_controls = mock.Mock()
        checker._update_speed_result = mock.Mock()
        checker.status_var = mock.Mock()
        checker.summary_var = mock.Mock()
        checker._log = mock.Mock()
        checker._apply_sort = mock.Mock()
        checker._restore_result_buttons = mock.Mock()
        checker._save_last_results = mock.Mock()
        checker._schedule_watch_check = mock.Mock()

        checker._finish_speed_test((speed,))

        checker._update_speed_result.assert_called_once_with(speed)
        checker._save_last_results.assert_called_once_with(mode="watch")
        checker._schedule_watch_check.assert_called_once_with()
        checker.status_var.set.assert_called_once_with(
            "Контроль доступности и скорости завершён"
        )

    def test_one_click_copies_results_when_auto_copy_is_enabled(self):
        checker = object.__new__(WireVeilChecker)
        checker.one_click_mode = True
        checker.auto_copy_results_var = mock.Mock()
        checker.auto_copy_results_var.get.return_value = True
        checker._copy_fast = mock.Mock()
        checker._log = mock.Mock()

        checker._complete_one_click()

        self.assertFalse(checker.one_click_mode)
        checker._copy_fast.assert_called_once_with()
        checker._log.assert_not_called()

    def test_one_click_leaves_clipboard_unchanged_when_auto_copy_is_disabled(self):
        checker = object.__new__(WireVeilChecker)
        checker.one_click_mode = True
        checker.auto_copy_results_var = mock.Mock()
        checker.auto_copy_results_var.get.return_value = False
        checker._copy_fast = mock.Mock()
        checker._log = mock.Mock()

        checker._complete_one_click()

        self.assertFalse(checker.one_click_mode)
        checker._copy_fast.assert_not_called()
        checker._log.assert_called_once_with(
            "Автокопирование рабочих ключей отключено."
        )

    def test_copying_good_servers_replaces_the_watched_set(self):
        target = healthcheck.ProbeTarget(
            0,
            "wv-0000",
            "vless://00000000-0000-4000-8000-000000000000@node.example:443",
            "vless",
            {},
        )
        result = healthcheck.ProbeResult(
            target, True, 50, attempts=1, successes=1
        )
        checker = object.__new__(WireVeilChecker)
        checker.report = object()
        checker._qualified_results = mock.Mock(return_value=(result,))
        checker.clipboard_clear = mock.Mock()
        checker.clipboard_append = mock.Mock()
        checker.update_idletasks = mock.Mock()
        checker._queue_settings_save = mock.Mock()
        checker.status_var = mock.Mock()
        checker._log = mock.Mock()
        checker.watch_enabled_var = mock.Mock()
        checker.watch_enabled_var.get.return_value = True
        checker._schedule_watch_check = mock.Mock()

        checker._copy_fast()

        self.assertEqual((target.uri,), checker.watched_uris)
        checker._queue_settings_save.assert_called_once_with()
        checker._schedule_watch_check.assert_called_once_with()


class SourceInputTests(unittest.TestCase):
    def test_shortcuts_work_by_windows_keycode_with_any_layout(self):
        expected = {65: "select_all", 67: "copy", 86: "paste", 88: "cut"}
        for keycode, action in expected.items():
            with self.subTest(keycode=keycode):
                event = mock.Mock(keycode=keycode, keysym="unrelated")
                self.assertEqual(
                    action, WireVeilChecker._source_shortcut_action(event)
                )

    def test_shortcuts_recognize_russian_keysyms(self):
        expected = {
            "Cyrillic_ef": "select_all",
            "Cyrillic_es": "copy",
            "Cyrillic_em": "paste",
            "Cyrillic_che": "cut",
        }
        for keysym, action in expected.items():
            with self.subTest(keysym=keysym):
                event = mock.Mock(keycode=-1, keysym=keysym)
                self.assertEqual(
                    action, WireVeilChecker._source_shortcut_action(event)
                )

    def test_clear_subscription_clears_input_and_persistent_value(self):
        checker = object.__new__(WireVeilChecker)
        checker.running = False
        checker.source = mock.Mock()
        checker.imported = object()
        checker.status_var = mock.Mock()
        checker._queue_settings_save = mock.Mock()

        checker._clear_source()

        checker.source.delete.assert_called_once_with("1.0", "end")
        self.assertIsNone(checker.imported)
        checker._queue_settings_save.assert_called_once_with()


class SettingsPersistenceTests(unittest.TestCase):
    def test_settings_round_trip(self):
        settings = {
            "rounds": 4,
            "timeout": 12,
            "workers": 24,
            "latency": 350,
            "auto_copy_results": False,
            "auto_enabled": True,
            "auto_interval": 17,
            "watch_enabled": True,
            "watch_interval": 31,
            "watched_uris": ["vless://one", "trojan://two"],
            "services": ["ChatGPT", "GitHub", "YouTube"],
            "advanced_visible": True,
            "subscription": "https://example.com/subscription",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "WireVeilChecker.config.json"
            write_checker_settings(path, settings)
            loaded = load_checker_settings(path)

            self.assertEqual(4, loaded["rounds"])
            self.assertEqual(12, loaded["timeout"])
            self.assertEqual(24, loaded["workers"])
            self.assertEqual(350, loaded["latency"])
            self.assertFalse(loaded["auto_copy_results"])
            self.assertTrue(loaded["auto_enabled"])
            self.assertEqual(17, loaded["auto_interval"])
            self.assertTrue(loaded["watch_enabled"])
            self.assertEqual(31, loaded["watch_interval"])
            self.assertEqual(
                ("vless://one", "trojan://two"), loaded["watched_uris"]
            )
            self.assertEqual(
                ("ChatGPT", "YouTube", "GitHub"), loaded["services"]
            )
            self.assertTrue(loaded["advanced_visible"])
            self.assertEqual(
                "https://example.com/subscription", loaded["subscription"]
            )
            self.assertEqual(2, json.loads(path.read_text(encoding="utf-8"))["version"])

    def test_invalid_settings_fall_back_to_safe_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "WireVeilChecker.config.json"
            path.write_text(
                json.dumps(
                    {
                        "rounds": 99,
                        "timeout": "broken",
                        "workers": 0,
                        "latency": -1,
                        "auto_copy_results": "yes",
                        "auto_enabled": "yes",
                        "auto_interval": 0,
                        "watch_enabled": "yes",
                        "watch_interval": 0,
                        "watched_uris": "broken",
                        "services": ["Unknown"],
                        "advanced_visible": "yes",
                        "subscription": 123,
                    }
                ),
                encoding="utf-8",
            )

            loaded = load_checker_settings(path)

            self.assertEqual(2, loaded["rounds"])
            self.assertEqual(8, loaded["timeout"])
            self.assertEqual(64, loaded["workers"])
            self.assertEqual(500, loaded["latency"])
            self.assertTrue(loaded["auto_copy_results"])
            self.assertFalse(loaded["auto_enabled"])
            self.assertEqual(30, loaded["auto_interval"])
            self.assertFalse(loaded["watch_enabled"])
            self.assertEqual(30, loaded["watch_interval"])
            self.assertEqual((), loaded["watched_uris"])
            self.assertEqual((), loaded["services"])
            self.assertFalse(loaded["advanced_visible"])
            self.assertEqual("", loaded["subscription"])


class ResultsPersistenceTests(unittest.TestCase):
    @staticmethod
    def sample_results():
        uri = (
            "vless://00000000-0000-4000-8000-000000000000@node.example:443"
            "?security=tls#Family"
        )
        protocol, outbound = healthcheck.uri_to_outbound(uri, "wv-0000")
        target = healthcheck.ProbeTarget(
            0, "wv-0000", uri, protocol, outbound
        )
        probe = healthcheck.ProbeResult(
            target,
            True,
            74,
            attempts=2,
            successes=2,
        )
        report = local_checker.CheckReport(
            candidates=(uri,),
            results=(probe,),
            conversion_unsupported={"ss": 1},
            runtime_rejected={},
            engine_version="sing-box test",
            attempts=2,
        )
        speeds = {
            0: local_checker.SpeedResult(
                target,
                speed_mbps=18.25,
                bytes_received=1_000_000,
                duration_ms=438,
            )
        }
        services = {
            (0, "ChatGPT"): local_checker.ServiceResult(
                target,
                "ChatGPT",
                available=True,
                latency_ms=91,
                http_status=403,
            )
        }
        return report, speeds, services

    def test_last_results_round_trip_keeps_exportable_targets(self):
        report, speeds, services = self.sample_results()
        source = "https://example.com/family-subscription"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "WireVeilChecker.last-results.json"
            write_checker_results(
                path,
                source,
                report,
                speeds,
                services,
                sort_column="quality",
                sort_descending=True,
            )

            loaded = load_checker_results(path, source)

        self.assertIsNotNone(loaded)
        self.assertEqual(report.candidates, loaded.report.candidates)
        self.assertEqual(74, loaded.report.results[0].delay_ms)
        self.assertEqual(report.results[0].target.uri, loaded.report.results[0].target.uri)
        self.assertTrue(loaded.report.results[0].target.outbound)
        self.assertEqual(18.25, loaded.speed_results[0].speed_mbps)
        self.assertTrue(loaded.service_results[(0, "ChatGPT")].available)
        self.assertEqual("quality", loaded.sort_column)
        self.assertTrue(loaded.sort_descending)

    def test_restored_results_always_start_sorted_by_rating(self):
        report, speeds, services = self.sample_results()
        saved = mock.Mock(
            report=report,
            speed_results=speeds,
            service_results=services,
            saved_at=1_700_000_000,
            sort_column="latency",
            sort_descending=True,
            mode="full",
        )
        checker = object.__new__(WireVeilChecker)
        checker.results_path = Path("saved-results.json")
        checker._populate_table = mock.Mock()
        checker._update_service_quality = mock.Mock()
        checker._apply_sort = mock.Mock()
        checker.progress_var = mock.Mock()
        checker._latency_limit = mock.Mock(return_value=500)
        checker.status_var = mock.Mock()
        checker.summary_var = mock.Mock()
        checker._restore_result_buttons = mock.Mock()
        checker._log = mock.Mock()

        with mock.patch("checker_app.load_checker_results", return_value=saved):
            checker._restore_last_results("subscription")

        self.assertEqual(DEFAULT_SORT_COLUMN, checker.sort_column)
        self.assertEqual(DEFAULT_SORT_DESCENDING, checker.sort_descending)
        checker._apply_sort.assert_called_once_with()

    def test_results_from_another_subscription_are_not_restored(self):
        report, speeds, services = self.sample_results()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "WireVeilChecker.last-results.json"
            write_checker_results(path, "subscription-a", report, speeds, services)

            loaded = load_checker_results(path, "subscription-b")

        self.assertIsNone(loaded)

    def test_corrupt_results_are_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "WireVeilChecker.last-results.json"
            path.write_text("{broken", encoding="utf-8")

            loaded = load_checker_results(path, "subscription")

        self.assertIsNone(loaded)


if __name__ == "__main__":
    unittest.main()
