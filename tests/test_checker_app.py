import json
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

from checker_app import (
    SERVICE_COLUMN_BY_NAME,
    TABLE_COLUMN_POSITIONS,
    TABLE_COLUMNS,
    WireVeilChecker,
    find_app_icon,
    load_checker_settings,
    load_checker_results,
    write_checker_results,
    write_checker_settings,
)
from scripts import healthcheck, local_checker


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


class AppIconTests(unittest.TestCase):
    def test_multisize_windows_icon_is_available(self):
        icon = find_app_icon()
        self.assertIsNotNone(icon)
        self.assertEqual("wireveil-icon.ico", icon.name)
        self.assertGreater(icon.stat().st_size, 0)


class MainUiLayoutTests(unittest.TestCase):
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
