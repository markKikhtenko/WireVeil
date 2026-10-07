import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from checker_app import (
    SERVICE_COLUMN_BY_NAME,
    TABLE_COLUMN_POSITIONS,
    TABLE_COLUMNS,
    WireVeilChecker,
    load_checker_settings,
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
            "домен отвечает · HTTP 403 · 70 ms",
            WireVeilChecker._format_service(result),
        )

    def test_smart_quality_prioritizes_full_access_before_ping(self):
        full = ["—"] * len(TABLE_COLUMNS)
        partial = ["—"] * len(TABLE_COLUMNS)
        full[TABLE_COLUMN_POSITIONS["quality"]] = "3/3 · 240 ms"
        partial[TABLE_COLUMN_POSITIONS["quality"]] = "2/3 · 40 ms"
        self.assertLess(
            WireVeilChecker._column_sort_value("quality", tuple(full)),
            WireVeilChecker._column_sort_value("quality", tuple(partial)),
        )

    def test_smart_quality_uses_worst_service_latency_as_tiebreaker(self):
        fast = ["—"] * len(TABLE_COLUMNS)
        slow = ["—"] * len(TABLE_COLUMNS)
        fast[TABLE_COLUMN_POSITIONS["quality"]] = "3/3 · 120 ms"
        slow[TABLE_COLUMN_POSITIONS["quality"]] = "3/3 · 350 ms"
        self.assertLess(
            WireVeilChecker._column_sort_value("quality", tuple(fast)),
            WireVeilChecker._column_sort_value("quality", tuple(slow)),
        )


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


class SettingsPersistenceTests(unittest.TestCase):
    def test_settings_round_trip_next_to_application(self):
        settings = {
            "rounds": 4,
            "timeout": 12,
            "workers": 24,
            "latency": 350,
            "auto_enabled": True,
            "auto_interval": 17,
            "services": ["ChatGPT", "GitHub", "YouTube"],
            "advanced_visible": True,
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
            self.assertEqual(
                ("ChatGPT", "YouTube", "GitHub"), loaded["services"]
            )
            self.assertTrue(loaded["advanced_visible"])
            self.assertEqual(1, json.loads(path.read_text(encoding="utf-8"))["version"])

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
                        "services": ["Unknown"],
                        "advanced_visible": "yes",
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
            self.assertEqual((), loaded["services"])
            self.assertFalse(loaded["advanced_visible"])


if __name__ == "__main__":
    unittest.main()
