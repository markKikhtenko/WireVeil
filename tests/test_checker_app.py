import unittest
from unittest import mock

from checker_app import (
    SERVICE_COLUMN_BY_NAME,
    TABLE_COLUMN_POSITIONS,
    TABLE_COLUMNS,
    WireVeilChecker,
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


if __name__ == "__main__":
    unittest.main()
