import unittest

from checker_app import WireVeilChecker


class TableSortTests(unittest.TestCase):
    def test_service_column_sorts_available_by_latency(self):
        fast = ("1", "VLESS", "one:443", "One", "80 ms", "—", "доступен · 95 ms", "2/2")
        slow = ("2", "VLESS", "two:443", "Two", "90 ms", "—", "доступен · 240 ms", "2/2")
        self.assertLess(
            WireVeilChecker._column_sort_value("service", fast),
            WireVeilChecker._column_sort_value("service", slow),
        )

    def test_service_restriction_sorts_after_available(self):
        available = ("1", "VLESS", "one:443", "One", "80 ms", "—", "доступен · 95 ms", "2/2")
        restricted = ("2", "VLESS", "two:443", "Two", "90 ms", "—", "HTTP 403 · 70 ms", "2/2")
        self.assertLess(
            WireVeilChecker._column_sort_value("service", available),
            WireVeilChecker._column_sort_value("service", restricted),
        )


if __name__ == "__main__":
    unittest.main()
