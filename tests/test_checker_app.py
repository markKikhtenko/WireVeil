import unittest

from checker_app import (
    SERVICE_COLUMN_BY_NAME,
    TABLE_COLUMN_POSITIONS,
    TABLE_COLUMNS,
    WireVeilChecker,
)


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


if __name__ == "__main__":
    unittest.main()
