import tempfile
import unittest
from pathlib import Path

from scripts import local_checker
from subscription_sources import (
    SubscriptionSource,
    import_subscription_sources,
    load_subscription_sources,
    save_subscription_sources,
    selected_sources_identity,
)


def vless_uri(host: str) -> str:
    return (
        "vless://550e8400-e29b-41d4-a716-446655440000@"
        f"{host}:443?security=tls"
    )


class SubscriptionSourcePersistenceTests(unittest.TestCase):
    def test_sources_round_trip_with_selection(self):
        sources = [
            SubscriptionSource("one", "Первый", "url", "https://one.test/sub", True),
            SubscriptionSource("two", "Второй", "file", "C:/vpn/two.txt", False),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sources.json"
            save_subscription_sources(path, sources)

            loaded = load_subscription_sources(path)

        self.assertEqual(sources, loaded)

    def test_url_display_hides_credentials_and_query(self):
        source = SubscriptionSource(
            "private",
            "Private",
            "url",
            "https://user:secret@example.com:8443/sub?token=private",
        )

        self.assertEqual("https://example.com:8443/sub", source.display)

    def test_identity_uses_only_selected_sources(self):
        first = SubscriptionSource("one", "One", "url", "https://one.test/sub")
        ignored = SubscriptionSource(
            "two", "Two", "url", "https://two.test/sub", selected=False
        )

        self.assertEqual(
            selected_sources_identity([first]),
            selected_sources_identity([first, ignored]),
        )


class SubscriptionSourceImportTests(unittest.TestCase):
    def test_selected_sources_are_merged_and_deduplicated(self):
        first = vless_uri("one.example.com")
        second = vless_uri("two.example.com")
        sources = (
            SubscriptionSource("one", "One", "text", f"{first}\n{second}"),
            SubscriptionSource("two", "Two", "text", second),
            SubscriptionSource(
                "off", "Off", "text", vless_uri("ignored.example.com"), False
            ),
        )

        imported, failures = import_subscription_sources(sources)

        self.assertEqual((first, second), imported.lines)
        self.assertEqual(1, imported.duplicates)
        self.assertEqual((), failures)

    def test_broken_source_does_not_discard_valid_selected_source(self):
        valid = vless_uri("one.example.com")
        sources = (
            SubscriptionSource("bad", "Bad", "text", "not a subscription"),
            SubscriptionSource("good", "Good", "text", valid),
        )

        imported, failures = import_subscription_sources(sources)

        self.assertEqual((valid,), imported.lines)
        self.assertEqual("Bad", failures[0][0])

    def test_empty_selection_is_rejected(self):
        sources = (
            SubscriptionSource("off", "Off", "text", vless_uri("off.test"), False),
        )

        with self.assertRaises(local_checker.LocalCheckError):
            import_subscription_sources(sources)


if __name__ == "__main__":
    unittest.main()
