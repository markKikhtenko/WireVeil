import base64
import json
import tempfile
import unittest
from pathlib import Path

from scripts import healthcheck, local_checker
from tests.test_build import UUID1, UUID2


def vless(uuid: str, host: str, name: str = "") -> str:
    suffix = f"#{name}" if name else ""
    return f"vless://{uuid}@{host}:443?security=tls{suffix}"


class SubscriptionImportTests(unittest.TestCase):
    def test_plain_subscription_deduplicates_and_rejects_invalid(self):
        uri = vless(UUID1, "one.example.com")
        imported = local_checker.parse_subscription_text(
            f"{uri}\n{uri}\nvless://not-a-uuid@bad.example.com:443\n"
        )
        self.assertEqual((uri,), imported.lines)
        self.assertEqual(1, imported.duplicates)
        self.assertEqual(1, imported.rejected)

    def test_base64_wrapped_subscription_is_supported(self):
        lines = [
            vless(UUID1, "one.example.com"),
            "trojan://secret@two.example.com:443?security=tls",
        ]
        wrapped = base64.b64encode("\n".join(lines).encode()).decode()
        self.assertEqual(tuple(lines), local_checker.parse_subscription_text(wrapped).lines)

    def test_empty_or_unrelated_input_is_rejected(self):
        with self.assertRaises(local_checker.LocalCheckError):
            local_checker.parse_subscription_text("not a proxy subscription")


class ReportTests(unittest.TestCase):
    def result(self, index: int, uri: str, active: bool, delay: int | None):
        target = healthcheck.ProbeTarget(index, f"wv-{index:04d}", uri, "vless", {})
        return healthcheck.ProbeResult(
            target, active, delay, None if active else "timeout", attempts=2, successes=2 if active else 0
        )

    def test_report_keeps_fastest_endpoint_and_applies_latency_threshold(self):
        slow = self.result(0, vless(UUID1, "same.example.com"), True, 600)
        fast = self.result(1, vless(UUID2, "same.example.com"), True, 80)
        dead = self.result(2, vless(UUID1, "dead.example.com"), False, None)
        report = local_checker.CheckReport(
            candidates=tuple(item.target.uri for item in (slow, fast, dead)),
            results=(slow, fast, dead),
            conversion_unsupported={},
            runtime_rejected={},
            engine_version="sing-box test",
            attempts=2,
        )
        self.assertEqual((fast,), report.active_results)
        self.assertEqual((fast,), report.fast_results(500))
        self.assertEqual((), report.fast_results(50))

    def test_exports_subscription_and_diagnostic_report(self):
        result = self.result(0, vless(UUID1, "one.example.com"), True, 80)
        report = local_checker.CheckReport(
            candidates=(result.target.uri,),
            results=(result,),
            conversion_unsupported={"hysteria": 1},
            runtime_rejected={},
            engine_version="sing-box test",
            attempts=2,
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            local_checker.write_subscription(root / "good.txt", report.fast_results(500))
            self.assertEqual(result.target.uri + "\n", (root / "good.txt").read_text())
            local_checker.write_report(root / "report.json", report, 500)
            payload = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(1, payload["fast_keys"])
            self.assertEqual(1, payload["unsupported_keys"])
            self.assertEqual(2, payload["results"][0]["successes"])


class RepeatedProbeTests(unittest.TestCase):
    def test_all_attempts_are_required_and_latency_uses_median(self):
        uri = vless(UUID1, "one.example.com")
        target = healthcheck.ProbeTarget(0, "wv-0000", uri, "vless", {})
        attempts = [
            healthcheck.ProbeResult(target, True, 100, attempts=1, successes=1),
            healthcheck.ProbeResult(target, True, 200, attempts=1, successes=1),
        ]
        combined = healthcheck._combine_probe_attempts(target, attempts, 2)
        self.assertTrue(combined.active)
        self.assertEqual(150, combined.delay_ms)
        self.assertEqual(2, combined.successes)

        failed = healthcheck._combine_probe_attempts(
            target,
            attempts[:1] + [healthcheck.ProbeResult(target, False, None, "timeout")],
            2,
        )
        self.assertFalse(failed.active)
        self.assertIsNone(failed.delay_ms)
        self.assertIn("1/2 successful", failed.error)


if __name__ == "__main__":
    unittest.main()
