import base64
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

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


class SpeedTestTests(unittest.TestCase):
    def target(self, index: int = 0):
        uri = vless(UUID1, f"speed{index}.example.com")
        return healthcheck.ProbeTarget(
            index,
            f"wv-{index:04d}",
            uri,
            "vless",
            {"type": "vless", "tag": f"wv-{index:04d}"},
        )

    def test_speed_config_routes_each_local_inbound_to_its_green_target(self):
        targets = (self.target(0), self.target(1))
        config = local_checker._speed_test_config(targets, (21001, 21002))
        self.assertEqual(2, len(config["inbounds"]))
        self.assertEqual("mixed", config["inbounds"][0]["type"])
        self.assertEqual("wv-0000", config["route"]["rules"][0]["outbound"])
        self.assertEqual("wv-0001", config["route"]["rules"][1]["outbound"])

    def test_download_speed_uses_body_transfer_time_and_reports_mbps(self):
        target = self.target()

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        opener = mock.Mock()
        opener.open.return_value = Response(b"x" * 1_000_000)
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            mock.patch("time.perf_counter", side_effect=[10.0, 10.5]),
        ):
            result = local_checker._test_download_speed(
                target,
                21001,
                download_bytes=1_000_000,
                timeout=15,
                cancel_event=None,
            )
        self.assertEqual(16.0, result.speed_mbps)
        self.assertEqual(1_000_000, result.bytes_received)
        self.assertEqual(500, result.duration_ms)
        self.assertIsNone(result.error)


class ServiceTestTests(unittest.TestCase):
    def target(self):
        uri = vless(UUID1, "service.example.com")
        return healthcheck.ProbeTarget(
            0,
            "wv-0000",
            uri,
            "vless",
            {"type": "vless", "tag": "wv-0000"},
        )

    def test_service_catalog_contains_requested_sites(self):
        names = set(local_checker.SERVICE_DEFINITIONS_BY_NAME)
        self.assertTrue({"ChatGPT", "YouTube", "GitHub"}.issubset(names))
        keys = [service.key for service in local_checker.SERVICE_DEFINITIONS]
        self.assertEqual(len(keys), len(set(keys)))

    def test_multiple_services_are_accepted_together(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "sing-box.exe"
            binary.touch()
            results = local_checker.run_service_tests(
                binary=binary,
                targets=(),
                service_names=("ChatGPT", "YouTube", "GitHub"),
            )
        self.assertEqual((), results)

    def test_service_access_reports_http_success_and_latency(self):
        class Response(io.BytesIO):
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        opener = mock.Mock()
        opener.open.return_value = Response(b"")
        service = local_checker.SERVICE_DEFINITIONS_BY_NAME["YouTube"]
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            mock.patch("time.perf_counter", side_effect=[10.0, 10.125]),
        ):
            result = local_checker._test_service_access(
                self.target(),
                21001,
                service=service,
                timeout=15,
                cancel_event=None,
            )
        self.assertTrue(result.available)
        self.assertEqual(204, result.http_status)
        self.assertEqual(125, result.latency_ms)

    def test_service_access_keeps_restriction_status(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError(
            "https://chatgpt.com/", 403, "Forbidden", {}, io.BytesIO(b"blocked")
        )
        service = local_checker.SERVICE_DEFINITIONS_BY_NAME["ChatGPT"]
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            mock.patch("time.perf_counter", side_effect=[20.0, 20.050]),
        ):
            result = local_checker._test_service_access(
                self.target(),
                21001,
                service=service,
                timeout=15,
                cancel_event=None,
            )
        self.assertFalse(result.available)
        self.assertEqual(403, result.http_status)
        self.assertEqual(50, result.latency_ms)


if __name__ == "__main__":
    unittest.main()
