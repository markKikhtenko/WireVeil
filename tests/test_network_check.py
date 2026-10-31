import time
import unittest
import urllib.error
from unittest import mock

from scripts import network_check


class NetworkCheckTests(unittest.TestCase):
    def test_returns_first_successful_https_probe(self):
        def probe(endpoint: str, _timeout: float) -> network_check.NetworkStatus:
            if endpoint.endswith("ok"):
                return network_check.NetworkStatus(True, 42, endpoint)
            return network_check.NetworkStatus(False, endpoint=endpoint)

        status = network_check.check_device_online(
            endpoints=("https://one.test/fail", "https://two.test/ok"),
            probe=probe,
        )

        self.assertTrue(status.online)
        self.assertEqual(status.latency_ms, 42)
        self.assertEqual(status.endpoint, "https://two.test/ok")

    def test_http_error_still_proves_connectivity(self):
        error = urllib.error.HTTPError(
            "https://example.test/blocked", 403, "Forbidden", {}, None
        )
        with mock.patch("urllib.request.urlopen", side_effect=error):
            status = network_check._probe_endpoint(
                "https://example.test/blocked", 0.5
            )

        self.assertTrue(status.online)
        self.assertGreaterEqual(status.latency_ms or 0, 1)

    def test_all_failed_probes_report_offline(self):
        def probe(endpoint: str, _timeout: float) -> network_check.NetworkStatus:
            return network_check.NetworkStatus(False, endpoint=endpoint)

        status = network_check.check_device_online(
            endpoints=("https://one.test/fail", "https://two.test/fail"),
            probe=probe,
        )

        self.assertFalse(status.online)
        self.assertIsNone(status.latency_ms)

    def test_slow_failed_probe_does_not_delay_fast_success(self):
        def probe(endpoint: str, _timeout: float) -> network_check.NetworkStatus:
            if endpoint.endswith("slow"):
                time.sleep(0.25)
                return network_check.NetworkStatus(False, endpoint=endpoint)
            return network_check.NetworkStatus(True, 5, endpoint)

        started = time.monotonic()
        status = network_check.check_device_online(
            timeout=0.5,
            endpoints=("https://one.test/slow", "https://two.test/fast"),
            probe=probe,
        )

        self.assertTrue(status.online)
        self.assertLess(time.monotonic() - started, 0.2)


if __name__ == "__main__":
    unittest.main()
