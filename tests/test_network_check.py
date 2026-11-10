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
        opener = mock.Mock()
        opener.open.side_effect = error
        with mock.patch.object(
            network_check, "_current_system_proxy_opener", return_value=opener
        ):
            status = network_check._probe_endpoint(
                "https://example.test/blocked", 0.5
            )

        self.assertTrue(status.online)
        self.assertGreaterEqual(status.latency_ms or 0, 1)

    def test_each_probe_reads_current_system_proxy_settings(self):
        first = {"https": "http://127.0.0.1:11080"}
        second = {"https": "http://127.0.0.1:12080"}
        with (
            mock.patch(
                "urllib.request.getproxies", side_effect=(first, second)
            ) as getproxies,
            mock.patch(
                "urllib.request.getproxies_registry", return_value={}, create=True
            ),
            mock.patch(
                "urllib.request.build_opener",
                side_effect=(mock.Mock(), mock.Mock()),
            ) as build,
        ):
            network_check._current_system_proxy_opener()
            network_check._current_system_proxy_opener()

        self.assertEqual(2, getproxies.call_count)
        self.assertEqual(first, build.call_args_list[0].args[0].proxies)
        self.assertEqual(second, build.call_args_list[1].args[0].proxies)

    def test_fresh_windows_registry_proxy_wins_over_stale_environment(self):
        environment = {"https": "http://127.0.0.1:11080"}
        registry = {"https": "http://127.0.0.1:12080"}
        with (
            mock.patch("urllib.request.getproxies", return_value=environment),
            mock.patch(
                "urllib.request.getproxies_registry",
                return_value=registry,
                create=True,
            ) as get_registry,
            mock.patch("urllib.request.build_opener", return_value=mock.Mock()) as build,
        ):
            network_check._current_system_proxy_opener()

        get_registry.assert_called_once_with()
        self.assertEqual(registry, build.call_args.args[0].proxies)

    def test_direct_route_recovers_from_stale_system_proxy(self):
        offline = network_check.NetworkStatus(False, endpoint="https://one.test")
        online = network_check.NetworkStatus(True, 7, "https://one.test")
        with (
            mock.patch.object(network_check, "_probe_endpoint", return_value=offline),
            mock.patch.object(
                network_check, "_probe_endpoint_direct", return_value=online
            ) as direct_probe,
        ):
            status = network_check.check_device_online(
                endpoints=("https://one.test",)
            )

        self.assertTrue(status.online)
        self.assertEqual(7, status.latency_ms)
        direct_probe.assert_called_once_with("https://one.test", 3.0)

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
