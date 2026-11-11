from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from mihomo_diagnostics_dialog import MihomoDiagnosticsDialog
from scripts import mihomo_diagnostics


class FakeRuntime:
    def __init__(
        self,
        *,
        launch_error: Exception | None = None,
        auth_status: int = 200,
        api_status_by_host: dict[str, tuple[int, bytes]] | None = None,
    ):
        self.controller_port = 19090
        self.proxy_port = 17890
        self.launch_error = launch_error
        self.auth_status = auth_status
        self.api_status_by_host = api_status_by_host or {}
        self.running = False
        self.stopped = False
        self.prepared = False

    def binary_version(self, _cancel_event: threading.Event) -> tuple[str, int]:
        return "Mihomo Meta v1.19.33", 4

    def prepare(self) -> None:
        self.prepared = True

    def validate_config(self, _cancel_event: threading.Event) -> tuple[str, int]:
        return "configuration OK", 6

    def launch(self) -> int:
        if self.launch_error is not None:
            raise self.launch_error
        self.running = True
        return 8

    def wait_for_controller(self, _cancel_event: threading.Event, _timeout: float) -> int:
        return 12

    def api_request(
        self, path: str, *, authorized: bool, timeout: float
    ) -> mihomo_diagnostics.ApiObservation:
        del timeout
        if not authorized:
            return mihomo_diagnostics.ApiObservation(401, b'{"message":"unauthorized"}', 2)
        if path == "/version":
            if self.auth_status != 200:
                return mihomo_diagnostics.ApiObservation(self.auth_status, b"{}", 2)
            return mihomo_diagnostics.ApiObservation(
                200, b'{"version":"Mihomo Meta v1.19.33"}', 2
            )
        if path == "/proxies":
            return mihomo_diagnostics.ApiObservation(
                200, b'{"proxies":{"DIRECT":{"type":"Direct"}}}', 2
            )
        if path.startswith("/proxies/DIRECT/delay?"):
            query = path.split("?", 1)[1]
            url = urllib.parse.parse_qs(query)["url"][0]
            host = urllib.parse.urlsplit(url).hostname or ""
            status, body = self.api_status_by_host.get(host, (200, b'{"delay":31}'))
            return mihomo_diagnostics.ApiObservation(status, body, 7)
        raise AssertionError(path)

    def is_running(self) -> bool:
        return self.running and not self.stopped

    def stop(self) -> None:
        self.running = False
        self.stopped = True


def successful_http_probe(
    url: str, _timeout: float, _proxy_url: str | None
) -> mihomo_diagnostics.HttpObservation:
    status = 204 if url.endswith("generate_204") else 200
    return mihomo_diagnostics.HttpObservation(status, 19)


class MihomoDiagnosticsTests(unittest.TestCase):
    def run_with_fake(
        self,
        binary: Path,
        runtime: FakeRuntime,
        *,
        probe=mihomo_diagnostics.https_probe,
    ) -> mihomo_diagnostics.DiagnosticReport:
        runner = mihomo_diagnostics.MihomoDiagnosticRunner(
            binary,
            "test-version",
            runtime_factory=lambda _path: runtime,
            http_probe=probe,
        )
        return runner.run()

    def test_successful_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            runtime = FakeRuntime()
            report = self.run_with_fake(binary, runtime, probe=successful_http_probe)

        self.assertEqual(mihomo_diagnostics.MihomoDiagnosticRunner.TOTAL_CHECKS, len(report.results))
        self.assertTrue(all(result.status == "PASS" for result in report.results))
        self.assertIn("Базовая работоспособность Mihomo подтверждена", report.conclusion)
        self.assertTrue(runtime.stopped)
        payload = json.loads(report.to_json())
        self.assertEqual("test-version", payload["wireveil_version"])
        self.assertEqual("Mihomo Meta v1.19.33", payload["mihomo_version"])

    def test_missing_mihomo_binary(self) -> None:
        runner = mihomo_diagnostics.MihomoDiagnosticRunner(
            None,
            "test-version",
            http_probe=successful_http_probe,
        )
        report = runner.run()

        presence = report.results[0]
        self.assertEqual("FAIL", presence.status)
        self.assertIn("не найден", presence.detail)
        direct = [item for item in report.results if item.method == "direct"]
        mihomo_methods = [item for item in report.results if item.method in {"api", "proxy"}]
        self.assertTrue(all(item.status == "PASS" for item in direct))
        self.assertTrue(all(item.status == "SKIPPED" for item in mihomo_methods))

    def test_failed_core_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            runtime = FakeRuntime(
                launch_error=mihomo_diagnostics.DiagnosticFailure("process exited")
            )
            report = self.run_with_fake(binary, runtime, probe=successful_http_probe)

        launch = next(item for item in report.results if item.check == "Запуск процесса")
        self.assertEqual("FAIL", launch.status)
        self.assertTrue(runtime.stopped)
        self.assertTrue(all(
            item.status == "SKIPPED"
            for item in report.results
            if item.method in {"api", "proxy"}
        ))

    def test_api_authorization_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            runtime = FakeRuntime(auth_status=401)
            report = self.run_with_fake(binary, runtime, probe=successful_http_probe)

        auth = next(item for item in report.results if item.check == "Авторизация API")
        self.assertEqual("FAIL", auth.status)
        self.assertEqual(401, auth.http_status)
        self.assertTrue(all(
            item.status == "SKIPPED" for item in report.results if item.method == "api"
        ))
        self.assertTrue(all(
            item.status == "PASS" for item in report.results if item.method == "proxy"
        ))

    def test_url_test_http_503_and_504_are_not_controller_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            runtime = FakeRuntime(api_status_by_host={
                "example.com": (503, b'{"message":"probe unavailable"}'),
                "github.com": (504, b'{"message":"deadline timeout"}'),
                "www.microsoft.com": (503, b'{"message":"probe unavailable"}'),
                "www.gstatic.com": (503, b'{"message":"probe unavailable"}'),
                "cp.cloudflare.com": (503, b'{"message":"probe unavailable"}'),
            })
            report = self.run_with_fake(binary, runtime, probe=successful_http_probe)

        api_results = [item for item in report.results if item.method == "api"]
        self.assertEqual({503, 504}, {item.http_status for item in api_results})
        self.assertTrue(all(item.status in {"FAIL", "TIMEOUT"} for item in api_results))
        self.assertTrue(all("не доказывает" in item.detail for item in api_results))
        controller = next(
            item for item in report.results if item.check == "Доступность локального API"
        )
        self.assertEqual("PASS", controller.status)
        self.assertIn("механизма API-проверки", report.conclusion)

    def test_network_timeout(self) -> None:
        def timeout_probe(
            _url: str, _timeout: float, _proxy_url: str | None
        ) -> mihomo_diagnostics.HttpObservation:
            raise socket.timeout("timed out")

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            report = self.run_with_fake(binary, FakeRuntime(), probe=timeout_probe)

        http_results = [item for item in report.results if item.method in {"direct", "proxy"}]
        self.assertTrue(http_results)
        self.assertTrue(all(item.status == "TIMEOUT" for item in http_results))

    def test_one_site_unavailable_is_reported_as_network_environment(self) -> None:
        def site_probe(
            url: str, timeout: float, proxy_url: str | None
        ) -> mihomo_diagnostics.HttpObservation:
            if "example.com" in url:
                raise socket.gaierror("DNS lookup failed")
            return successful_http_probe(url, timeout, proxy_url)

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            runtime = FakeRuntime(api_status_by_host={
                "example.com": (503, b'{"message":"lookup failed"}')
            })
            report = self.run_with_fake(binary, runtime, probe=site_probe)

        example = [item for item in report.results if item.site == "Example"]
        self.assertTrue(all(item.status == "FAIL" for item in example))
        self.assertIn("сетевое окружение", report.conclusion)
        self.assertIn("не доказывает неисправность чекера", report.conclusion)

    def test_http_proxy_error_is_distinct(self) -> None:
        def proxy_failure(
            url: str, timeout: float, proxy_url: str | None
        ) -> mihomo_diagnostics.HttpObservation:
            if proxy_url is not None:
                raise ConnectionRefusedError("connection refused")
            return successful_http_probe(url, timeout, proxy_url)

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            report = self.run_with_fake(binary, FakeRuntime(), probe=proxy_failure)

        proxy_results = [item for item in report.results if item.method == "proxy"]
        self.assertTrue(all(item.status == "FAIL" for item in proxy_results))
        self.assertTrue(all("Ошибка HTTP-прокси" in item.detail for item in proxy_results))

    def test_closing_dialog_cancels_active_runner(self) -> None:
        runner = mock.Mock()
        callback = mock.Mock()
        dialog = object.__new__(MihomoDiagnosticsDialog)
        dialog._closed = False
        dialog.runner = runner
        dialog._poll_job = None
        dialog.on_closed = callback
        dialog.destroy = mock.Mock()

        MihomoDiagnosticsDialog.close(dialog)

        runner.cancel.assert_called_once_with()
        dialog.destroy.assert_called_once_with()
        callback.assert_called_once_with()
        self.assertTrue(dialog._closed)

    def test_runtime_stop_terminates_process_and_removes_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mihomo.exe"
            binary.touch()
            runtime = mihomo_diagnostics.MihomoDiagnosticRuntime(binary)
            runtime.prepare()
            assert runtime._temporary is not None
            temporary_path = Path(runtime._temporary.name)
            process = mock.Mock()
            process.poll.return_value = None
            process.wait.return_value = 0
            runtime.process = process

            runtime.stop()

            process.terminate.assert_called_once_with()
            self.assertFalse(temporary_path.exists())
            self.assertIsNone(runtime.process)
            self.assertIsNone(runtime._temporary)


if __name__ == "__main__":
    unittest.main()
