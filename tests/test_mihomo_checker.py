import json
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

import yaml

from mihomo_tab import MihomoCheckerTab, _MultilineDialog
from scripts import mihomo_checker


UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"


def source(source_id: str, name: str = "Provider", kind: str = "text", value: str = ""):
    return mihomo_checker.SourceSpec(source_id, name, kind, value)


def vless_proxy(name: str = "Node", uuid: str = UUID_A, server: str = "edge.example.com"):
    return {
        "name": name,
        "type": "vless",
        "server": server,
        "port": 443,
        "uuid": uuid,
        "network": "ws",
        "tls": True,
        "servername": "cdn.example.com",
        "client-fingerprint": "chrome",
        "reality-opts": {"public-key": "PUBLIC-KEY", "short-id": "abcd"},
        "ws-opts": {"path": "/socket", "headers": {"Host": "cdn.example.com"}},
    }


def parsed_source(spec, proxies):
    return mihomo_checker.parse_source_text(
        spec,
        yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False),
    )


class ImportTests(unittest.TestCase):
    def test_txt_url_list_expands_to_independent_url_sources(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "providers.txt"
            path.write_text(
                "# main providers\n"
                "https://one.example/sub.yaml?token=secret-one\n"
                "\n"
                "https://two.example/config.yml\n",
                encoding="utf-8",
            )
            sources = mihomo_checker.source_specs_from_file(path)

        self.assertEqual(2, len(sources))
        self.assertEqual(["url", "url"], [item.kind for item in sources])
        self.assertEqual(
            [
                "https://one.example/sub.yaml?token=secret-one",
                "https://two.example/config.yml",
            ],
            [item.value for item in sources],
        )
        self.assertEqual(2, len({item.source_id for item in sources}))
        self.assertIn("one.example", sources[0].name)
        self.assertIn("two.example", sources[1].name)

    def test_txt_yaml_is_kept_as_one_file_source(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "subscription.txt"
            path.write_text("proxies:\n  - name: Test\n", encoding="utf-8")
            sources = mihomo_checker.source_specs_from_file(path)

        self.assertEqual(1, len(sources))
        self.assertEqual("file", sources[0].kind)
        self.assertEqual(str(path), sources[0].value)

    def test_mixed_txt_is_not_partially_imported_as_url_list(self):
        text = "https://one.example/sub.yaml\nnot-a-url\n"
        self.assertIsNone(mihomo_checker.subscription_urls_from_text(text))

    def test_mihomo_yaml_preserves_transport_and_reality_fields(self):
        proxy = vless_proxy()
        text = yaml.safe_dump(
            {
                "proxies": [proxy],
                "dns": {"enable": True},
                "tun": {"enable": True},
                "external-controller": "0.0.0.0:9090",
                "rules": ["MATCH,DIRECT"],
            },
            sort_keys=False,
        )
        parsed = mihomo_checker.parse_source_text(source("src-1"), text)
        self.assertEqual("ok", parsed.parse_status)
        self.assertEqual(proxy, parsed.nodes[0].proxy)
        runtime = mihomo_checker._runtime_config(parsed.nodes, 12345, "secret")
        self.assertNotIn("dns", runtime)
        self.assertNotIn("tun", runtime)
        self.assertEqual("127.0.0.1:12345", runtime["external-controller"])
        self.assertFalse(runtime["allow-lan"])

    def test_proxy_provider_yaml_with_embedded_proxies_is_supported(self):
        parsed = parsed_source(source("src-provider"), [vless_proxy()])
        self.assertEqual("ok", parsed.parse_status)
        self.assertEqual(1, parsed.total_entries)

    def test_external_provider_without_proxies_is_explicit(self):
        text = yaml.safe_dump(
            {"proxy-providers": {"vendor": {"type": "http", "url": "https://vendor.example/sub"}}}
        )
        parsed = mihomo_checker.parse_source_text(source("src-external"), text)
        self.assertEqual("unsupported", parsed.parse_status)
        self.assertEqual("EXTERNAL_PROVIDER_NOT_EXPANDED", parsed.error_code)

    def test_share_uri_list_is_not_silently_converted(self):
        parsed = mihomo_checker.parse_source_text(
            source("src-uri"), f"vless://{UUID_A}@edge.example.com:443"
        )
        self.assertEqual("unsupported", parsed.parse_status)
        self.assertEqual("UNSUPPORTED_FORMAT", parsed.error_code)

    def test_partial_source_keeps_supported_and_unsupported_entries(self):
        parsed = parsed_source(
            source("src-partial"),
            [vless_proxy(), {"name": "WG", "type": "wireguard", "server": "wg.example", "port": 51820}],
        )
        self.assertEqual("partial", parsed.parse_status)
        self.assertEqual(2, parsed.total_entries)
        self.assertEqual(2, len(parsed.nodes))
        self.assertTrue(parsed.nodes[0].supported)
        self.assertFalse(parsed.nodes[1].supported)
        self.assertEqual("UNSUPPORTED_PROTOCOL", parsed.nodes[1].import_error_code)

    def test_invalid_yaml_is_a_parse_error(self):
        parsed = mihomo_checker.parse_source_text(source("src-bad"), "proxies: [broken")
        self.assertEqual("failed", parsed.parse_status)
        self.assertEqual("PARSE_ERROR", parsed.error_code)

    def test_subscription_url_rejects_private_and_invalid_ports(self):
        with mock.patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 443))],
        ):
            with self.assertRaisesRegex(mihomo_checker.MihomoCheckError, "локальный"):
                mihomo_checker.validate_subscription_url("https://provider.example/sub")
        with self.assertRaises(mihomo_checker.MihomoCheckError) as raised:
            mihomo_checker.validate_subscription_url("https://provider.example:99999/sub")
        self.assertEqual("UNSAFE_SOURCE_URL", raised.exception.code)

    def test_sensitive_fields_are_redacted_from_untrusted_errors(self):
        safe = mihomo_checker.sanitize_text(
            "password short-secret token=long-secret-value uuid: " + UUID_A
        )
        self.assertNotIn("short-secret", safe)
        self.assertNotIn("long-secret-value", safe)
        self.assertNotIn(UUID_A, safe)


class MultilineDialogTests(unittest.TestCase):
    def test_shortcuts_work_by_windows_keycode_with_any_layout(self):
        expected = {65: "select_all", 67: "copy", 86: "paste", 88: "cut"}
        for keycode, action in expected.items():
            with self.subTest(keycode=keycode):
                event = mock.Mock(keycode=keycode, keysym="unrelated")
                self.assertEqual(action, _MultilineDialog._shortcut_action(event))

    def test_shortcuts_recognize_english_and_russian_keysyms(self):
        expected = {
            "a": "select_all",
            "c": "copy",
            "v": "paste",
            "x": "cut",
            "Cyrillic_ef": "select_all",
            "Cyrillic_es": "copy",
            "Cyrillic_em": "paste",
            "Cyrillic_che": "cut",
        }
        for keysym, action in expected.items():
            with self.subTest(keysym=keysym):
                event = mock.Mock(keycode=-1, keysym=keysym)
                self.assertEqual(action, _MultilineDialog._shortcut_action(event))

    def test_paste_replaces_selection_and_single_line_flattens_newlines(self):
        dialog = object.__new__(_MultilineDialog)
        dialog.multiline = False
        dialog.text = mock.Mock()
        dialog.text.tag_ranges.return_value = ("1.0", "1.3")
        dialog.clipboard_get = mock.Mock(return_value="https://one.example/\nnext")

        dialog._paste_clipboard()

        dialog.text.delete.assert_called_once_with("1.0", "1.3")
        dialog.text.insert.assert_called_once_with(
            "insert", "https://one.example/ next"
        )
        dialog.text.see.assert_called_once_with("insert")

    def test_insert_handlers_are_explicit_and_consume_events(self):
        dialog = object.__new__(_MultilineDialog)
        dialog._copy_selection = mock.Mock(return_value=True)
        dialog._paste_clipboard = mock.Mock()

        self.assertEqual("break", dialog._copy_event())
        self.assertEqual("break", dialog._paste_event())
        dialog._copy_selection.assert_called_once_with()
        dialog._paste_clipboard.assert_called_once_with()


class DeduplicationTests(unittest.TestCase):
    def test_same_configuration_different_names_is_tested_once_with_all_sources(self):
        first = parsed_source(source("src-a", "A"), [vless_proxy("A node")])
        second = parsed_source(source("src-b", "B"), [vless_proxy("B node")])
        merged = mihomo_checker.merge_nodes([first, second])
        self.assertEqual(1, len(merged))
        self.assertEqual(["src-a", "src-b"], merged[0].source_ids)
        self.assertEqual("A node", merged[0].source_original_names["src-a"])
        self.assertEqual("B node", merged[0].source_original_names["src-b"])

    def test_credentials_sni_and_transport_participate_in_identity(self):
        variants = []
        for field, value in (
            ("uuid", UUID_B),
            ("servername", "other.example.com"),
            ("network", "grpc"),
            ("client-fingerprint", "firefox"),
        ):
            proxy = vless_proxy()
            proxy[field] = value
            variants.append(proxy)
        ids = {mihomo_checker.proxy_node_id(vless_proxy()), *(mihomo_checker.proxy_node_id(item) for item in variants)}
        self.assertEqual(5, len(ids))


class BatchRunnerTests(unittest.TestCase):
    def test_bad_source_does_not_abort_and_duplicate_node_is_probed_once(self):
        spec_a = source("src-a", "A")
        spec_b = source("src-b", "B")
        spec_bad = source("src-bad", "Bad")
        parsed_a = parsed_source(spec_a, [vless_proxy("A")])
        parsed_b = parsed_source(spec_b, [vless_proxy("B")])
        failed = mihomo_checker.ParsedSource(
            spec=spec_bad,
            fetch_status="failed",
            parse_status="not_started",
            issues=[mihomo_checker.SourceIssue("SOURCE_FETCH_FAILED", "offline")],
        )

        class Runtime:
            def __init__(self, _binary, nodes):
                self.nodes = nodes
                self.version = "Mihomo Meta v1.19.33"

            def start(self):
                return None

            def stop(self):
                return None

        def load(item):
            return {"src-a": parsed_a, "src-b": parsed_b, "src-bad": failed}[item.source_id]

        probe = mihomo_checker.DelayResult(True, 125)
        with (
            mock.patch("scripts.mihomo_checker.load_source", side_effect=load),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch(
                "scripts.mihomo_checker.validate_runtime_nodes",
                side_effect=lambda _binary, nodes: (list(nodes), []),
            ),
            mock.patch("scripts.mihomo_checker.api_delay", return_value=probe) as delay,
            mock.patch("scripts.mihomo_checker._direct_baseline", return_value="ok"),
        ):
            report = mihomo_checker.BatchRunner().run(
                binary=Path("mihomo.exe"),
                source_specs=(spec_a, spec_bad, spec_b),
                selected_services=("ChatGPT",),
                attempts=2,
                workers=2,
            )
        self.assertEqual(1, len(report.node_results))
        self.assertEqual(["src-a", "src-b"], report.node_results[0].node.source_ids)
        self.assertEqual("good", report.node_results[0].overall_status)
        self.assertEqual(3, delay.call_count)  # two independent HTTPS runs plus one service
        self.assertEqual("SOURCE_FETCH_FAILED", report.sources[1].error_code)

    def test_base_https_failure_skips_service_checks(self):
        spec = source("src-a")
        parsed = parsed_source(spec, [vless_proxy()])

        class Runtime:
            version = "test"

            def __init__(self, *_args):
                pass

            def start(self):
                pass

            def stop(self):
                pass

        probes = [
            mihomo_checker.DelayResult(True, 100),
            mihomo_checker.DelayResult(False, error_code="TIMEOUT", error_summary="timeout"),
        ]
        with (
            mock.patch("scripts.mihomo_checker.load_source", return_value=parsed),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch(
                "scripts.mihomo_checker.validate_runtime_nodes",
                side_effect=lambda _binary, nodes: (list(nodes), []),
            ),
            mock.patch("scripts.mihomo_checker.api_delay", side_effect=probes) as delay,
            mock.patch("scripts.mihomo_checker._direct_baseline", return_value="failed"),
        ):
            report = mihomo_checker.BatchRunner().run(
                binary=Path("mihomo.exe"), source_specs=(spec,), selected_services=("YouTube",), attempts=2
            )
        result = report.node_results[0]
        self.assertEqual("failed", result.overall_status)
        self.assertEqual("TIMEOUT", result.error_code)
        self.assertEqual({}, result.services)
        self.assertEqual(2, delay.call_count)

    def test_config_rejected_node_is_isolated_from_valid_nodes(self):
        nodes = parsed_source(source("src"), [vless_proxy("Good"), vless_proxy("Bad", UUID_B)]).nodes
        # Combined config fails, first individual passes, second fails, accepted set passes.
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "mihomo.exe"
            binary.touch()
            with mock.patch(
                "scripts.mihomo_checker._check_config",
                side_effect=[(False, "combined"), (True, ""), (False, "bad"), (True, "")],
            ):
                accepted, rejected = mihomo_checker.validate_runtime_nodes(binary, nodes)
        self.assertEqual([nodes[0]], accepted)
        self.assertEqual(1, len(rejected))
        self.assertEqual("MIHOMO_CONFIG_REJECTED", rejected[0].error_code)

    def test_runtime_start_failure_is_reported_per_node(self):
        spec = source("src-a")
        parsed = parsed_source(spec, [vless_proxy()])

        class Runtime:
            version = "unknown"

            def __init__(self, *_args):
                pass

            def start(self):
                raise mihomo_checker.MihomoCheckError("MIHOMO_START_FAILED", "local API unavailable")

            def stop(self):
                pass

        with (
            mock.patch("scripts.mihomo_checker.load_source", return_value=parsed),
            mock.patch("scripts.mihomo_checker.validate_runtime_nodes", side_effect=lambda _binary, nodes: (list(nodes), [])),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch("scripts.mihomo_checker._direct_baseline", return_value="ok"),
        ):
            report = mihomo_checker.BatchRunner().run(binary=Path("mihomo.exe"), source_specs=(spec,))
        self.assertEqual("not_tested", report.node_results[0].overall_status)
        self.assertEqual("MIHOMO_START_FAILED", report.node_results[0].error_code)

    def test_no_testable_nodes_skips_direct_network_baseline(self):
        spec = source("src-bad")
        unsupported = parsed_source(
            spec,
            [{"name": "WG", "type": "wireguard", "server": "wg.example", "port": 51820}],
        )
        with (
            mock.patch("scripts.mihomo_checker.load_source", return_value=unsupported),
            mock.patch("scripts.mihomo_checker._direct_baseline") as baseline,
        ):
            report = mihomo_checker.BatchRunner().run(binary=Path("missing.exe"), source_specs=(spec,))
        baseline.assert_not_called()
        self.assertEqual("skipped", report.direct_baseline)
        self.assertEqual("unsupported", report.node_results[0].overall_status)


class ApiClassificationTests(unittest.TestCase):
    def test_delay_api_uses_expected_status_and_bearer_control(self):
        runtime = mock.Mock()
        runtime._request.return_value = b'{"delay": 87}'
        node = parsed_source(source("src"), [vless_proxy()]).nodes[0]
        result = mihomo_checker.api_delay(
            runtime, node, url="https://example.com/generate_204", timeout_ms=8000, expected="204"
        )
        self.assertTrue(result.success)
        self.assertEqual(87, result.latency_ms)
        path = runtime._request.call_args.args[0]
        self.assertIn("expected=204", path)
        self.assertIn("timeout=8000", path)

    def test_timeout_error_is_normalized_without_remote_body(self):
        runtime = mock.Mock()
        runtime._request.side_effect = urllib.error.URLError(TimeoutError("secret-token timeout"))
        node = parsed_source(source("src"), [vless_proxy()]).nodes[0]
        result = mihomo_checker.api_delay(
            runtime, node, url="https://example.com", timeout_ms=1000, expected="200-299"
        )
        self.assertFalse(result.success)
        self.assertEqual("TIMEOUT", result.error_code)
        self.assertNotIn("secret-token", result.error_summary or "")


def diagnostic_report():
    spec = source(
        "src-secret",
        f"Provider {UUID_A}",
        "url",
        "https://provider.example/subscription?token=super-secret-token-value-123456",
    )
    proxy = vless_proxy(f"Node {UUID_A}")
    proxy["private-key"] = "PRIVATE-KEY-MATERIAL-DO-NOT-LEAK"
    proxy["password"] = "PASSWORD-DO-NOT-LEAK"
    parsed = parsed_source(spec, [proxy])
    parsed.checked_at = "2026-10-27T11:00:00+03:00"
    result = mihomo_checker.NodeResult(
        parsed.nodes[0],
        overall_status="partial",
        base_successes=2,
        base_attempts=2,
        base_latency_ms=176,
        services={
            "ChatGPT": mihomo_checker.ServiceResult("reachable", 185),
            "Instagram": mihomo_checker.ServiceResult("failed", error_code="TIMEOUT", error_summary="timeout"),
        },
        error_code="SITE_PARTIAL",
        error_summary="Instagram timeout",
    )
    return mihomo_checker.BatchReport(
        generated_at="2026-10-27T11:00:00+03:00",
        engine_version="Mihomo Meta v1.19.33",
        direct_baseline="ok",
        selected_services=("ChatGPT", "Instagram"),
        attempts=2,
        timeout_ms=8000,
        sources=[parsed],
        node_results=[result],
    )


class ReportTests(unittest.TestCase):
    def test_json_contract_v1_and_source_counts(self):
        payload = mihomo_checker.report_payload(diagnostic_report())
        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("mihomo", payload["engine"]["name"])
        self.assertEqual("Windows-local", payload["engine"]["runtime_location"])
        self.assertEqual("ok", payload["test_environment"]["direct_baseline"])
        self.assertEqual(1, payload["totals"]["unique_nodes"])
        self.assertEqual(1, payload["totals"]["partial"])
        self.assertEqual(1, payload["sources"][0]["partial_nodes"])
        self.assertEqual("partial", payload["nodes"][0]["overall_status"])

    def test_public_exports_never_contain_credentials(self):
        report = diagnostic_report()
        with tempfile.TemporaryDirectory() as name:
            path = mihomo_checker.export_report_zip(report, Path(name) / "report.zip")
            with zipfile.ZipFile(path) as archive:
                self.assertEqual({"report.json", "summary.md", "nodes.csv"}, set(archive.namelist()))
                content = b"\n".join(archive.read(item) for item in archive.namelist()).decode("utf-8-sig")
        for secret in (
            UUID_A,
            "super-secret-token-value-123456",
            "PRIVATE-KEY-MATERIAL-DO-NOT-LEAK",
            "PASSWORD-DO-NOT-LEAK",
        ):
            self.assertNotIn(secret, content)
        self.assertIn("https://provider.example/<redacted>", content)
        self.assertIn("schema_version", content)

    def test_csv_has_bom_and_one_row_per_source_node_pair(self):
        report = diagnostic_report()
        duplicate_spec = source("src-second", "Second")
        report.sources.append(parsed_source(duplicate_spec, [vless_proxy()]))
        report.node_results[0].node.source_ids.append("src-second")
        report.node_results[0].node.source_original_names["src-second"] = "Second node"
        content = mihomo_checker.nodes_csv(report)
        self.assertTrue(content.startswith("\ufeff"))
        self.assertEqual(3, len(content.splitlines()))

    def test_private_yaml_keeps_full_proxy_fields_and_is_separate(self):
        report = diagnostic_report()
        report.node_results[0].overall_status = "good"
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "private.yaml"
            mihomo_checker.export_private_yaml(report, path)
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        proxy = payload["proxies"][0]
        self.assertEqual(UUID_A, proxy["uuid"])
        self.assertEqual("PRIVATE-KEY-MATERIAL-DO-NOT-LEAK", proxy["private-key"])
        self.assertEqual("/socket", proxy["ws-opts"]["path"])


class SourceStoreTests(unittest.TestCase):
    def test_sources_round_trip_without_test_results(self):
        sources = [
            source("src-000000000001", "URL", "url", "https://provider.example/sub?token=private"),
            source("src-000000000002", "Text", "text", "proxies: []"),
        ]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "sources.json"
            mihomo_checker.save_source_specs(path, sources)
            loaded = mihomo_checker.load_source_specs(path)
            raw = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(sources, loaded)
        self.assertNotIn("results", raw)
        self.assertIn("warning", raw)


class MockUiTests(unittest.TestCase):
    def test_service_cell_formats_mock_results_without_mihomo(self):
        self.assertEqual("—", MihomoCheckerTab._service_cell(None))
        self.assertEqual(
            "доступен · 42 ms",
            MihomoCheckerTab._service_cell(mihomo_checker.ServiceResult("reachable", 42)),
        )
        self.assertEqual(
            "TIMEOUT",
            MihomoCheckerTab._service_cell(mihomo_checker.ServiceResult("failed", error_code="TIMEOUT")),
        )

    def test_service_sort_places_reachable_latency_before_errors(self):
        self.assertLess(
            MihomoCheckerTab._tree_sort_value("доступен · 95 ms"),
            MihomoCheckerTab._tree_sort_value("TIMEOUT"),
        )
        self.assertLess(
            MihomoCheckerTab._tree_sort_value("доступен · 95 ms"),
            MihomoCheckerTab._tree_sort_value("доступен · 240 ms"),
        )


class PortableBuildTests(unittest.TestCase):
    def test_workflow_pins_and_packages_verified_mihomo(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "portable-checker.yml").read_text(encoding="utf-8")
        self.assertIn('MIHOMO_VERSION: "1.19.33"', workflow)
        self.assertIn("6ab2180875f9f6fff8b19386d760daec257f66b45f72b3afc650634272fa837a", workflow)
        self.assertIn('--add-binary "$env:WIREVEIL_MIHOMO;."', workflow)
        self.assertIn('"dist\\WireVeilChecker\\_internal\\mihomo.exe"', workflow)
        self.assertIn("mihomo-GPL-3.0.txt", workflow)
        self.assertIn('pull_request:', workflow)
        requirements = (root / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("PyYAML==6.0.3", requirements)


if __name__ == "__main__":
    unittest.main()
