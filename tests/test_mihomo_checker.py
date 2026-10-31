import json
import subprocess
import tempfile
import threading
import time
import tkinter as tk
import unittest
import urllib.error
import zipfile
from pathlib import Path
from tkinter import ttk
from unittest import mock

import yaml

from mihomo_tab import MihomoCheckerTab, _MultilineDialog, load_ui_settings, save_ui_settings
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


def source_yaml(proxies):
    return yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)


def synthetic_nodes(count: int) -> list[mihomo_checker.NodeRecord]:
    spec = source("src-synthetic", "Synthetic")
    result: list[mihomo_checker.NodeRecord] = []
    for index in range(count):
        node_id = f"{index:064x}"
        proxy = {
            "name": f"Synthetic {index}",
            "type": "ss",
            "server": f"edge-{index}.example.com",
            "port": 10000 + (index % 50000),
            "cipher": "aes-128-gcm",
            "password": f"private-password-{index:08d}",
        }
        result.append(
            mihomo_checker.NodeRecord(
                node_id=node_id,
                runtime_name=f"wv-{index:016x}",
                protocol="ss",
                server=str(proxy["server"]),
                port=int(proxy["port"]),
                proxy=proxy,
                source_ids=[spec.source_id],
                source_original_names={spec.source_id: str(proxy["name"])},
            )
        )
    return result


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

    def test_csv_catalog_requires_subscription_url_and_preserves_provenance(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "catalog.csv"
            rows = ["id,repository,subscription_url,last_repo_push,tier,notes"]
            rows.extend(
                f"{index},owner/repo-{index},https://raw.githubusercontent.com/owner/repo-{index}/main/clash.yaml,2026-10-{index:02},start,note"
                for index in range(1, 29)
            )
            path.write_text("\ufeff" + "\n".join(rows), encoding="utf-8")
            specs = mihomo_checker.source_specs_from_file(path)

        self.assertEqual(28, len(specs))
        self.assertEqual(28, len({item.source_id for item in specs}))
        self.assertTrue(all(item.kind == "url" for item in specs))
        self.assertEqual("owner/repo-1 — clash.yaml", specs[0].name)
        self.assertEqual("owner/repo-1", specs[0].metadata["repository"])
        self.assertEqual("start", specs[0].metadata["tier"])

    def test_arbitrary_csv_is_never_treated_as_yaml(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "other.csv"
            path.write_text("name,value\nalpha,beta\n", encoding="utf-8")
            with self.assertRaises(mihomo_checker.MihomoCheckError) as raised:
                mihomo_checker.source_specs_from_file(path)
        self.assertEqual("CSV_SUBSCRIPTION_URL_REQUIRED", raised.exception.code)

    def test_github_source_names_are_distinct_and_readable(self):
        first = mihomo_checker.source_name_from_url(
            "https://raw.githubusercontent.com/owner/alpha/main/clash.yaml?token=secret"
        )
        second = mihomo_checker.source_name_from_url(
            "https://raw.githubusercontent.com/owner/beta/main/config.yaml"
        )
        self.assertEqual("owner/alpha — clash.yaml", first)
        self.assertEqual("owner/beta — config.yaml", second)
        self.assertNotIn("secret", first)

    def test_catalog_age_is_derived_without_losing_original_provenance(self):
        metadata = {"last_repo_push": "2026-10-20T12:00:00+00:00", "tier": "start"}
        self.assertEqual(
            7,
            mihomo_checker.source_age_days(metadata, "2026-10-27T15:00:00+00:00"),
        )
        self.assertEqual("2026-10-20T12:00:00+00:00", metadata["last_repo_push"])

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


class RepresentativeSamplingTests(unittest.TestCase):
    @staticmethod
    def pool(source_count: int = 28, per_source: int = 30):
        protocols = sorted(mihomo_checker.SUPPORTED_PROTOCOLS)
        parsed = []
        for source_index in range(source_count):
            spec = source(f"src-{source_index:012x}", f"Source {source_index}")
            proxies = []
            for node_index in range(per_source):
                proxies.append(
                    {
                        "name": f"Node {source_index}-{node_index}",
                        "type": protocols[node_index % len(protocols)],
                        "server": f"edge-{source_index}-{node_index}.example.com",
                        "port": 10_000 + node_index,
                        "password": f"private-{source_index}-{node_index}",
                    }
                )
            parsed.append(parsed_source(spec, proxies))
        return mihomo_checker.merge_nodes(parsed)

    def test_500_slots_cover_all_28_sources_and_balance_protocols(self):
        nodes = self.pool()
        selected, metadata = mihomo_checker.representative_sample(
            nodes, limit=500, seed="audit-2026"
        )
        per_source = metadata["per_source_selected"]
        self.assertEqual(500, len(selected))
        self.assertEqual(28, len(per_source))
        self.assertGreaterEqual(min(per_source.values()), 17)
        self.assertLessEqual(max(per_source.values()), 18)
        self.assertEqual(set(mihomo_checker.SUPPORTED_PROTOCOLS), set(metadata["per_protocol_selected"]))

    def test_sampling_is_reproducible_and_not_first_n(self):
        nodes = self.pool(source_count=4, per_source=40)
        first, _ = mihomo_checker.representative_sample(nodes, limit=50, seed="same")
        again, _ = mihomo_checker.representative_sample(nodes, limit=50, seed="same")
        other, _ = mihomo_checker.representative_sample(nodes, limit=50, seed="other")
        self.assertEqual([item.node_id for item in first], [item.node_id for item in again])
        self.assertNotEqual([item.node_id for item in first], [item.node_id for item in other])
        self.assertEqual(4, len({source_id for item in first for source_id in item.source_ids}))

    def test_per_source_stage_caps_each_provider(self):
        nodes = self.pool(source_count=6, per_source=50)
        selected, metadata = mihomo_checker.representative_sample(
            nodes, limit=None, per_source_limit=20, seed="stage-two"
        )
        self.assertEqual(120, len(selected))
        self.assertTrue(all(value == 20 for value in metadata["per_source_selected"].values()))


class BatchRunnerTests(unittest.TestCase):
    def test_28_sources_are_preflighted_independently_and_deduplicated(self):
        specs = tuple(source(f"src-{index:012x}", f"Provider {index}") for index in range(28))

        class Runtime:
            version = "test"

            def __init__(self, *_args, **_kwargs):
                pass

            def start(self):
                pass

            def stop(self):
                pass

        def load(spec):
            return source_yaml([vless_proxy(spec.name)])

        with (
            mock.patch("scripts.mihomo_checker.read_source_text", side_effect=load),
            mock.patch("scripts.mihomo_checker.validate_runtime_nodes", side_effect=lambda _binary, nodes, **_kwargs: (list(nodes), [])),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch("scripts.mihomo_checker._direct_baseline", return_value="ok"),
            mock.patch("scripts.mihomo_checker.api_delay", return_value=mihomo_checker.DelayResult(True, 50)),
        ):
            report = mihomo_checker.BatchRunner().run(
                binary=Path("mihomo.exe"), source_specs=specs, selected_services=()
            )

        self.assertEqual(28, len(report.sources))
        self.assertTrue(all(item.fetch_status == "ok" for item in report.sources))
        self.assertEqual(1, len(report.node_results))
        self.assertEqual(28, len(report.node_results[0].node.source_ids))

    def test_unsupported_nodes_are_classified_even_outside_sample(self):
        spec = source("src-mixed")
        proxies = [
            vless_proxy("One", server="one.example.com"),
            vless_proxy("Two", uuid=UUID_B, server="two.example.com"),
            {"name": "WG", "type": "wireguard", "server": "wg.example.com", "port": 51820},
        ]

        class Runtime:
            version = "test"

            def __init__(self, *_args, **_kwargs):
                pass

            def start(self):
                pass

            def stop(self):
                pass

        with (
            mock.patch("scripts.mihomo_checker.read_source_text", return_value=source_yaml(proxies)),
            mock.patch("scripts.mihomo_checker.validate_runtime_nodes", side_effect=lambda _binary, nodes, **_kwargs: (list(nodes), [])),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch("scripts.mihomo_checker._direct_baseline", return_value="ok"),
            mock.patch("scripts.mihomo_checker.api_delay", return_value=mihomo_checker.DelayResult(True, 50)),
        ):
            report = mihomo_checker.BatchRunner().run(
                binary=Path("mihomo.exe"), source_specs=(spec,), node_limit=1, selected_services=()
            )
        self.assertEqual(1, sum(item.overall_status == "unsupported" for item in report.node_results))
        self.assertEqual(1, sum(item.error_code == "SAMPLE_LIMIT" for item in report.node_results))

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
            def __init__(self, _binary, nodes, **_kwargs):
                self.nodes = nodes
                self.version = "Mihomo Meta v1.19.33"

            def start(self):
                return None

            def stop(self):
                return None

        def load(item):
            if item.source_id == "src-bad":
                raise mihomo_checker.MihomoCheckError("SOURCE_FETCH_FAILED", "offline")
            proxy = vless_proxy("A" if item.source_id == "src-a" else "B")
            return source_yaml([proxy])

        probe = mihomo_checker.DelayResult(True, 125)
        with (
            mock.patch("scripts.mihomo_checker.read_source_text", side_effect=load),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch(
                "scripts.mihomo_checker.validate_runtime_nodes",
                side_effect=lambda _binary, nodes, **_kwargs: (list(nodes), []),
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

            def __init__(self, *_args, **_kwargs):
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
            mock.patch("scripts.mihomo_checker.read_source_text", return_value=source_yaml([vless_proxy()])),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch(
                "scripts.mihomo_checker.validate_runtime_nodes",
                side_effect=lambda _binary, nodes, **_kwargs: (list(nodes), []),
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
                side_effect=[(False, "combined"), (True, ""), (True, ""), (False, "bad")],
            ):
                accepted, rejected = mihomo_checker.validate_runtime_nodes(binary, nodes)
        self.assertEqual([nodes[0]], accepted)
        self.assertEqual(1, len(rejected))
        self.assertEqual("MIHOMO_CONFIG_REJECTED", rejected[0].error_code)
        self.assertEqual("not_tested", rejected[0].overall_status)
        self.assertEqual("invalid_configuration", rejected[0].error_category)

    def test_runtime_start_failure_is_reported_per_node(self):
        spec = source("src-a")
        parsed = parsed_source(spec, [vless_proxy()])

        class Runtime:
            version = "unknown"

            def __init__(self, *_args, **_kwargs):
                pass

            def start(self):
                raise mihomo_checker.MihomoCheckError("MIHOMO_START_FAILED", "local API unavailable")

            def stop(self):
                pass

        with (
            mock.patch("scripts.mihomo_checker.read_source_text", return_value=source_yaml([vless_proxy()])),
            mock.patch("scripts.mihomo_checker.validate_runtime_nodes", side_effect=lambda _binary, nodes, **_kwargs: (list(nodes), [])),
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
            mock.patch(
                "scripts.mihomo_checker.read_source_text",
                return_value=source_yaml(
                    [{"name": "WG", "type": "wireguard", "server": "wg.example", "port": 51820}]
                ),
            ),
            mock.patch("scripts.mihomo_checker._direct_baseline") as baseline,
        ):
            report = mihomo_checker.BatchRunner().run(binary=Path("missing.exe"), source_specs=(spec,))
        baseline.assert_not_called()
        self.assertEqual("skipped", report.direct_baseline)
        self.assertEqual("unsupported", report.node_results[0].overall_status)

    def test_progress_covers_all_stages_and_quick_limit_keeps_omitted_nodes(self):
        spec = source("src-many")
        proxies = [item.proxy for item in synthetic_nodes(3)]
        updates: list[mihomo_checker.ProgressUpdate] = []

        class Runtime:
            version = "test"

            def __init__(self, *_args, **_kwargs):
                pass

            def start(self):
                pass

            def stop(self):
                pass

        with (
            mock.patch("scripts.mihomo_checker.read_source_text", return_value=source_yaml(proxies)),
            mock.patch(
                "scripts.mihomo_checker.validate_runtime_nodes",
                side_effect=lambda _binary, nodes, **_kwargs: (list(nodes), []),
            ),
            mock.patch("scripts.mihomo_checker.MihomoRuntime", Runtime),
            mock.patch("scripts.mihomo_checker._direct_baseline", return_value="ok"),
            mock.patch(
                "scripts.mihomo_checker.api_delay",
                return_value=mihomo_checker.DelayResult(True, 50),
            ),
        ):
            report = mihomo_checker.BatchRunner().run(
                binary=Path("mihomo.exe"),
                source_specs=(spec,),
                selected_services=("ChatGPT",),
                node_limit=1,
                progress_callback=updates.append,
            )

        self.assertEqual(3, len(report.node_results))
        self.assertEqual(1, sum(item.overall_status == "good" for item in report.node_results))
        self.assertEqual(2, sum(item.error_code == "SAMPLE_LIMIT" for item in report.node_results))
        self.assertEqual("source_protocol_round_robin_v1", report.sampling["strategy"])
        self.assertEqual(set(mihomo_checker.STAGE_LABELS), {item.stage for item in updates})
        self.assertEqual(100.0, updates[-1].overall_percent)
        self.assertEqual(
            sorted(item.overall_percent for item in updates),
            [item.overall_percent for item in updates],
        )

    def test_cancelled_preparation_returns_partial_report(self):
        spec = source("src-cancel")
        runner = mihomo_checker.BatchRunner()

        def load(_spec):
            runner.stop()
            return source_yaml([vless_proxy()])

        with mock.patch("scripts.mihomo_checker.read_source_text", side_effect=load):
            report = runner.run(binary=Path("mihomo.exe"), source_specs=(spec,))

        self.assertEqual("cancelled", report.sources[0].fetch_status)
        self.assertEqual([], report.node_results)


class ValidationScalingTests(unittest.TestCase):
    def test_single_bad_node_in_5257_is_localized_with_logarithmic_checks(self):
        nodes = synthetic_nodes(5_257)
        bad = nodes[4_321]
        calls = 0

        def check(_binary, path, **_kwargs):
            nonlocal calls
            calls += 1
            if path.name == "base.yaml":
                return True, ""
            return bad.runtime_name not in path.read_text(encoding="utf-8"), "rejected"

        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "mihomo.exe"
            binary.touch()
            with mock.patch("scripts.mihomo_checker._check_config", side_effect=check):
                accepted, rejected = mihomo_checker.validate_runtime_nodes(binary, nodes)

        self.assertEqual(5_256, len(accepted))
        self.assertEqual([bad.node_id], [item.node.node_id for item in rejected])
        self.assertLess(calls, 40)

    def test_common_config_failure_stops_after_base_probe(self):
        nodes = synthetic_nodes(5_000)
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "mihomo.exe"
            binary.touch()
            check = mock.Mock(return_value=(False, "common failure"))
            with mock.patch("scripts.mihomo_checker._check_config", check):
                accepted, results = mihomo_checker.validate_runtime_nodes(binary, nodes)

        self.assertEqual([], accepted)
        self.assertEqual(2, check.call_count)
        self.assertEqual(5_000, len(results))
        self.assertTrue(all(item.error_code == "MIHOMO_COMMON_CONFIG_REJECTED" for item in results))

    def test_validation_cancel_preserves_every_unresolved_node(self):
        nodes = synthetic_nodes(500)
        cancel_event = threading.Event()

        def check(_binary, _path, **_kwargs):
            cancel_event.set()
            return False, "CANCELLED"

        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "mihomo.exe"
            binary.touch()
            with mock.patch("scripts.mihomo_checker._check_config", side_effect=check) as checked:
                accepted, results = mihomo_checker.validate_runtime_nodes(
                    binary,
                    nodes,
                    cancel_event=cancel_event,
                )

        self.assertEqual([], accepted)
        self.assertEqual(1, checked.call_count)
        self.assertEqual(500, len(results))
        self.assertTrue(all(item.error_code == "CANCELLED" for item in results))

    def test_validation_timeout_does_not_split_batch(self):
        nodes = synthetic_nodes(500)
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "mihomo.exe"
            binary.touch()
            check = mock.Mock(return_value=(False, "TIMEOUT"))
            with mock.patch("scripts.mihomo_checker._check_config", check):
                accepted, results = mihomo_checker.validate_runtime_nodes(binary, nodes)

        self.assertEqual([], accepted)
        self.assertEqual(1, check.call_count)
        self.assertEqual(500, len(results))
        self.assertTrue(all(item.error_code == "MIHOMO_CONFIG_TIMEOUT" for item in results))

    def test_many_invalid_nodes_respect_validation_process_budget(self):
        nodes = synthetic_nodes(5_000)

        def check(_binary, path, **_kwargs):
            return (True, "") if path.name == "base.yaml" else (False, "node rejected")

        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "mihomo.exe"
            binary.touch()
            with mock.patch("scripts.mihomo_checker._check_config", side_effect=check) as checked:
                accepted, results = mihomo_checker.validate_runtime_nodes(
                    binary,
                    nodes,
                    max_checks=12,
                )

        self.assertEqual([], accepted)
        self.assertLessEqual(checked.call_count, 12)
        self.assertEqual(5_000, len(results))
        self.assertTrue(any(item.error_code == "MIHOMO_VALIDATION_LIMIT" for item in results))

    def test_stop_terminates_active_validation_child(self):
        runner = mihomo_checker.BatchRunner()
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        runner._set_validation_process(process)

        runner.stop()

        process.terminate.assert_called_once_with()

    def test_check_config_timeout_terminates_child(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        with mock.patch("scripts.mihomo_checker.subprocess.Popen", return_value=process):
            valid, detail = mihomo_checker._check_config(
                Path("mihomo.exe"),
                Path("config.yaml"),
                timeout=0,
            )
        self.assertFalse(valid)
        self.assertEqual("TIMEOUT", detail)
        process.terminate.assert_called_once_with()


class LargeSubscriptionPerformanceTests(unittest.TestCase):
    def test_parse_and_deduplicate_10000_synthetic_nodes(self):
        proxies = [item.proxy for item in synthetic_nodes(10_000)]
        text = source_yaml(proxies)
        started = time.monotonic()

        parsed = mihomo_checker.parse_source_text(source("src-10000"), text)
        merged = mihomo_checker.merge_nodes([parsed])
        elapsed = time.monotonic() - started

        self.assertEqual("ok", parsed.parse_status)
        self.assertEqual(10_000, len(merged))
        self.assertLess(elapsed, 20.0)

    def test_representative_sampling_scales_to_20000_nodes(self):
        nodes = synthetic_nodes(20_000)
        for index, node in enumerate(nodes):
            node.source_ids = [f"src-{index % 28:012x}"]
        started = time.monotonic()
        selected, metadata = mihomo_checker.representative_sample(
            nodes, limit=500, seed="load-test"
        )
        elapsed = time.monotonic() - started
        self.assertEqual(500, len(selected))
        self.assertEqual(28, len(metadata["per_source_selected"]))
        self.assertLess(elapsed, 10.0)

    def test_offline_benchmark_covers_5k_10k_and_20k(self):
        script = (Path(__file__).resolve().parents[1] / "scripts" / "mihomo_benchmark.py").read_text(encoding="utf-8")
        self.assertIn("default=[5_000, 10_000, 20_000]", script)
        self.assertIn("tree_batch_update_seconds", script)
        self.assertIn("tracemalloc", script)


class ProgressSecurityTests(unittest.TestCase):
    def test_progress_messages_are_sanitized_before_ui_callback(self):
        updates: list[mihomo_checker.ProgressUpdate] = []
        reporter = mihomo_checker._ProgressReporter(updates.append)
        secret_url = "https://provider.example/sub?token=super-secret-token-value"

        reporter.emit(
            "loading",
            1,
            1,
            f"uuid={UUID_A} password=hidden-value source={secret_url}",
            force=True,
        )

        message = updates[0].message
        self.assertNotIn(UUID_A, message)
        self.assertNotIn("hidden-value", message)
        self.assertNotIn("super-secret-token-value", message)
        self.assertIn("https://provider.example/<redacted>", message)


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

    def test_controller_503_is_not_reported_as_target_http_status(self):
        runtime = mock.Mock()
        error = urllib.error.HTTPError(
            "http://127.0.0.1:9090/proxies/node/delay", 503, "upstream secret", {}, None
        )
        runtime._request.side_effect = error
        node = parsed_source(source("src"), [vless_proxy()]).nodes[0]
        result = mihomo_checker.api_delay(
            runtime, node, url="https://chatgpt.com/", timeout_ms=8000, expected="200-499"
        )
        self.assertFalse(result.success)
        self.assertEqual("CONTROLLER_API_503", result.error_code)
        self.assertEqual("controller_api", result.error_category)
        self.assertEqual(503, result.controller_http_status)
        self.assertNotIn("chatgpt", result.error_summary or "")
        error.close()

    def test_base_endpoints_are_kept_separately(self):
        node = parsed_source(source("src"), [vless_proxy()]).nodes[0]
        cancel = threading.Event()
        with mock.patch(
            "scripts.mihomo_checker.api_delay",
            side_effect=[
                mihomo_checker.DelayResult(True, 40),
                mihomo_checker.DelayResult(False, error_code="TIMEOUT", error_summary="timeout", error_category="network"),
            ],
        ):
            strict = mihomo_checker._probe_base_node(
                mock.Mock(), node, attempts=2, timeout_ms=8000, cancel_event=cancel
            )
        self.assertEqual({"gstatic", "cloudflare"}, set(strict.base_endpoint_results))
        self.assertEqual(1, strict.base_successes)
        self.assertEqual("failed", strict.overall_status)
        self.assertEqual("TIMEOUT", strict.error_code)

    def test_one_of_two_policy_marks_unstable_but_allows_services(self):
        node = parsed_source(source("src"), [vless_proxy()]).nodes[0]
        with mock.patch(
            "scripts.mihomo_checker.api_delay",
            side_effect=[
                mihomo_checker.DelayResult(True, 40),
                mihomo_checker.DelayResult(False, error_code="TIMEOUT", error_summary="timeout", error_category="network"),
            ],
        ):
            result = mihomo_checker._probe_base_node(
                mock.Mock(), node, attempts=2, timeout_ms=8000,
                cancel_event=threading.Event(), minimum_successes=1,
            )
        self.assertEqual("not_tested", result.overall_status)
        self.assertEqual("UNSTABLE_BASE_HTTPS", result.base_error_code)

    def test_timeout_storm_reduces_base_concurrency_to_eight(self):
        nodes = synthetic_nodes(32)

        def fail(_runtime, node, **_kwargs):
            probe = mihomo_checker.DelayResult(
                False, error_code="TIMEOUT", error_summary="timeout", error_category="network"
            )
            return mihomo_checker.NodeResult(
                node,
                overall_status="failed",
                base_attempts=2,
                base_error_code="TIMEOUT",
                error_code="TIMEOUT",
                error_category="network",
                base_endpoint_results={"gstatic": [probe], "cloudflare": [probe]},
            )

        with mock.patch("scripts.mihomo_checker._probe_base_node", side_effect=fail):
            results, effective, events = mihomo_checker._run_base_probes_adaptive(
                mock.Mock(), nodes, attempts=2, timeout_ms=8000, workers=16,
                minimum_successes=2, cancel_event=threading.Event(),
            )
        self.assertEqual(32, len(results))
        self.assertEqual(8, effective)
        self.assertEqual("concurrency_reduced", events[0]["event"])

    def test_service_checks_never_exceed_eight_concurrent_nodes(self):
        base_results = [mihomo_checker.NodeResult(node) for node in synthetic_nodes(24)]
        active = 0
        maximum = 0
        lock = threading.Lock()

        def probe(_runtime, result, **_kwargs):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.01)
            with lock:
                active -= 1
            result.overall_status = "good"
            return result

        with mock.patch("scripts.mihomo_checker._probe_services_node", side_effect=probe):
            completed = mihomo_checker._run_service_probes_bounded(
                mock.Mock(), base_results,
                services=(mihomo_checker.SERVICE_DEFINITIONS[0],),
                timeout_ms=8000,
                cancel_event=threading.Event(),
            )
        self.assertEqual(24, len(completed))
        self.assertLessEqual(maximum, 8)
        self.assertGreater(maximum, 1)


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
        base_endpoint_results={
            "gstatic": [mihomo_checker.DelayResult(True, 170)],
            "cloudflare": [mihomo_checker.DelayResult(True, 182)],
        },
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
        sampling={"strategy": "source_protocol_round_robin_v1", "seed": "audit", "selected_nodes": 1},
        requested_workers=16,
        effective_workers=8,
        adaptive_events=[{"event": "concurrency_reduced", "from": 16, "to": 8}],
        mihomo_stderr_summary=f"uuid={UUID_A} token=super-secret-token-value-123456",
    )


class ReportTests(unittest.TestCase):
    def test_json_contract_v2_and_source_counts(self):
        payload = mihomo_checker.report_payload(diagnostic_report())
        self.assertEqual(2, payload["schema_version"])
        self.assertEqual("mihomo", payload["engine"]["name"])
        self.assertEqual("Windows-local", payload["engine"]["runtime_location"])
        self.assertEqual("ok", payload["test_environment"]["direct_baseline"])
        self.assertEqual(1, payload["totals"]["unique_nodes"])
        self.assertEqual(1, payload["totals"]["partial"])
        self.assertEqual(1, payload["sources"][0]["partial_nodes"])
        self.assertIn("age_days", payload["sources"][0])
        self.assertEqual("partial", payload["nodes"][0]["overall_status"])
        self.assertEqual(1, payload["nodes"][0]["base_https"]["endpoints"]["gstatic"]["successes"])
        self.assertEqual("source_protocol_round_robin_v1", payload["sampling"]["strategy"])
        self.assertEqual(8, payload["test_environment"]["base_workers_effective"])
        self.assertIn("vless", payload["capability_matrix"]["runtime_tested_protocols"])

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
            mihomo_checker.SourceSpec(
                "src-000000000001", "URL", "url",
                "https://provider.example/sub?token=private",
                {"repository": "owner/repo", "last_repo_push": "2026-10-20"},
            ),
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
    def test_duplicate_source_url_is_warned_and_not_added(self):
        existing = mihomo_checker.SourceSpec(
            "src-000000000001", "Existing", "url", "https://provider.example/sub.yaml"
        )
        duplicate = mihomo_checker.SourceSpec(
            "src-000000000002", "Duplicate", "url", "https://PROVIDER.example:443/sub.yaml#copy"
        )
        tab = object.__new__(MihomoCheckerTab)
        tab.sources = [existing]
        tab._save_sources = mock.Mock()
        tab._refresh_source_tree = mock.Mock()
        tab.status_var = mock.Mock()
        tab.state_var = mock.Mock()
        with mock.patch("mihomo_tab.messagebox.showwarning") as warning:
            tab._append_sources([duplicate])
        self.assertEqual([existing], tab.sources)
        warning.assert_called_once()
        tab._save_sources.assert_not_called()

    def test_service_cell_formats_mock_results_without_mihomo(self):
        self.assertEqual("—", MihomoCheckerTab._service_cell(None))
        self.assertEqual(
            "● 42",
            MihomoCheckerTab._service_cell(mihomo_checker.ServiceResult("reachable", 42)),
        )
        self.assertEqual(
            "× TIMEOUT",
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

    def test_live_result_updates_existing_tree_row_without_full_rebuild(self):
        spec = source("src-ui", "UI")
        node = synthetic_nodes(1)[0]
        node.source_ids = [spec.source_id]
        node.source_original_names = {spec.source_id: "Node"}
        first = mihomo_checker.NodeResult(node, overall_status="failed", error_code="TIMEOUT")
        second = mihomo_checker.NodeResult(node, overall_status="good", base_latency_ms=42)
        tab = object.__new__(MihomoCheckerTab)
        tab.sources = [spec]
        tab.node_tree = mock.Mock()
        tab.node_tree.exists.side_effect = [False, True]
        tab.source_filter_var = mock.Mock()
        tab.source_filter_var.get.return_value = "Все источники"
        tab.status_filter_var = mock.Mock()
        tab.status_filter_var.get.return_value = "Все статусы"
        tab.service_filter_var = mock.Mock()
        tab.service_filter_var.get.return_value = "Все сервисы"

        tab._update_node_rows([first])
        tab._update_node_rows([second])

        tab.node_tree.insert.assert_called_once()
        tab.node_tree.item.assert_called_once()
        tab.node_tree.delete.assert_not_called()


class MihomoUiLayoutTests(unittest.TestCase):
    def test_ui_settings_persist_accessibility_and_sampling_choices(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "ui.json"
            save_ui_settings(
                path,
                {
                    "font_size": 14,
                    "workers": 24,
                    "sample_mode": "20 на источник",
                    "sampling_seed": "reproducible",
                    "base_policy": "Достаточно 1/2",
                    "table_mode": "Подробно",
                },
            )
            loaded = load_ui_settings(path)
        self.assertEqual(14, loaded["font_size"])
        self.assertEqual(24, loaded["workers"])
        self.assertEqual("20 на источник", loaded["sample_mode"])
        self.assertEqual("reproducible", loaded["sampling_seed"])

    def test_1280_layout_remains_usable_at_125_and_150_percent_scaling(self):
        for scaling in (1.25, 1.5):
            root = None
            try:
                root = tk.Tk()
            except tk.TclError as exc:
                self.skipTest(f"Tk display unavailable: {exc}")
            try:
                root.tk.call("tk", "scaling", scaling)
                root.geometry("1280x720")
                with (
                    mock.patch("mihomo_tab.mihomo_checker.load_source_specs", return_value=[]),
                    mock.patch.object(MihomoCheckerTab, "_save_ui_settings"),
                ):
                    tab = MihomoCheckerTab(root)
                    tab.pack(fill="both", expand=True)
                    root.update()
                    self.assertLessEqual(tab.winfo_reqwidth(), 1280)
                    self.assertGreaterEqual(tab.views.winfo_height(), 150)
                    self.assertIsInstance(tab.add_source_button, ttk.Menubutton)
                    self.assertEqual(3, tab.add_source_menu.index("end"))
                    self.assertEqual(3, tab.source_actions_menu.index("end"))
                    self.assertEqual(2, tab.export_menu.index("end"))
                    self.assertFalse(tab.advanced_visible)
                    self.assertFalse(tab.advanced_frame.winfo_ismapped())
                    tab._toggle_advanced_settings()
                    root.update_idletasks()
                    self.assertTrue(tab.advanced_frame.winfo_ismapped())
                    tab._toggle_advanced_settings()
                    root.update_idletasks()
                    self.assertFalse(tab.advanced_frame.winfo_ismapped())
                    self.assertEqual(
                        ("source", "name", "protocol", "status", "base", "chatgpt", "instagram", "spotify", "error"),
                        tuple(tab.node_tree["displaycolumns"]),
                    )
                    self.assertLessEqual(
                        tab.stop_button.winfo_y() + tab.stop_button.winfo_height(),
                        tab.check_panel.winfo_height(),
                    )
                    tab.close()
            finally:
                if root is not None:
                    root.destroy()


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
