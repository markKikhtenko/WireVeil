import json
import tempfile
import tkinter as tk
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import yaml

from router_subscription import (
    AUTO_TEST_URL,
    RouterSubscriptionServer,
    build_router_yaml,
    new_subscription_token,
    valid_subscription_token,
)
from router_subscription_tab import RouterSubscriptionTab, load_router_settings, save_router_settings
from scripts import mihomo_checker


def sample_report() -> mihomo_checker.BatchReport:
    source = mihomo_checker.SourceSpec("src-000000000001", "Provider", "text", "private")
    parsed = mihomo_checker.ParsedSource(source, fetch_status="ok", parse_status="ok")
    good_node = mihomo_checker.NodeRecord(
        "a" * 64,
        "wv-good",
        "ss",
        "good.example",
        443,
        {"name": "Good", "type": "ss", "server": "good.example", "port": 443, "cipher": "aes-128-gcm", "password": "secret"},
        [source.source_id],
        {source.source_id: "Good"},
    )
    failed_node = mihomo_checker.NodeRecord(
        "b" * 64,
        "wv-failed",
        "ss",
        "failed.example",
        443,
        {"name": "Failed", "type": "ss", "server": "failed.example", "port": 443, "cipher": "aes-128-gcm", "password": "secret"},
        [source.source_id],
        {source.source_id: "Failed"},
    )
    return mihomo_checker.BatchReport(
        generated_at="2026-11-16T12:00:00+03:00",
        engine_version="test",
        direct_baseline="ok",
        selected_services=(),
        attempts=2,
        timeout_ms=8000,
        sources=[parsed],
        node_results=[
            mihomo_checker.NodeResult(good_node, overall_status="ready"),
            mihomo_checker.NodeResult(failed_node, overall_status="failed"),
        ],
    )


class RouterYamlTests(unittest.TestCase):
    def test_build_includes_accepted_nodes_without_network_results(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "router.yaml"
            payload = build_router_yaml(sample_report(), path)
        document = yaml.safe_load(payload)
        proxy_names = [item["name"] for item in document["proxies"]]
        groups = {item["name"]: item for item in document["proxy-groups"]}
        self.assertEqual(["Good"], proxy_names)
        self.assertEqual(["AUTO", "MANUAL", "PROXY"], list(groups))
        self.assertEqual(proxy_names, groups["AUTO"]["proxies"])
        self.assertEqual("url-test", groups["AUTO"]["type"])
        self.assertEqual(AUTO_TEST_URL, groups["AUTO"]["url"])
        self.assertEqual(900, groups["AUTO"]["interval"])
        self.assertEqual(100, groups["AUTO"]["tolerance"])
        self.assertIs(True, groups["AUTO"]["lazy"])
        self.assertEqual(
            {"name", "type", "proxies", "url", "interval", "tolerance", "lazy"},
            set(groups["AUTO"]),
        )
        self.assertEqual(proxy_names, groups["MANUAL"]["proxies"])
        self.assertEqual("select", groups["MANUAL"]["type"])
        self.assertEqual(["AUTO", "MANUAL"], groups["PROXY"]["proxies"])
        self.assertEqual("select", groups["PROXY"]["type"])
        self.assertNotIn("GLOBAL", groups)
        self.assertNotIn("ALL", groups)
        self.assertNotIn("DIRECT", groups)
        self.assertEqual("MATCH,PROXY", document["rules"][-1])
        self.assertNotIn("Failed", payload.decode("utf-8"))
        self.assertNotIn(b"&id", payload)
        self.assertNotIn(b"*id", payload)

    def test_reserved_proxy_names_are_renamed_and_group_references_stay_valid(self):
        for reserved_name in ("AUTO", "MANUAL", "PROXY", "DIRECT"):
            with self.subTest(reserved_name=reserved_name):
                report = sample_report()
                report.node_results[0].node.proxy["name"] = reserved_name
                with tempfile.TemporaryDirectory() as name:
                    payload = build_router_yaml(report, Path(name) / "router.yaml")
                document = yaml.safe_load(payload)
                proxy_names = [item["name"] for item in document["proxies"]]
                groups = {
                    item["name"]: item for item in document["proxy-groups"]
                }
                self.assertEqual([f"{reserved_name} [2]"], proxy_names)
                self.assertEqual(proxy_names, groups["AUTO"]["proxies"])
                self.assertEqual(proxy_names, groups["MANUAL"]["proxies"])
                self.assertTrue(set(proxy_names).isdisjoint(groups))

    def test_failed_build_preserves_previous_subscription(self):
        report = sample_report()
        report.node_results[0].overall_status = "failed"
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "router.yaml"
            path.write_bytes(b"previous\n")
            with self.assertRaises(mihomo_checker.MihomoCheckError):
                build_router_yaml(report, path)
            self.assertEqual(b"previous\n", path.read_bytes())


class RouterServerTests(unittest.TestCase):
    def test_serves_only_tokenized_yaml_route_and_updates_content(self):
        token = "1" * 32
        server = RouterSubscriptionServer(token, lan_ip_provider=lambda: "127.0.0.1")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            server.set_content(b"proxies: []\n")
            url = server.start(0)
            with opener.open(url, timeout=3) as response:
                self.assertEqual("application/yaml; charset=utf-8", response.headers["Content-Type"])
                self.assertEqual(b"proxies: []\n", response.read())
            server.set_content(b"proxies:\n  - name: updated\n")
            with opener.open(url, timeout=3) as response:
                self.assertIn(b"updated", response.read())
            try:
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    opener.open(url.rsplit("/", 1)[0] + "/wrong.yaml", timeout=3)
                self.assertEqual(404, caught.exception.code)
            finally:
                caught.exception.close()
        finally:
            server.stop()
        self.assertFalse(server.running)

    def test_tokens_are_valid_and_random(self):
        first = new_subscription_token()
        second = new_subscription_token()
        self.assertTrue(valid_subscription_token(first))
        self.assertNotEqual(first, second)
        self.assertFalse(valid_subscription_token("short"))


class RouterSettingsTests(unittest.TestCase):
    def test_round_trip_keeps_stable_url_token_and_selection(self):
        token = "a" * 32
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "settings.json"
            save_router_settings(
                path,
                {
                    "port": 19090,
                    "attempts": 3,
                    "timeout": 12,
                    "workers": 24,
                    "token": token,
                    "enabled_source_ids": ["src-000000000001"],
                },
            )
            loaded = load_router_settings(path)
            raw = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(19090, loaded["port"])
        self.assertEqual(token, loaded["token"])
        self.assertEqual(["src-000000000001"], loaded["enabled_source_ids"])
        self.assertEqual(token, raw["token"])


class RouterUiLayoutTests(unittest.TestCase):
    def test_third_tab_fits_1280_by_720(self):
        root = None
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")
        try:
            root.tk.call("tk", "scaling", 1.5)
            root.geometry("1280x720")
            with tempfile.TemporaryDirectory() as name:
                base = Path(name)
                with mock.patch(
                    "router_subscription_tab.user_data_file",
                    side_effect=lambda filename: base / filename,
                ):
                    tab = RouterSubscriptionTab(root)
                    tab.pack(fill="both", expand=True)
                    root.update()
                    self.assertLessEqual(tab.winfo_reqwidth(), 1280)
                    self.assertLessEqual(tab.winfo_reqheight(), 640)
                    self.assertEqual("disabled", str(tab.build_button["state"]))
                    tab.close()
        finally:
            if root is not None:
                root.destroy()


if __name__ == "__main__":
    unittest.main()
