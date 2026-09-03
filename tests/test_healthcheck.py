import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from scripts import build, healthcheck
from tests.test_build import UUID1, vmess_uri


class ConversionTests(unittest.TestCase):
    def test_supported_protocols_convert_to_sing_box(self):
        samples = {
            "vless": (
                f"vless://{UUID1}@vless.example.com:443?security=reality&type=ws"
                "&sni=cdn.example.com&pbk=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"
                "&sid=0a12&path=%2Fws&host=cdn.example.com"
            ),
            "trojan": "trojan://secret@trojan.example.com:443?security=tls&type=grpc&serviceName=x",
            "shadowsocks": "ss://aes-256-gcm:secret@ss.example.com:8388",
            "vmess": vmess_uri(),
            "hysteria2": "hy2://secret@hy.example.com:443?sni=cdn.example.com&insecure=1",
            "tuic": f"tuic://{UUID1}:secret@tuic.example.com:443?congestion_control=bbr&sni=cdn.example.com",
        }
        for protocol, uri in samples.items():
            with self.subTest(protocol=protocol):
                actual_protocol, outbound = healthcheck.uri_to_outbound(uri, "test")
                self.assertEqual(protocol, actual_protocol)
                self.assertEqual(protocol, outbound["type"])
                self.assertEqual("test", outbound["tag"])

    def test_xhttp_is_explicitly_not_marked_as_testable(self):
        uri = f"vless://{UUID1}@edge.example.com:443?security=tls&type=xhttp"
        with self.assertRaisesRegex(healthcheck.UnsupportedConfig, "xhttp"):
            healthcheck.uri_to_outbound(uri, "test")

    def test_html_encoded_tuic_query_is_normalized(self):
        uri = (
            f"tuic://{UUID1}:secret@tuic.example.com:443?congestion_control=bbr"
            "&amp;udp_relay_mode=quic&amp;allow_insecure=1"
        )
        _protocol, outbound = healthcheck.uri_to_outbound(uri, "test")
        self.assertEqual("quic", outbound["udp_relay_mode"])
        self.assertTrue(outbound["tls"]["insecure"])

    def test_hysteria2_userpass_preserves_both_parts(self):
        uri = "hysteria2://alice:secret@hy.example.com:443"
        _protocol, outbound = healthcheck.uri_to_outbound(uri, "test")
        self.assertEqual("alice:secret", outbound["password"])


class PublicationTests(unittest.TestCase):
    def candidate(self, protocol: str, index: int, delay: int):
        uris = {
            "vless": f"vless://{UUID1}@vless{index}.example.com:443?security=tls",
            "trojan": f"trojan://secret@trojan{index}.example.com:443",
        }
        uri = uris[protocol]
        parsed = build.parse_uri(uri)
        target = healthcheck.ProbeTarget(
            index, f"wv-{index:04d}", uri, protocol, {"type": protocol}
        )
        return healthcheck.ProbeResult(target, True, delay), parsed

    def test_active_output_is_mixed_and_atomic(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "README.md").write_text(
                "# Test\n" + healthcheck.README_START + "\nold\n" + healthcheck.README_END + "\n",
                encoding="utf-8",
            )
            entries = [
                self.candidate("vless", 0, 90)[0],
                self.candidate("vless", 1, 20)[0],
                self.candidate("trojan", 2, 30)[0],
            ]
            candidate_lines = [entry.target.uri for entry in entries]
            stats = healthcheck.publish_results(
                entries,
                candidate_lines=candidate_lines,
                conversion_unsupported={},
                runtime_rejected={},
                engine_version="sing-box version test",
                probe_urls=["https://example.com/generate_204"],
                root=root,
                min_active=1,
                now=dt.datetime(2026, 9, 3, 6, 0, tzinfo=dt.timezone.utc),
            )
            lines = build.validate_txt(root / "active.txt")
            self.assertEqual(3, stats["active_keys"])
            self.assertEqual("trojan", build.parse_uri(lines[1]).protocol)
            parsed_stats = json.loads((root / "active-stats.json").read_text(encoding="utf-8"))
            self.assertEqual(3, parsed_stats["output_file"]["keys"])

    def test_too_few_active_keys_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "README.md").write_text(
                healthcheck.README_START + "\nold\n" + healthcheck.README_END + "\n",
                encoding="utf-8",
            )
            (root / "active.txt").write_text("working\n", encoding="utf-8")
            with self.assertRaises(healthcheck.HealthCheckError):
                healthcheck.publish_results(
                    [],
                    candidate_lines=[],
                    conversion_unsupported={},
                    runtime_rejected={},
                    engine_version="test",
                    probe_urls=[],
                    root=root,
                    min_active=1,
                )
            self.assertEqual("working\n", (root / "active.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
