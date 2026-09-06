import dataclasses
import datetime as dt
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import build, healthcheck
from tests.test_build import UUID1, UUID2, vmess_uri


class GoodConfigTests(unittest.TestCase):
    def test_cli_defaults_to_repository_config(self):
        args = healthcheck.parse_args(["--sing-box", "sing-box"])
        self.assertEqual(healthcheck.CONFIG_PATH, args.config)
        # The checked-in threshold and enabled flag can change without breaking CI.
        healthcheck.load_good_config(args.config)

    def test_config_defaults_and_custom_values(self):
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "config.json"
            for data, expected in (
                ({}, healthcheck.GoodConfig(True, 500)),
                ({"good": {}}, healthcheck.GoodConfig(True, 500)),
                (
                    {"good": {"enabled": False, "max_latency_ms": 250}},
                    healthcheck.GoodConfig(False, 250),
                ),
            ):
                with self.subTest(data=data):
                    config.write_text(json.dumps(data), encoding="utf-8")
                    self.assertEqual(expected, healthcheck.load_good_config(config))

    def test_invalid_config_is_rejected(self):
        invalid = [[], {"good": None}, {"good": {"max_latncy_ms": 50}}]
        invalid.extend({"good": {"enabled": value}} for value in ("false", 0, None))
        invalid.extend(
            {"good": {"max_latency_ms": value}}
            for value in (0, -1, True, 1.5, "500", None)
        )
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "config.json"
            for data in invalid:
                with self.subTest(data=data):
                    config.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(healthcheck.HealthCheckError):
                        healthcheck.load_good_config(config)
            config.write_text("{", encoding="utf-8")
            with self.assertRaises(healthcheck.HealthCheckError):
                healthcheck.load_good_config(config)
            with self.assertRaises(healthcheck.HealthCheckError):
                healthcheck.load_good_config(Path(name) / "missing.json")

    def test_cli_forwards_custom_good_config_without_changing_probe_options(self):
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "config.json"
            config.write_text('{"good": {"max_latency_ms": 250}}', encoding="utf-8")
            with mock.patch.object(healthcheck, "healthcheck") as run:
                status = healthcheck.main(["--sing-box", "sing-box", "--config", str(config)])
                self.assertEqual(0, status)
            options = run.call_args.kwargs
            self.assertEqual(healthcheck.GoodConfig(True, 250), options["good"])
            self.assertEqual(8000, options["timeout_ms"])
            self.assertEqual(64, options["workers"])
            self.assertEqual(10, options["min_active"])
            self.assertEqual(healthcheck.DEFAULT_PROBE_URLS, options["probe_urls"])

    def test_invalid_config_stops_before_healthcheck(self):
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "config.json"
            config.write_text('{"good": {"max_latency_ms": -1}}', encoding="utf-8")
            with (
                mock.patch.object(healthcheck, "healthcheck") as run,
                mock.patch("sys.stderr", new_callable=io.StringIO),
            ):
                status = healthcheck.main(["--sing-box", "sing-box", "--config", str(config)])
                self.assertEqual(1, status)
            run.assert_not_called()


class ConversionTests(unittest.TestCase):
    def test_cli_defaults_test_every_input_key(self):
        args = healthcheck.parse_args(["--sing-box", "sing-box"])
        self.assertIsNone(args.expected_keys)

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
    def candidate(self, protocol: str, index: int, delay: int | None):
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

    def make_root(self, root: Path):
        (root / "README.md").write_text(
            "# Test\n" + healthcheck.README_START + "\nold\n" + healthcheck.README_END + "\n",
            encoding="utf-8",
        )

    def publish(self, root: Path, results, good=healthcheck.GoodConfig()):
        return healthcheck.publish_results(
            results,
            candidate_lines=[result.target.uri for result in results],
            conversion_unsupported={},
            runtime_rejected={},
            engine_version="sing-box version test",
            probe_urls=healthcheck.DEFAULT_PROBE_URLS,
            root=root,
            min_active=1,
            good=good,
        )

    def test_good_filters_slow_failed_unknown_and_fallback_errors(self):
        entries = [
            self.candidate("vless", 0, 40)[0],
            self.candidate("trojan", 1, 500)[0],
            self.candidate("vless", 2, 501)[0],
            dataclasses.replace(
                self.candidate("trojan", 3, None)[0],
                active=False, error="TimeoutError: timed out",
            ),
            dataclasses.replace(
                self.candidate("vless", 4, None)[0], active=False, error="HTTP 503",
            ),
            dataclasses.replace(
                self.candidate("trojan", 5, 100)[0], error="HTTP 504: Timeout",
            ),
            self.candidate("vless", 6, None)[0],
        ]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            stats = self.publish(root, entries)
            # Preserve the existing active order, including slow and fallback successes.
            expected_active = [entries[index].target.uri for index in (0, 5, 2, 1, 6)]
            self.assertEqual(expected_active, build.validate_txt(root / "active.txt"))
            good_lines = build.validate_txt(root / "good.txt")
            self.assertEqual([entries[index].target.uri for index in (0, 1)], good_lines)
            self.assertTrue(set(good_lines) <= set(expected_active))
            self.assertEqual(5, stats["total_active"])
            self.assertEqual(2, stats["total_good"])
            latency_fields = ("latency_min", "latency_avg", "latency_max")
            self.assertEqual((40, 285.25, 501), tuple(stats[key] for key in latency_fields))
            self.assertEqual((40, 270, 500), tuple(stats["good"][key] for key in latency_fields))
            self.assertEqual(3, stats["active_by_protocol"]["vless"])
            self.assertEqual(2, stats["active_by_protocol"]["trojan"])
            self.assertEqual(1, stats["good_by_protocol"]["vless"])
            self.assertEqual(1, stats["good_by_protocol"]["trojan"])
            self.assertEqual(0, stats["good_by_protocol"]["tuic"])
            saved_stats = json.loads((root / "active-stats.json").read_text(encoding="utf-8"))
            self.assertEqual(stats, saved_stats)
            for entry, record in zip(entries, stats["probe_results"]):
                self.assertEqual(entry.target.index, record["candidate_index"])
                uri_hash = hashlib.sha256(entry.target.uri.encode("utf-8")).hexdigest()
                self.assertEqual(uri_hash, record["uri_sha256"])
                self.assertEqual(entry.delay_ms, record["latency_ms"])
                self.assertEqual(entry.error, record["error"])
                self.assertEqual(entry.active, record["active"])
            output = stats["good_output_file"]
            content = (root / "good.txt").read_bytes()
            self.assertEqual(len(content), output["bytes"])
            self.assertEqual(2, output["keys"])
            self.assertEqual(hashlib.sha256(content).hexdigest(), output["sha256"])
            readme = (root / "README.md").read_text(encoding="utf-8")
            self.assertIn("≤ 500 мс", readme)
            self.assertIn("/main/good.txt) | 2 |", readme)
            self.assertIn("/main/active.txt) | 5 |", readme)

    def test_threshold_and_enabled_settings_only_change_good_output(self):
        entries = [self.candidate("vless", 0, 40)[0], self.candidate("trojan", 1, 500)[0]]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            expected_active = "".join(f"{entry.target.uri}\n" for entry in entries).encode("utf-8")
            cases = ((True, 500, 2), (True, 499, 1), (False, 500, 0), (True, 40, 1))
            for enabled, limit, count in cases:
                with self.subTest(enabled=enabled, limit=limit):
                    stats = self.publish(root, entries, healthcheck.GoodConfig(enabled, limit))
                    self.assertEqual(expected_active, (root / "active.txt").read_bytes())
                    self.assertEqual(2, stats["active_keys"])
                    self.assertEqual(count, len(build.validate_txt(root / "good.txt")))
                    self.assertEqual(count, stats["total_good"])
                    if not enabled:
                        self.assertIsNone(stats["good"]["latency_avg"])
                        self.assertIn("отключено", (root / "README.md").read_text(encoding="utf-8"))

    def test_empty_good_replaces_stale_output_without_blocking_active(self):
        entries = [self.candidate("vless", 0, 501)[0]]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            (root / "good.txt").write_bytes(b"stale\n")
            stats = self.publish(root, entries)
            self.assertEqual([entries[0].target.uri], build.validate_txt(root / "active.txt"))
            self.assertEqual(b"", (root / "good.txt").read_bytes())
            self.assertEqual(0, stats["total_good"])
            self.assertEqual(0, sum(stats["good_by_protocol"].values()))
            for key in ("latency_min", "latency_avg", "latency_max"):
                self.assertIsNone(stats["good"][key])

    def test_missing_latency_does_not_qualify_as_good_or_break_stats(self):
        entry = self.candidate("vless", 0, None)[0]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            stats = self.publish(root, [entry])
            self.assertEqual([entry.target.uri], build.validate_txt(root / "active.txt"))
            self.assertEqual([], build.validate_txt(root / "good.txt"))
            for key in ("latency_min", "latency_avg", "latency_max"):
                self.assertIsNone(stats[key])

    def test_good_uses_existing_active_endpoint_winner(self):
        uri = f"vless://{UUID1}@same.example.com:443?security=tls"
        other_uri = f"vless://{UUID2}@same.example.com:443?security=tls"
        fast = healthcheck.ProbeResult(
            healthcheck.ProbeTarget(0, "wv-0000", uri, "vless", {}), True, 20, "HTTP 503",
        )
        slow = healthcheck.ProbeResult(
            healthcheck.ProbeTarget(1, "wv-0001", other_uri, "vless", {}), True, 90,
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            stats = self.publish(root, [fast, slow])
            self.assertEqual([uri], build.validate_txt(root / "active.txt"))
            self.assertEqual([], build.validate_txt(root / "good.txt"))
            self.assertEqual(1, stats["active_endpoint_duplicates_removed"])

    def test_good_validation_failure_preserves_all_published_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            for filename in ("active.txt", "good.txt", "active-stats.json"):
                (root / filename).write_bytes(b"previous\n")
            previous = {
                filename: (root / filename).read_bytes()
                for filename in ("active.txt", "good.txt", "active-stats.json", "README.md")
            }
            original_validate = build.validate_txt

            def reject_good(path):
                if path.name == "good.txt":
                    raise build.BuildError("invalid good output")
                return original_validate(path)

            with mock.patch.object(build, "validate_txt", side_effect=reject_good):
                with self.assertRaises(build.BuildError):
                    self.publish(root, [self.candidate("vless", 0, 40)[0]])
            for filename, content in previous.items():
                self.assertEqual(content, (root / filename).read_bytes())

    def test_existing_probe_fallback_remains_active_but_is_excluded_from_good(self):
        target = self.candidate("vless", 0, 40)[0].target
        with mock.patch.object(
            healthcheck, "_api_request", side_effect=[TimeoutError("timed out"), {"delay": 40}],
        ) as api:
            result = healthcheck._probe_target(
                target, controller="127.0.0.1:19090",
                probe_urls=healthcheck.DEFAULT_PROBE_URLS, timeout_ms=8000,
            )
        self.assertEqual(2, api.call_count)
        self.assertTrue(result.active)
        self.assertEqual(40, result.delay_ms)
        self.assertIn("TimeoutError", result.error)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            self.publish(root, [result])
            self.assertEqual([target.uri], build.validate_txt(root / "active.txt"))
            self.assertEqual([], build.validate_txt(root / "good.txt"))

    def test_healthcheck_passes_quality_settings_to_publication(self):
        entries = [self.candidate("vless", 0, 250)[0], self.candidate("trojan", 1, 251)[0]]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            input_path = root / "subscription.txt"
            candidate_content = "".join(f"{entry.target.uri}\n" for entry in entries).encode("utf-8")
            input_path.write_bytes(candidate_content)
            binary = root / "sing-box"
            binary.touch()
            with (
                mock.patch.object(
                    healthcheck, "validate_targets",
                    return_value=([entry.target for entry in entries], {}),
                ),
                mock.patch.object(
                    healthcheck, "run_probes", return_value=(entries, "test"),
                ) as probes,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                stats = healthcheck.healthcheck(
                    binary=binary, input_path=input_path, root=root,
                    min_active=1, good=healthcheck.GoodConfig(max_latency_ms=250),
                )
            self.assertEqual(2, stats["total_active"])
            self.assertEqual(1, stats["total_good"])
            self.assertEqual([entries[0].target.uri], build.validate_txt(root / "good.txt"))
            self.assertEqual(candidate_content, input_path.read_bytes())
            probes.assert_called_once()
            self.assertEqual(8000, probes.call_args.kwargs["timeout_ms"])
            self.assertEqual(64, probes.call_args.kwargs["workers"])
            self.assertEqual(healthcheck.DEFAULT_PROBE_URLS, probes.call_args.kwargs["probe_urls"])

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
            (root / "good.txt").write_bytes(b"previous good\n")
            (root / "active-stats.json").write_bytes(b"previous stats\n")
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
            self.assertEqual(b"previous good\n", (root / "good.txt").read_bytes())
            self.assertEqual(b"previous stats\n", (root / "active-stats.json").read_bytes())

    def test_active_output_keeps_fastest_result_per_endpoint(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "README.md").write_text(
                healthcheck.README_START + "\nold\n" + healthcheck.README_END + "\n",
                encoding="utf-8",
            )
            slow_uri = f"vless://{UUID1}@same.example.com:443?security=tls"
            fast_uri = f"vless://{UUID2}@same.example.com:443?security=tls"
            results = []
            for index, uri, delay in ((0, slow_uri, 90), (1, fast_uri, 20)):
                target = healthcheck.ProbeTarget(
                    index, f"wv-{index:04d}", uri, "vless", {"type": "vless"}
                )
                results.append(healthcheck.ProbeResult(target, True, delay))

            stats = healthcheck.publish_results(
                results,
                candidate_lines=[slow_uri, fast_uri],
                conversion_unsupported={},
                runtime_rejected={},
                engine_version="sing-box version test",
                probe_urls=["https://example.com/generate_204"],
                root=root,
                min_active=1,
            )

            self.assertEqual([fast_uri], build.validate_txt(root / "active.txt"))
            self.assertEqual([fast_uri], build.validate_txt(root / "good.txt"))
            self.assertEqual(2, stats["passing_keys_before_endpoint_deduplication"])
            self.assertEqual(1, stats["active_endpoint_duplicates_removed"])
            self.assertEqual(1, stats["active_keys"])
            self.assertEqual(0, stats["inactive_keys"])


if __name__ == "__main__":
    unittest.main()
