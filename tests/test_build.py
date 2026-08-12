import base64
import datetime as dt
import ipaddress
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from scripts import build


UUID1 = "550e8400-e29b-41d4-a716-446655440000"
UUID2 = "123e4567-e89b-42d3-a456-426614174000"


def b64(text: str, *, urlsafe: bool = False) -> str:
    raw = text.encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
    return encoded.decode("ascii").rstrip("=")


def vmess_uri(**overrides) -> str:
    data = {
        "v": "2",
        "ps": "sample",
        "add": "vm.example.com",
        "port": "443",
        "id": UUID1,
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "cdn.example.com",
    }
    data.update(overrides)
    return "vmess://" + b64(json.dumps(data, separators=(",", ":")))


class ProtocolParsingTests(unittest.TestCase):
    def test_every_supported_protocol(self):
        samples = {
            "vless": f"vless://{UUID1}@vless.example.com:443?security=tls&type=ws&path=%2Fws#node",
            "trojan": "trojan://secret@trojan.example.com:443?security=tls&type=grpc#node",
            "shadowsocks": "ss://aes-256-gcm:secret@ss.example.com:8388#node",
            "vmess": vmess_uri(),
            "hysteria": "hysteria://token@hy.example.com:443?protocol=udp#node",
            "hysteria2": "hy2://secret@hy2.example.com:443?sni=cdn.example.com#node",
            "tuic": f"tuic://{UUID1}:secret@tuic.example.com:443?congestion_control=bbr#node",
        }
        for protocol, uri in samples.items():
            with self.subTest(protocol=protocol):
                parsed = build.parse_uri(uri)
                self.assertEqual(protocol, parsed.protocol)
                self.assertEqual(uri, parsed.original)

    def test_vless_reality_and_transports(self):
        for network in ("tcp", "ws", "grpc", "xhttp", "h2", "http"):
            uri = (
                f"vless://{UUID1}@edge.example.com:443?security=reality&type={network}"
                f"&pbk={b64('01234567890123456789012345678901', urlsafe=True)}"
                "&sid=0a12&flow=xtls-rprx-vision"
            )
            with self.subTest(network=network):
                self.assertEqual("vless", build.parse_uri(uri).protocol)

    def test_hysteria2_accepts_both_schemes(self):
        first = build.parse_uri("hy2://secret@edge.example.com:443")
        second = build.parse_uri("hysteria2://secret@edge.example.com:443")
        self.assertEqual("hysteria2", first.protocol)
        self.assertEqual(first.identity, second.identity)

    def test_shadowsocks_sip002_and_legacy(self):
        sip002_plain = "ss://aes-256-gcm:secret@ss.example.com:8388#plain"
        sip002_encoded = f"ss://{b64('aes-256-gcm:secret')}@ss.example.com:8388#encoded"
        legacy = f"ss://{b64('aes-256-gcm:secret@ss.example.com:8388')}#legacy"
        parsed = [build.parse_uri(uri) for uri in (sip002_plain, sip002_encoded, legacy)]
        self.assertTrue(all(item.protocol == "shadowsocks" for item in parsed))
        self.assertEqual(parsed[0].identity, parsed[1].identity)
        self.assertEqual(parsed[0].identity, parsed[2].identity)

    def test_vmess_base64_json(self):
        parsed = build.parse_uri(vmess_uri())
        self.assertEqual("vm.example.com", parsed.server)
        self.assertEqual(443, parsed.port)

    def test_corrupt_uris_are_rejected(self):
        invalid = [
            "vless://bad-uuid@example.com:443?security=tls",
            f"vless://{UUID1}@example.com:70000?security=tls",
            f"vless://{UUID1}@example.com:443?security=reality&type=tcp",
            f"vless://{UUID1}@example.com:443?security=reality&pbk=not-a-key&sid=xyz",
            f"vless://{UUID1}@example.com:443?security=none&flow=xtls-rprx-vision",
            "trojan://@example.com:443",
            "ss://not-base64",
            "vmess://not-base64",
            "hysteria://example.com:443",
            "hy2://example.com:443",
            f"tuic://{UUID1}@example.com:443",
            "wireguard://unsupported",
        ]
        for uri in invalid:
            with self.subTest(uri=uri), self.assertRaises(build.ValidationError):
                build.parse_uri(uri)


class ExtractionTests(unittest.TestCase):
    def test_plain_text_and_single_base64_wrapper(self):
        uri = f"vless://{UUID1}@edge.example.com:443?security=tls"
        self.assertEqual([uri], build.extract_uris("heading\n" + uri + "\nfooter"))
        self.assertEqual([uri], build.extract_uris(b64(uri + "\n")))

    def test_base64_is_not_decoded_recursively(self):
        uri = f"vless://{UUID1}@edge.example.com:443?security=tls"
        self.assertEqual([], build.extract_uris(b64(b64(uri))))


class DeduplicationTests(unittest.TestCase):
    def candidate(self, uri: str, priority: int, source: str, order: int = 0):
        return build.Candidate(
            build.parse_uri(uri), source, source, priority, order, 0
        )

    def test_fragment_and_query_order_do_not_affect_identity(self):
        first = f"vless://{UUID1}@edge.example.com:443?security=tls&type=ws&path=%2Fx#first"
        second = f"vless://{UUID1}@edge.example.com:443?path=%2Fx&type=ws&security=tls#second"
        unique, duplicates = build.deduplicate(
            [self.candidate(first, 10, "low", 1), self.candidate(second, 100, "high")]
        )
        self.assertEqual(1, duplicates)
        self.assertEqual([second], [item.parsed.original for item in unique])

    def test_different_ports_paths_and_security_are_preserved(self):
        base = f"vless://{UUID1}@edge.example.com"
        uris = [
            base + ":443?security=tls&type=ws&path=%2Fa#one",
            base + ":8443?security=tls&type=ws&path=%2Fa#two",
            base + ":443?security=tls&type=ws&path=%2Fb#three",
            base + ":443?security=none&type=ws&path=%2Fa#four",
        ]
        unique, duplicates = build.deduplicate(
            [self.candidate(uri, 10, str(index), index) for index, uri in enumerate(uris)]
        )
        self.assertEqual(0, duplicates)
        self.assertEqual(set(uris), {item.parsed.original for item in unique})

    def test_vmess_display_name_is_decorative(self):
        one = vmess_uri(ps="first")
        two = vmess_uri(ps="second")
        self.assertEqual(build.parse_uri(one).identity, build.parse_uri(two).identity)


class GeographyTests(unittest.TestCase):
    def candidates(self):
        uris = [
            f"vless://{UUID1}@ru.example.com:443?security=tls",
            f"vless://{UUID1}@unknown.example.com:443?security=tls",
            f"vless://{UUID1}@de.example.com:443?security=tls",
        ]
        return [
            build.Candidate(build.parse_uri(uri), "x", "x", 1, 0, index)
            for index, uri in enumerate(uris)
        ]

    def test_only_confirmed_ru_is_excluded_and_unknown_is_kept(self):
        mapping = {
            "ru.example.com": "RU",
            "unknown.example.com": "UNKNOWN",
            "de.example.com": "NON_RU",
        }
        filtered, counts = build.filter_geography(
            self.candidates(), mapping.__getitem__, workers=1
        )
        self.assertEqual(Counter({"RU": 1, "UNKNOWN": 1, "NON_RU": 1}), counts)
        self.assertEqual(
            {"unknown.example.com", "de.example.com"},
            {item.parsed.server for item in filtered},
        )

    def test_unexpected_classifier_value_is_treated_as_unknown(self):
        filtered, counts = build.filter_geography(
            self.candidates()[:1], lambda _host: "possibly-RU", workers=1
        )
        self.assertEqual(1, len(filtered))
        self.assertEqual(1, counts["UNKNOWN"])

    def test_russian_network_registry_parser(self):
        text = (
            "2|ripencc|20260811|0|0|0|0|\n"
            "ripencc|RU|ipv4|203.0.113.0|256|20200101|allocated\n"
            "ripencc|DE|ipv4|198.51.100.0|256|20200101|allocated\n"
            "ripencc|RU|ipv6|2001:db8::|32|20200101|assigned\n"
        )
        index = build.RussianNetworkIndex.from_text(text)
        self.assertTrue(index.contains(ipaddress.ip_address("203.0.113.9")))
        self.assertTrue(index.contains(ipaddress.ip_address("2001:db8::1")))
        self.assertFalse(index.contains(ipaddress.ip_address("198.51.100.9")))

    def test_rdap_detects_ru_reassignment_inside_foreign_parent(self):
        calls = []

        def rdap_fetcher(url):
            calls.append(url)
            return {
                "startAddress": "104.171.133.0",
                "endAddress": "104.171.133.255",
                "country": "RU",
            }

        now = lambda: dt.datetime(2026, 8, 12, tzinfo=dt.timezone.utc)
        rdap = build.RdapGeoIndex(fetcher=rdap_fetcher, now=now)
        delegated = build.RussianNetworkIndex([], [])
        classifier = build.GeoClassifier(delegated, rdap)

        self.assertEqual("RU", classifier.classify("104.171.133.53"))
        self.assertEqual("RU", classifier.classify("104.171.133.99"))
        self.assertEqual(1, len(calls), "the returned /24 must satisfy the second lookup")

    def test_iana_bootstrap_selects_authoritative_service(self):
        bootstrap = build.RdapBootstrap.from_documents(
            {
                "services": [
                    [["104.0.0.0/8"], ["https://rdap.arin.example/registry"]],
                    [["2001:db8::/32"], ["https://rdap.ripe.example"]],
                ]
            }
        )
        self.assertEqual(
            "https://rdap.arin.example/registry/ip/104.171.133.53",
            bootstrap.url_for(ipaddress.ip_address("104.171.133.53")),
        )
        self.assertEqual(
            "https://rdap.ripe.example/ip/2001%3Adb8%3A%3A1",
            bootstrap.url_for(ipaddress.ip_address("2001:db8::1")),
        )

    def test_rdap_non_ru_and_missing_country(self):
        responses = {
            "198.51.100.7": {
                "startAddress": "198.51.100.0",
                "endAddress": "198.51.100.127",
                "country": "DE",
            },
            "198.51.100.200": {
                "startAddress": "198.51.100.128",
                "endAddress": "198.51.100.255",
            },
        }

        def fetcher(url):
            return responses[url.rsplit("/", 1)[-1]]

        rdap = build.RdapGeoIndex(fetcher=fetcher)
        self.assertEqual("NON_RU", rdap.lookup(ipaddress.ip_address("198.51.100.7")))
        self.assertEqual("UNKNOWN", rdap.lookup(ipaddress.ip_address("198.51.100.200")))

    def test_rdap_failure_falls_back_only_to_confirmed_delegated_ru(self):
        def unavailable(_url):
            raise build.BuildError("offline")

        delegated = build.RussianNetworkIndex(
            [ipaddress.ip_network("203.0.113.0/24")], []
        )
        classifier = build.GeoClassifier(delegated, build.RdapGeoIndex(fetcher=unavailable))
        self.assertEqual("RU", classifier.classify("203.0.113.9"))
        self.assertEqual("UNKNOWN", classifier.classify("198.51.100.9"))

    def test_rdap_cache_round_trip(self):
        fixed_now = dt.datetime(2026, 8, 12, 1, 2, 3, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "geo-cache.json"
            original = build.RdapGeoIndex(
                [
                    build.GeoRange(
                        ipaddress.ip_address("104.171.133.0"),
                        ipaddress.ip_address("104.171.133.255"),
                        "RU",
                        fixed_now,
                    )
                ],
                now=lambda: fixed_now,
            )
            original.save(path)
            loaded = build.RdapGeoIndex.load(
                path,
                fetcher=lambda _url: self.fail("fresh cache should prevent network access"),
                now=lambda: fixed_now,
            )
            self.assertEqual("RU", loaded.lookup(ipaddress.ip_address("104.171.133.53")))


class PublicationTests(unittest.TestCase):
    def make_root(self, path: Path):
        (path / "README.md").write_text(
            "# Test\n\n"
            + build.README_START
            + "\nold\n"
            + build.README_END
            + "\n",
            encoding="utf-8",
        )

    def publish(self, root: Path, lines, min_keys=1):
        return build.publish_build(
            lines,
            source_stats=[{"id": "test", "valid": sum(map(len, lines.values()))}],
            recognized=sum(map(len, lines.values())),
            rejected=0,
            duplicates=0,
            geo_counts={"UNKNOWN": sum(map(len, lines.values()))},
            root=root,
            min_keys=min_keys,
            now=dt.datetime(2026, 8, 11, 20, 0, tzinfo=dt.timezone.utc),
        )

    def test_publication_format_and_protocol_outputs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            lines = {
                "vless": [f"vless://{UUID1}@edge.example.com:443?security=tls"],
                "trojan": ["trojan://secret@edge.example.com:443"],
                "shadowsocks": ["ss://aes-256-gcm:secret@edge.example.com:8388"],
                "vmess": [vmess_uri()],
                "hysteria": ["hysteria://token@edge.example.com:443"],
                "hysteria2": ["hysteria2://secret@edge.example.com:443"],
                "tuic": [f"tuic://{UUID1}:secret@edge.example.com:443"],
            }
            stats = self.publish(root, lines)
            self.assertEqual(7, stats["total_keys"])
            for protocol, filename in build.PROTOCOL_FILES.items():
                self.assertEqual(lines[protocol], build.validate_txt(root / filename, protocol))
            raw = (root / "subscription.txt").read_bytes()
            self.assertNotIn(b"\r", raw)
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
            self.assertTrue(raw.endswith(b"\n"))

    def test_empty_result_cannot_overwrite_working_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            original = b"working-data\n"
            (root / "subscription.txt").write_bytes(original)
            with self.assertRaises(build.BuildError):
                self.publish(root, {}, min_keys=100)
            self.assertEqual(original, (root / "subscription.txt").read_bytes())
            self.assertFalse((root / "stats.json").exists())

    def test_empty_protocol_preserves_previous_valid_file(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            previous = "trojan://secret@edge.example.com:443"
            (root / "trojan.txt").write_text(previous + "\n", encoding="utf-8", newline="\n")
            current = {
                "vless": [f"vless://{UUID1}@edge.example.com:443?security=tls"]
            }
            stats = self.publish(root, current)
            self.assertEqual([previous], build.validate_txt(root / "trojan.txt", "trojan"))
            self.assertIn("trojan", stats["preserved_protocol_files"])

    def test_identical_rebuild_does_not_change_metadata_or_history(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.make_root(root)
            lines = {
                "vless": [f"vless://{UUID1}@edge.example.com:443?security=tls"]
            }
            first = self.publish(root, lines)
            before = {
                name: (root / name).read_bytes()
                for name in ("stats.json", "update-history.json", "README.md")
            }
            second = build.publish_build(
                lines,
                source_stats=[{"id": "changed-stats", "valid": 1}],
                recognized=999,
                rejected=999,
                duplicates=999,
                geo_counts={"UNKNOWN": 1},
                root=root,
                min_keys=1,
                now=dt.datetime(2026, 8, 12, 20, 0, tzinfo=dt.timezone.utc),
            )
            self.assertEqual(first, second)
            for filename, content in before.items():
                self.assertEqual(content, (root / filename).read_bytes())


class OfflineIntegrationTests(unittest.TestCase):
    def test_build_skips_unavailable_source_without_network(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "README.md").write_text(
                "# Test\n" + build.README_START + "\nold\n" + build.README_END + "\n",
                encoding="utf-8",
            )
            sources = {
                "sources": [
                    {
                        "id": "good",
                        "name": "Good",
                        "url": "memory://good",
                        "priority": 100,
                        "enabled": True,
                        "protocols": ["vless"],
                        "note": "test",
                    },
                    {
                        "id": "down",
                        "name": "Down",
                        "url": "memory://down",
                        "priority": 10,
                        "enabled": True,
                        "protocols": ["vless"],
                        "note": "test",
                    },
                ]
            }
            source_path = root / "sources.json"
            source_path.write_text(json.dumps(sources), encoding="utf-8")

            def fetcher(url):
                if url.endswith("down"):
                    raise build.BuildError("offline fixture")
                return f"vless://{UUID2}@edge.example.com:443?security=tls\n"

            stats = build.build(
                root=root,
                sources_path=source_path,
                fetcher=fetcher,
                classifier=lambda _host: "UNKNOWN",
                min_keys=1,
                workers=1,
            )
            self.assertEqual(1, stats["total_keys"])
            statuses = {item["id"]: item["status"] for item in stats["sources"]}
            self.assertEqual({"good": "ok", "down": "unavailable"}, statuses)


if __name__ == "__main__":
    unittest.main()
