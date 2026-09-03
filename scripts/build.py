#!/usr/bin/env python3
"""Build WireVeil subscriptions from public URI sources.

The builder intentionally uses only Python's standard library.  It validates
configuration data without rewriting it, deduplicates by connection semantics,
filters only endpoints that can be positively identified as Russian, and
publishes a complete build atomically after all safety checks pass.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
SOURCES_PATH = ROOT / "sources.json"
HISTORY_PATH = ROOT / "update-history.json"
STATS_PATH = ROOT / "stats.json"
GEO_CACHE_PATH = ROOT / "geo-cache.json"

PROTOCOL_FILES = {
    "vless": "vless.txt",
    "trojan": "trojan.txt",
    "shadowsocks": "shadowsocks.txt",
    "vmess": "vmess.txt",
    "hysteria": "hysteria.txt",
    "hysteria2": "hysteria2.txt",
    "tuic": "tuic.txt",
}
MIX_REQUIRED_PROTOCOLS = (
    "vless",
    "trojan",
    "shadowsocks",
    "vmess",
    "hysteria2",
    "tuic",
)
SCHEME_PROTOCOL = {
    "vless": "vless",
    "trojan": "trojan",
    "ss": "shadowsocks",
    "vmess": "vmess",
    "hysteria": "hysteria",
    "hy2": "hysteria2",
    "hysteria2": "hysteria2",
    "tuic": "tuic",
}
SUPPORTED_SCHEMES = tuple(SCHEME_PROTOCOL)
SCHEME_PATTERN = r"(?:vless|trojan|ss|vmess|hysteria2|hysteria|hy2|tuic)"
URI_RE = re.compile(
    rf"(?i){SCHEME_PATTERN}://.*?(?={SCHEME_PATTERN}://|[\s<>\"']|$)"
)
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]{0,16}$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")
NETWORKS = {"tcp", "ws", "grpc", "xhttp", "http", "h2", "kcp", "quic"}
VLESS_NETWORKS = {"tcp", "ws", "grpc", "xhttp", "httpupgrade", "http", "h2"}
NETWORK_ALIASES = {
    "raw": "tcp",
    "websocket": "ws",
    "splithttp": "xhttp",
}
DECORATIVE_QUERY_KEYS = {
    "name",
    "remark",
    "remarks",
    "tag",
    "title",
    "label",
    "emoji",
}
RIPE_DELEGATED_URL = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"
RDAP_IP_URL = "https://rdap.org/ip/{address}"
IANA_RDAP_IPV4_URL = "https://data.iana.org/rdap/ipv4.json"
IANA_RDAP_IPV6_URL = "https://data.iana.org/rdap/ipv6.json"
GEO_CACHE_TTL = dt.timedelta(days=7)
USER_AGENT = "WireVeil/1.0 (+https://github.com/)"


class BuildError(RuntimeError):
    """Raised when a build cannot be safely published."""


class ValidationError(ValueError):
    """Raised for malformed or unsupported configuration URIs."""


@dataclasses.dataclass(frozen=True)
class ParsedURI:
    original: str
    protocol: str
    server: str
    port: int
    identity: tuple


@dataclasses.dataclass(frozen=True)
class Candidate:
    parsed: ParsedURI
    source_id: str
    source_name: str
    priority: int
    source_order: int
    item_order: int


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _b64decode(value: str) -> bytes:
    compact = "".join(value.split())
    if not compact or not BASE64_RE.fullmatch(compact):
        raise ValidationError("invalid Base64 alphabet")
    padded = compact + "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("invalid Base64 data") from exc


def _b64decode_text(value: str) -> str:
    try:
        return _b64decode(value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("Base64 is not UTF-8 text") from exc


def _valid_uuid(value: str) -> bool:
    if not UUID_RE.fullmatch(value):
        return False
    try:
        return str(uuid.UUID(value)).lower() == value.lower()
    except ValueError:
        return False


def _valid_host(value: str) -> bool:
    host = value.strip().rstrip(".")
    if not host or len(host) > 253 or any(char.isspace() for char in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_host.split(".")
    return len(labels) >= 2 and all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def _port(value: object) -> int:
    try:
        port = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ValidationError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValidationError("port outside 1..65535")
    return port


def _split(uri: str) -> urllib.parse.SplitResult:
    try:
        parsed = urllib.parse.urlsplit(uri)
        # Accessing .port also detects malformed and out-of-range ports.
        _ = parsed.port
        return parsed
    except ValueError as exc:
        raise ValidationError("malformed authority or port") from exc


def _host_port(parsed: urllib.parse.SplitResult) -> tuple[str, int]:
    host = parsed.hostname or ""
    if not _valid_host(host):
        raise ValidationError("invalid server")
    if parsed.port is None:
        raise ValidationError("missing port")
    return host.lower().rstrip("."), _port(parsed.port)


def _query(parsed: urllib.parse.SplitResult) -> dict[str, list[str]]:
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=False
        )
    except ValueError as exc:
        raise ValidationError("malformed query") from exc
    result: dict[str, list[str]] = {}
    for key, value in pairs:
        normalized_key = key.lower()
        result.setdefault(normalized_key, []).append(value)
    return result


def _first(query: Mapping[str, Sequence[str]], *keys: str) -> str:
    for key in keys:
        values = query.get(key.lower())
        if values:
            return values[0]
    return ""


def _semantic_query(
    query: Mapping[str, Sequence[str]], *, exclude: Iterable[str] = ()
) -> tuple:
    ignored = DECORATIVE_QUERY_KEYS | {item.lower() for item in exclude}
    case_insensitive_values = {
        "alpn",
        "fp",
        "fingerprint",
        "flow",
        "host",
        "mode",
        "network",
        "peer",
        "security",
        "server_name",
        "servername",
        "sid",
        "shortid",
        "sni",
        "type",
    }
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for key, values in query.items():
        if key not in ignored:
            comparable = (
                (value.lower() for value in values)
                if key in case_insensitive_values
                else iter(values)
            )
            normalized.append((key, tuple(sorted(comparable))))
    return tuple(sorted(normalized))


def _userinfo(parsed: urllib.parse.SplitResult) -> tuple[str, str]:
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    return username, password


def _transport(query: Mapping[str, Sequence[str]]) -> str:
    value = (_first(query, "type", "network") or "tcp").lower()
    return NETWORK_ALIASES.get(value, value)


def parse_vless(uri: str) -> ParsedURI:
    parsed = _split(uri)
    server, port = _host_port(parsed)
    user, _ = _userinfo(parsed)
    if not _valid_uuid(user):
        raise ValidationError("VLESS requires a valid UUID")
    query = _query(parsed)
    network = _transport(query)
    if network not in VLESS_NETWORKS:
        raise ValidationError("unsupported VLESS transport")
    security = (_first(query, "security") or "none").lower()
    if security == "false":
        security = "none"
    if security not in {"none", "tls", "reality", "xtls"}:
        raise ValidationError("unsupported VLESS security")
    flow = _first(query, "flow").lower()
    if flow and flow not in {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}:
        raise ValidationError("unsupported VLESS flow")
    public_key = _first(query, "pbk", "publickey")
    short_id = _first(query, "sid", "shortid")
    if security == "reality":
        if not public_key:
            raise ValidationError("Reality requires a public key")
        try:
            decoded_public_key = _b64decode(public_key)
        except ValidationError as exc:
            raise ValidationError("invalid Reality public key") from exc
        if len(decoded_public_key) != 32:
            raise ValidationError("invalid Reality public key")
        if short_id and (not SHORT_ID_RE.fullmatch(short_id) or len(short_id) % 2):
            raise ValidationError("invalid Reality short ID")
    elif short_id:
        raise ValidationError("short ID supplied without Reality")
    if flow and security not in {"tls", "reality"}:
        raise ValidationError("XTLS-Vision requires TLS or Reality")
    identity = (
        "vless",
        server,
        port,
        user.lower(),
        network,
        security,
        _semantic_query(query, exclude={"type", "network", "security", "flow"}),
        flow,
    )
    return ParsedURI(uri, "vless", server, port, identity)


def parse_trojan(uri: str) -> ParsedURI:
    parsed = _split(uri)
    server, port = _host_port(parsed)
    password, _ = _userinfo(parsed)
    if not password:
        raise ValidationError("Trojan requires a password")
    query = _query(parsed)
    network = _transport(query)
    if network not in VLESS_NETWORKS:
        raise ValidationError("unsupported Trojan transport")
    identity = (
        "trojan",
        server,
        port,
        password,
        network,
        _semantic_query(query, exclude={"type", "network"}),
    )
    return ParsedURI(uri, "trojan", server, port, identity)


def _parse_ss_payload(payload: str) -> tuple[str, str, str, int]:
    """Return method, password, host, port from decoded SIP002 credentials."""
    if "@" not in payload or ":" not in payload:
        raise ValidationError("malformed Shadowsocks payload")
    credentials, endpoint = payload.rsplit("@", 1)
    if ":" not in credentials:
        raise ValidationError("Shadowsocks credentials need method and password")
    method, password = credentials.split(":", 1)
    if not method or not password:
        raise ValidationError("empty Shadowsocks method or password")
    endpoint_uri = _split("ss://x@" + endpoint)
    host, port = _host_port(endpoint_uri)
    return method.lower(), password, host, port


def parse_shadowsocks(uri: str) -> ParsedURI:
    raw = uri[5:]
    without_fragment = raw.split("#", 1)[0]
    main, separator, query_text = without_fragment.partition("?")
    query = _query(urllib.parse.urlsplit("ss://x/?" + query_text)) if separator else {}

    if "@" in main:
        userinfo, endpoint = main.rsplit("@", 1)
        decoded_userinfo = urllib.parse.unquote(userinfo)
        if ":" not in decoded_userinfo:
            decoded_userinfo = _b64decode_text(decoded_userinfo)
        method, password, server, port = _parse_ss_payload(
            decoded_userinfo + "@" + endpoint
        )
    else:
        decoded = _b64decode_text(urllib.parse.unquote(main))
        method, password, server, port = _parse_ss_payload(decoded)

    identity = (
        "shadowsocks",
        server,
        port,
        method,
        password,
        _semantic_query(query),
    )
    return ParsedURI(uri, "shadowsocks", server, port, identity)


def parse_vmess(uri: str) -> ParsedURI:
    payload = uri[len("vmess://") :].split("#", 1)[0].strip()
    try:
        data = json.loads(_b64decode_text(payload))
    except json.JSONDecodeError as exc:
        raise ValidationError("VMess payload is not JSON") from exc
    if not isinstance(data, dict):
        raise ValidationError("VMess payload must be an object")
    server = str(data.get("add", "")).lower().rstrip(".")
    if not _valid_host(server):
        raise ValidationError("VMess has invalid server")
    port = _port(data.get("port"))
    user = str(data.get("id", ""))
    if not _valid_uuid(user):
        raise ValidationError("VMess requires a valid UUID")
    network = str(data.get("net", "tcp") or "tcp").lower()
    if network not in NETWORKS:
        raise ValidationError("unsupported VMess transport")
    # Exclude presentation-only fields while retaining every connection field.
    connection = {
        str(key).lower(): str(value)
        for key, value in data.items()
        if str(key).lower() not in {"ps", "remark", "remarks", "name"}
    }
    connection.update({"add": server, "port": str(port), "id": user.lower(), "net": network})
    identity = ("vmess", tuple(sorted(connection.items())))
    return ParsedURI(uri, "vmess", server, port, identity)


def _parse_hysteria(uri: str, protocol: str) -> ParsedURI:
    parsed = _split(uri)
    server, port = _host_port(parsed)
    username, password = _userinfo(parsed)
    query = _query(parsed)
    if protocol == "hysteria":
        auth = password or username or _first(
            query, "auth", "auth_str", "authstr", "password", "token"
        )
    else:
        auth = password or username or _first(query, "password", "auth", "token")
    if not auth:
        raise ValidationError(f"{protocol} requires authentication")
    identity = (
        protocol,
        server,
        port,
        username,
        password,
        _semantic_query(query),
    )
    return ParsedURI(uri, protocol, server, port, identity)


def parse_tuic(uri: str) -> ParsedURI:
    parsed = _split(uri)
    server, port = _host_port(parsed)
    user, password = _userinfo(parsed)
    if not _valid_uuid(user) or not password:
        raise ValidationError("TUIC requires a UUID and password")
    query = _query(parsed)
    identity = (
        "tuic",
        server,
        port,
        user.lower(),
        password,
        _semantic_query(query),
    )
    return ParsedURI(uri, "tuic", server, port, identity)


PARSERS: dict[str, Callable[[str], ParsedURI]] = {
    "vless": parse_vless,
    "trojan": parse_trojan,
    "ss": parse_shadowsocks,
    "vmess": parse_vmess,
    "hysteria": lambda uri: _parse_hysteria(uri, "hysteria"),
    "hy2": lambda uri: _parse_hysteria(uri, "hysteria2"),
    "hysteria2": lambda uri: _parse_hysteria(uri, "hysteria2"),
    "tuic": parse_tuic,
}


def parse_uri(uri: str) -> ParsedURI:
    if not uri or any(char in uri for char in "\r\n\x00"):
        raise ValidationError("empty or multiline URI")
    scheme = uri.split(":", 1)[0].lower()
    parser = PARSERS.get(scheme)
    if parser is None:
        raise ValidationError("unsupported URI scheme")
    return parser(uri)


def extract_uris(text: str) -> list[str]:
    """Extract supported URI candidates, decoding a wrapped source once at most."""
    direct = URI_RE.findall(text)
    if direct:
        return direct
    stripped = text.strip()
    if not stripped or not BASE64_RE.fullmatch(stripped):
        return []
    try:
        decoded = _b64decode_text(stripped)
    except ValidationError:
        return []
    # Deliberately do not attempt a second decode.
    return URI_RE.findall(decoded)


def fetch_url(
    url: str,
    *,
    timeout: float = 20.0,
    retries: int = 3,
    opener: Callable[..., object] = urllib.request.urlopen,
) -> str:
    last_error: BaseException | None = None
    for attempt in range(1, retries + 1):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with opener(request, timeout=timeout) as response:  # type: ignore[attr-defined]
                body = response.read()
            return body.decode("utf-8-sig")
        except (OSError, UnicodeError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 4))
    raise BuildError(f"failed after {retries} attempts: {last_error}")


def fetch_json_url(
    url: str,
    *,
    timeout: float = 20.0,
    retries: int = 3,
    opener: Callable[..., object] = urllib.request.urlopen,
) -> dict:
    """Fetch a JSON object with bounded retries and RDAP-friendly headers."""
    last_error: BaseException | None = None
    for attempt in range(1, retries + 1):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
        )
        try:
            with opener(request, timeout=timeout) as response:  # type: ignore[attr-defined]
                data = json.loads(response.read().decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON root is not an object")
            return data
        except (OSError, UnicodeError, ValueError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 4))
    raise BuildError(f"failed after {retries} attempts: {last_error}")


class RussianNetworkIndex:
    """Conservative lookup based on the current RIPE delegated registry."""

    def __init__(self, ipv4: Sequence[ipaddress.IPv4Network], ipv6: Sequence[ipaddress.IPv6Network]):
        self.ipv4 = tuple(ipv4)
        self.ipv6 = tuple(ipv6)

    @classmethod
    def from_text(cls, text: str) -> "RussianNetworkIndex":
        ipv4: list[ipaddress.IPv4Network] = []
        ipv6: list[ipaddress.IPv6Network] = []
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 7 or parts[1].upper() != "RU" or parts[6] not in {"allocated", "assigned"}:
                continue
            try:
                if parts[2] == "ipv4":
                    start = ipaddress.IPv4Address(parts[3])
                    count = int(parts[4])
                    end = ipaddress.IPv4Address(int(start) + count - 1)
                    ipv4.extend(ipaddress.summarize_address_range(start, end))
                elif parts[2] == "ipv6":
                    ipv6.append(ipaddress.IPv6Network(f"{parts[3]}/{parts[4]}", strict=False))
            except (ValueError, ipaddress.AddressValueError):
                continue
        return cls(ipv4, ipv6)

    def contains(self, address: ipaddress._BaseAddress) -> bool:
        networks = self.ipv4 if address.version == 4 else self.ipv6
        return any(address in network for network in networks)


@dataclasses.dataclass(frozen=True)
class GeoRange:
    start: ipaddress._BaseAddress
    end: ipaddress._BaseAddress
    country: str
    checked_at: dt.datetime

    def contains(self, address: ipaddress._BaseAddress) -> bool:
        return (
            address.version == self.start.version
            and int(self.start) <= int(address) <= int(self.end)
        )

    @property
    def span(self) -> int:
        return int(self.end) - int(self.start)


class RdapBootstrap:
    """Resolve an IP to its authoritative RIR RDAP endpoint via IANA data."""

    def __init__(self, services: Sequence[tuple[ipaddress._BaseNetwork, str]]):
        self.services = tuple(
            sorted(services, key=lambda item: item[0].prefixlen, reverse=True)
        )

    @classmethod
    def from_documents(cls, *documents: Mapping) -> "RdapBootstrap":
        services: list[tuple[ipaddress._BaseNetwork, str]] = []
        for document in documents:
            for service in document.get("services", []):
                if (
                    not isinstance(service, list)
                    or len(service) != 2
                    or not isinstance(service[0], list)
                    or not isinstance(service[1], list)
                    or not service[1]
                ):
                    continue
                base_url = str(service[1][0]).rstrip("/")
                if not base_url.startswith("https://"):
                    continue
                for prefix in service[0]:
                    try:
                        services.append((ipaddress.ip_network(str(prefix), strict=False), base_url))
                    except ValueError:
                        continue
        if not services:
            raise BuildError("IANA RDAP bootstrap contains no usable services")
        return cls(services)

    def url_for(self, address: ipaddress._BaseAddress) -> str:
        for network, base_url in self.services:
            if address.version == network.version and address in network:
                return f"{base_url}/ip/{urllib.parse.quote(str(address))}"
        return RDAP_IP_URL.format(address=urllib.parse.quote(str(address)))


class RdapGeoIndex:
    """Exact country lookup using authoritative RDAP network assignments.

    RIR delegated files describe top-level allocations and can miss a more
    specific reassignment to Russia. RDAP returns the current network object for
    the actual IP. Returned ranges are cached so an hourly build does not issue
    one request per key.
    """

    def __init__(
        self,
        ranges: Sequence[GeoRange] = (),
        *,
        fetcher: Callable[[str], Mapping] | None = None,
        url_for_address: Callable[[ipaddress._BaseAddress], str] | None = None,
        now: Callable[[], dt.datetime] | None = None,
        ttl: dt.timedelta = GEO_CACHE_TTL,
    ):
        self.ranges = list(ranges)
        self.fetcher = fetcher or (lambda url: fetch_json_url(url))
        self.url_for_address = url_for_address or (
            lambda address: RDAP_IP_URL.format(address=urllib.parse.quote(str(address)))
        )
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self.ttl = ttl
        self.lock = threading.RLock()
        self.inflight: dict[str, threading.Event] = {}
        self.query_failures = 0
        self.cache_hits = 0
        self.queries = 0

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        fetcher: Callable[[str], Mapping] | None = None,
        url_for_address: Callable[[ipaddress._BaseAddress], str] | None = None,
        now: Callable[[], dt.datetime] | None = None,
        ttl: dt.timedelta = GEO_CACHE_TTL,
    ) -> "RdapGeoIndex":
        ranges: list[GeoRange] = []
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if data.get("schema_version") != 1 or not isinstance(data.get("ranges"), list):
                    raise ValueError("unsupported cache schema")
                for item in data["ranges"]:
                    start = ipaddress.ip_address(item["start"])
                    end = ipaddress.ip_address(item["end"])
                    checked = dt.datetime.fromisoformat(
                        str(item["checked_at_utc"]).replace("Z", "+00:00")
                    )
                    if start.version != end.version or int(start) > int(end):
                        continue
                    ranges.append(
                        GeoRange(start, end, cls._normalize_country(item.get("country")), checked)
                    )
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                warn(f"geo-cache.json is invalid and will be rebuilt: {exc}")
                ranges = []
        return cls(
            ranges,
            fetcher=fetcher,
            url_for_address=url_for_address,
            now=now,
            ttl=ttl,
        )

    @staticmethod
    def _normalize_country(value: object) -> str:
        country = str(value or "").strip().upper()
        return country if re.fullmatch(r"[A-Z]{2}", country) and country != "ZZ" else ""

    def _fresh(self, item: GeoRange, current: dt.datetime) -> bool:
        checked = item.checked_at
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=dt.timezone.utc)
        return current - checked.astimezone(dt.timezone.utc) <= self.ttl

    def _cached(self, address: ipaddress._BaseAddress) -> GeoRange | None:
        current = self.now().astimezone(dt.timezone.utc)
        matches = [
            item for item in self.ranges if self._fresh(item, current) and item.contains(address)
        ]
        return min(matches, key=lambda item: item.span) if matches else None

    @staticmethod
    def _group_key(address: ipaddress._BaseAddress) -> str:
        prefix = 24 if address.version == 4 else 48
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))

    @staticmethod
    def _classification(country: str) -> str:
        if country == "RU":
            return "RU"
        return "NON_RU" if country else "UNKNOWN"

    def lookup(self, address: ipaddress._BaseAddress) -> str | None:
        """Return exact RDAP classification, or None when RDAP is unavailable."""
        group = self._group_key(address)
        while True:
            with self.lock:
                cached = self._cached(address)
                if cached is not None:
                    self.cache_hits += 1
                    return self._classification(cached.country)
                event = self.inflight.get(group)
                if event is None:
                    event = threading.Event()
                    self.inflight[group] = event
                    leader = True
                else:
                    leader = False
            if leader:
                break
            # A peer is resolving an address in the same coarse range. Its RDAP
            # response normally covers us too; waiting avoids request bursts.
            event.wait(timeout=60)
            with self.lock:
                if group not in self.inflight:
                    continue
            return None

        try:
            with self.lock:
                self.queries += 1
                query_number = self.queries
            if query_number % 100 == 0:
                print(f"RDAP progress: {query_number} network lookups", file=sys.stderr)
            data = self.fetcher(self.url_for_address(address))
            start = ipaddress.ip_address(str(data["startAddress"]))
            end = ipaddress.ip_address(str(data["endAddress"]))
            if (
                start.version != address.version
                or end.version != address.version
                or not (int(start) <= int(address) <= int(end))
            ):
                raise ValueError("RDAP range does not contain the queried address")
            item = GeoRange(
                start=start,
                end=end,
                country=self._normalize_country(data.get("country")),
                checked_at=self.now().astimezone(dt.timezone.utc),
            )
            with self.lock:
                self.ranges = [
                    old
                    for old in self.ranges
                    if not (old.start == item.start and old.end == item.end)
                ]
                self.ranges.append(item)
            return self._classification(item.country)
        except (BuildError, KeyError, OSError, TypeError, ValueError):
            with self.lock:
                self.query_failures += 1
            return None
        finally:
            with self.lock:
                self.inflight.pop(group, None)
                event.set()

    def save(self, path: Path) -> None:
        current = self.now().astimezone(dt.timezone.utc)
        with self.lock:
            fresh = [item for item in self.ranges if self._fresh(item, current)]
        fresh.sort(key=lambda item: (item.start.version, int(item.start), int(item.end)))
        updated_at = max(
            (item.checked_at.astimezone(dt.timezone.utc) for item in fresh),
            default=current,
        )
        data = {
            "schema_version": 1,
            "updated_at_utc": updated_at.replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "ranges": [
                {
                    "start": str(item.start),
                    "end": str(item.end),
                    "country": item.country or None,
                    "checked_at_utc": item.checked_at.astimezone(dt.timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
                for item in fresh
            ],
        }
        content = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        if path.exists() and path.read_text(encoding="utf-8") == content:
            return
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, path)


class GeoClassifier:
    """Classify actual server endpoints; only positive RU matches are excluded."""

    def __init__(
        self,
        russian_networks: RussianNetworkIndex | None,
        rdap: RdapGeoIndex | None = None,
    ):
        self.russian_networks = russian_networks
        self.rdap = rdap
        self.cache: dict[str, str] = {}
        self.lock = threading.RLock()

    def classify(self, host: str) -> str:
        with self.lock:
            if host in self.cache:
                return self.cache[host]
        try:
            try:
                addresses = {ipaddress.ip_address(host)}
            except ValueError:
                addresses = {
                    ipaddress.ip_address(item[4][0])
                    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                }
            classifications: list[str] = []
            for address in addresses:
                exact = self.rdap.lookup(address) if self.rdap is not None else None
                if exact is not None:
                    classifications.append(exact)
                elif self.russian_networks is not None and self.russian_networks.contains(address):
                    classifications.append("RU")
                else:
                    # A non-RU top-level allocation is not proof: a smaller
                    # network inside it may have been reassigned to Russia.
                    classifications.append("UNKNOWN")
            if classifications and all(value == "RU" for value in classifications):
                result = "RU"
            elif classifications and all(value == "NON_RU" for value in classifications):
                result = "NON_RU"
            else:
                result = "UNKNOWN"
        except (OSError, ValueError):
            result = "UNKNOWN"
        with self.lock:
            self.cache[host] = result
        return result


def load_sources(path: Path = SOURCES_PATH) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    sources = data.get("sources") if isinstance(data, dict) else None
    if not isinstance(sources, list) or not sources:
        raise BuildError("sources.json must contain a non-empty sources array")
    required = {"id", "name", "url", "priority", "enabled", "protocols", "note"}
    seen: set[str] = set()
    result: list[dict] = []
    for source in sources:
        if not isinstance(source, dict) or not required.issubset(source):
            raise BuildError("every source must contain all required fields")
        if source["id"] in seen:
            raise BuildError(f"duplicate source id: {source['id']}")
        seen.add(source["id"])
        unknown = set(source["protocols"]) - set(PROTOCOL_FILES)
        if unknown:
            raise BuildError(f"source {source['id']} has unknown protocols: {unknown}")
        result.append(source)
    return sorted(result, key=lambda item: (-int(item["priority"]), item["id"]))


def collect_candidates(
    sources: Sequence[dict],
    fetcher: Callable[[str], str],
) -> tuple[list[Candidate], list[dict], int, int]:
    candidates: list[Candidate] = []
    source_stats: list[dict] = []
    recognized_total = 0
    rejected_total = 0
    for source_order, source in enumerate(sources):
        record = {
            "id": source["id"],
            "name": source["name"],
            "priority": int(source["priority"]),
            "enabled": bool(source["enabled"]),
            "status": "disabled" if not source["enabled"] else "pending",
            "lines": 0,
            "recognized": 0,
            "valid": 0,
            "rejected": 0,
        }
        if not source["enabled"]:
            source_stats.append(record)
            continue
        try:
            text = fetcher(source["url"])
        except Exception as exc:  # A broken source must not break the full build.
            record["status"] = "unavailable"
            record["warning"] = str(exc)
            warn(f"{source['name']}: {exc}; source skipped")
            source_stats.append(record)
            if source.get("required", False):
                raise BuildError(f"required source {source['id']} is unavailable") from exc
            continue
        record["status"] = "ok"
        record["lines"] = len(text.splitlines())
        uris = extract_uris(text)
        record["recognized"] = len(uris)
        recognized_total += len(uris)
        expected = set(source["protocols"])
        for item_order, uri in enumerate(uris):
            try:
                parsed = parse_uri(uri)
                if parsed.protocol not in expected:
                    raise ValidationError("protocol not declared for this source")
            except ValidationError:
                record["rejected"] += 1
                rejected_total += 1
                continue
            candidates.append(
                Candidate(
                    parsed=parsed,
                    source_id=source["id"],
                    source_name=source["name"],
                    priority=int(source["priority"]),
                    source_order=source_order,
                    item_order=item_order,
                )
            )
            record["valid"] += 1
        source_stats.append(record)
    return candidates, source_stats, recognized_total, rejected_total


def deduplicate(candidates: Sequence[Candidate]) -> tuple[list[Candidate], int]:
    winners: dict[tuple, Candidate] = {}
    ordered = sorted(
        candidates,
        key=lambda item: (-item.priority, item.source_order, item.item_order, item.parsed.original),
    )
    for candidate in ordered:
        winners.setdefault(candidate.parsed.identity, candidate)
    result = sorted(
        winners.values(),
        key=lambda item: (item.parsed.protocol, repr(item.parsed.identity), item.parsed.original),
    )
    return result, len(candidates) - len(result)


def select_mixed(
    candidates: Sequence[Candidate],
    target_keys: int,
    required_protocols: Sequence[str] = (),
) -> list[Candidate]:
    """Select an exact, deterministic and protocol-balanced subset."""
    if target_keys < 1:
        raise BuildError("mix target must be a positive integer")

    unknown = set(required_protocols) - set(PROTOCOL_FILES)
    if unknown:
        raise BuildError(f"mix requires unknown protocols: {sorted(unknown)}")

    groups: dict[str, list[Candidate]] = {protocol: [] for protocol in PROTOCOL_FILES}
    for candidate in candidates:
        groups[candidate.parsed.protocol].append(candidate)
    missing = [protocol for protocol in required_protocols if not groups[protocol]]
    if missing:
        raise BuildError(f"mix is missing required protocols: {', '.join(missing)}")
    if len(candidates) < target_keys:
        raise BuildError(
            f"mix target failed: {len(candidates)} unique keys available, "
            f"target is {target_keys}"
        )

    for group in groups.values():
        group.sort(
            key=lambda item: (
                -item.priority,
                item.source_order,
                item.item_order,
                item.parsed.original,
            )
        )

    active = [protocol for protocol in PROTOCOL_FILES if groups[protocol]]
    offsets = {protocol: 0 for protocol in active}
    selected: list[Candidate] = []
    while len(selected) < target_keys:
        added = False
        for protocol in active:
            offset = offsets[protocol]
            if offset >= len(groups[protocol]):
                continue
            selected.append(groups[protocol][offset])
            offsets[protocol] += 1
            added = True
            if len(selected) == target_keys:
                break
        if not added:  # Defensive: the size check above should make this unreachable.
            break
    if len(selected) != target_keys:
        raise BuildError(
            f"mix target failed: selected {len(selected)} keys, target is {target_keys}"
        )
    return selected


def filter_geography(
    candidates: Sequence[Candidate], classifier: Callable[[str], str], workers: int = 24
) -> tuple[list[Candidate], Counter]:
    hosts = sorted({candidate.parsed.server for candidate in candidates})
    classifications: dict[str, str] = {}
    if workers <= 1:
        for host in hosts:
            try:
                classifications[host] = classifier(host)
            except Exception:
                classifications[host] = "UNKNOWN"
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_hosts = {executor.submit(classifier, host): host for host in hosts}
            for future in concurrent.futures.as_completed(future_hosts):
                host = future_hosts[future]
                try:
                    value = future.result()
                except Exception:
                    value = "UNKNOWN"
                classifications[host] = value
    classifications = {
        host: value if value in {"RU", "NON_RU", "UNKNOWN"} else "UNKNOWN"
        for host, value in classifications.items()
    }
    counts = Counter(classifications[candidate.parsed.server] for candidate in candidates)
    return [
        candidate
        for candidate in candidates
        if classifications[candidate.parsed.server] != "RU"
    ], counts


def _read_previous_protocol(root: Path, protocol: str) -> list[str]:
    path = root / PROTOCOL_FILES[protocol]
    if not path.exists():
        return []
    result: list[str] = []
    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw:
            return []
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    for line in text.splitlines():
        try:
            parsed = parse_uri(line)
        except ValidationError:
            return []
        if parsed.protocol != protocol:
            return []
        result.append(line)
    return result


def _write_txt(path: Path, lines: Sequence[str]) -> None:
    content = "".join(f"{line}\n" for line in lines)
    path.write_bytes(content.encode("utf-8"))


def _txt_bytes(lines: Sequence[str]) -> bytes:
    return "".join(f"{line}\n" for line in lines).encode("utf-8")


@contextlib.contextmanager
def _staging_directory(root: Path):
    """Create a private-name staging directory that inherits repository ACLs.

    tempfile creates mode 0700 directories. On modern Windows that translates
    to an owner-only ACL which follows files moved out with os.replace, making
    the published artifacts unreadable to Git running as the interactive user.
    WireVeil data is public, so mode 0755 plus the process umask is appropriate
    and keeps atomic replacements readable on every supported platform.
    """
    path: Path | None = None
    for _attempt in range(10):
        candidate = root / f".wireveil-{uuid.uuid4().hex}"
        try:
            candidate.mkdir(mode=0o755)
        except FileExistsError:
            continue
        path = candidate
        break
    if path is None:
        raise BuildError("cannot create a unique staging directory")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _published_txt_is_unchanged(
    root: Path, effective: Mapping[str, Sequence[str]], subscription: Sequence[str]
) -> bool:
    expected = {"subscription.txt": _txt_bytes(subscription)}
    expected.update(
        {
            filename: _txt_bytes(effective[protocol])
            for protocol, filename in PROTOCOL_FILES.items()
        }
    )
    try:
        return all((root / name).read_bytes() == content for name, content in expected.items())
    except OSError:
        return False


def validate_txt(path: Path, expected_protocol: str | None = None) -> list[str]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise BuildError(f"{path.name} contains a UTF-8 BOM")
    if b"\r" in raw:
        raise BuildError(f"{path.name} contains non-LF line endings")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuildError(f"{path.name} is not UTF-8") from exc
    if text and not text.endswith("\n"):
        raise BuildError(f"{path.name} lacks a trailing newline")
    lines = text.splitlines()
    if any(not line or line != line.strip() for line in lines):
        raise BuildError(f"{path.name} contains blank or padded lines")
    if len(lines) != len(set(lines)):
        raise BuildError(f"{path.name} contains exact duplicates")
    for line in lines:
        try:
            parsed = parse_uri(line)
        except ValidationError as exc:
            raise BuildError(f"{path.name} contains an invalid URI: {exc}") from exc
        if expected_protocol and parsed.protocol != expected_protocol:
            raise BuildError(f"{path.name} contains {parsed.protocol}, expected {expected_protocol}")
    return lines


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(131072), b""):
            digest.update(block)
    return digest.hexdigest()


def _iso_times(now: dt.datetime | None = None) -> tuple[str, str]:
    current = now or dt.datetime.now(dt.timezone.utc)
    current = current.astimezone(dt.timezone.utc).replace(microsecond=0)
    moscow = current.astimezone(dt.timezone(dt.timedelta(hours=3), name="MSK"))
    return current.isoformat().replace("+00:00", "Z"), moscow.isoformat()


def _load_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        warn("existing update-history.json is invalid; starting a fresh history")
        return []
    updates = data.get("updates") if isinstance(data, dict) else None
    return updates[-19:] if isinstance(updates, list) else []


README_START = "<!-- WIREVEIL_STATS_START -->"
README_END = "<!-- WIREVEIL_STATS_END -->"


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.2f} MiB"


def _update_readme(template: str, stats: dict) -> str:
    rows = []
    labels = {
        "subscription.txt": "Все протоколы",
        "vless.txt": "VLESS",
        "trojan.txt": "Trojan",
        "shadowsocks.txt": "Shadowsocks",
        "vmess.txt": "VMess",
        "hysteria.txt": "Hysteria",
        "hysteria2.txt": "Hysteria2",
        "tuic.txt": "TUIC",
    }
    for filename, values in stats["output_files"].items():
        rows.append(
            f"| {labels[filename]} | "
            f"[RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/{filename}) | "
            f"{values['keys']} | {_format_size(values['bytes'])} |"
        )
    dynamic = (
        f"{README_START}\n"
        f"Последнее успешное обновление: **{stats['built_at']['msk']}** "
        f"(UTC: {stats['built_at']['utc']}).\n\n"
        "| Подписка | RAW-ссылка | Ключей | Размер |\n"
        "|---|---|---:|---:|\n"
        + "\n".join(rows)
        + f"\n{README_END}"
    )
    pattern = re.compile(re.escape(README_START) + r".*?" + re.escape(README_END), re.S)
    if not pattern.search(template):
        raise BuildError("README.md has no WireVeil statistics markers")
    return pattern.sub(dynamic, template)


def publish_build(
    protocol_lines: Mapping[str, Sequence[str]],
    *,
    source_stats: list[dict],
    recognized: int,
    rejected: int,
    duplicates: int,
    geo_counts: Mapping[str, int],
    eligible_keys: int | None = None,
    mix_target: int | None = None,
    root: Path = ROOT,
    min_keys: int = 100,
    max_keys: int = 1000,
    now: dt.datetime | None = None,
) -> dict:
    """Stage, validate, and atomically replace every published artifact."""
    effective: dict[str, list[str]] = {}
    preserved: list[str] = []
    for protocol in PROTOCOL_FILES:
        current = list(protocol_lines.get(protocol, ()))
        if not current:
            previous = _read_previous_protocol(root, protocol)
            if previous:
                current = previous
                preserved.append(protocol)
        effective[protocol] = current

    subscription: list[str] = []
    for protocol in PROTOCOL_FILES:
        subscription.extend(effective[protocol])
    # Deterministic order also prevents churn if upstream sources reorder keys.
    subscription.sort(key=lambda uri: (parse_uri(uri).protocol, repr(parse_uri(uri).identity), uri))
    if len(subscription) < min_keys:
        raise BuildError(
            f"safety threshold failed: {len(subscription)} unique keys, minimum is {min_keys}"
        )
    if len(subscription) > max_keys:
        raise BuildError(
            f"quality threshold failed: {len(subscription)} unique keys, maximum is {max_keys}"
        )

    # A successful fetch with identical subscriptions is a no-op. This keeps
    # hourly automation from committing timestamp-only changes and defines the
    # history as the last 20 successful content publications.
    if _published_txt_is_unchanged(root, effective, subscription):
        try:
            existing_stats = json.loads((root / "stats.json").read_text(encoding="utf-8"))
            existing_history = json.loads(
                (root / "update-history.json").read_text(encoding="utf-8")
            )
            existing_readme = (root / "README.md").read_text(encoding="utf-8")
            metadata_matches = (
                isinstance(existing_history.get("updates"), list)
                and README_START in existing_readme
                and README_END in existing_readme
                and int(existing_stats.get("total_keys", -1)) == len(subscription)
                and all(
                    existing_stats["output_files"][filename]["sha256"]
                    == hashlib.sha256((root / filename).read_bytes()).hexdigest()
                    for filename in ["subscription.txt", *PROTOCOL_FILES.values()]
                )
            )
        except (AttributeError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            pass
        else:
            if metadata_matches:
                print("WireVeil subscriptions are unchanged; published files were not modified.")
                return existing_stats

    utc_time, msk_time = _iso_times(now)
    temp_parent = root
    temp_parent.mkdir(parents=True, exist_ok=True)
    with _staging_directory(temp_parent) as temp:
        for protocol, filename in PROTOCOL_FILES.items():
            _write_txt(temp / filename, effective[protocol])
        _write_txt(temp / "subscription.txt", subscription)

        output_files: dict[str, dict] = {}
        for filename in ["subscription.txt", *PROTOCOL_FILES.values()]:
            expected = None
            for protocol, protocol_filename in PROTOCOL_FILES.items():
                if protocol_filename == filename:
                    expected = protocol
                    break
            lines = validate_txt(temp / filename, expected)
            output_files[filename] = {
                "keys": len(lines),
                "bytes": (temp / filename).stat().st_size,
                "sha256": _sha256(temp / filename),
            }

        total_by_protocol = {
            protocol: len(effective[protocol]) for protocol in PROTOCOL_FILES
        }
        stats = {
            "schema_version": 1,
            "built_at": {"utc": utc_time, "msk": msk_time},
            "sources": source_stats,
            "recognized_keys": recognized,
            "valid_keys_before_deduplication": sum(
                int(source.get("valid", 0)) for source in source_stats
            ),
            "rejected_keys": rejected,
            "duplicates_removed": duplicates,
            "eligible_keys_before_mix": (
                int(eligible_keys) if eligible_keys is not None else len(subscription)
            ),
            "mix_target": mix_target,
            "total_keys": len(subscription),
            "keys_by_protocol": total_by_protocol,
            "geography": {
                "ru_excluded": int(geo_counts.get("RU", 0)),
                "unknown_kept": int(geo_counts.get("UNKNOWN", 0)),
                "non_ru_kept": int(geo_counts.get("NON_RU", 0)),
            },
            "preserved_protocol_files": preserved,
            "output_files": output_files,
        }

        history = _load_history(root / "update-history.json")
        history.append(
            {
                "utc": utc_time,
                "msk": msk_time,
                "total_keys": len(subscription),
                "keys_by_protocol": total_by_protocol,
                "duplicates_removed": duplicates,
                "ru_excluded": int(geo_counts.get("RU", 0)),
                "subscription_sha256": output_files["subscription.txt"]["sha256"],
            }
        )
        (temp / "stats.json").write_text(
            json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        (temp / "update-history.json").write_text(
            json.dumps({"updates": history[-20:]}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        readme_path = root / "README.md"
        try:
            readme = readme_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BuildError(f"cannot read README.md: {exc}") from exc
        (temp / "README.md").write_text(
            _update_readme(readme, stats), encoding="utf-8", newline="\n"
        )

        for json_name in ("stats.json", "update-history.json"):
            try:
                json.loads((temp / json_name).read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise BuildError(f"generated {json_name} is invalid") from exc
        if not (temp / "README.md").read_text(encoding="utf-8").endswith("\n"):
            raise BuildError("generated README.md lacks a trailing newline")

        # All validation has succeeded. os.replace is atomic per file; the safety
        # threshold ensures no partial empty/corrupt build is ever staged here.
        publish_names = [
            "subscription.txt",
            *PROTOCOL_FILES.values(),
            "stats.json",
            "update-history.json",
            "README.md",
        ]
        for filename in publish_names:
            os.replace(temp / filename, root / filename)
    return stats


def build(
    *,
    root: Path = ROOT,
    sources_path: Path | None = None,
    fetcher: Callable[[str], str] | None = None,
    classifier: Callable[[str], str] | None = None,
    min_keys: int = 100,
    timeout: float = 20.0,
    retries: int = 3,
    workers: int = 12,
    max_keys: int = 1000,
    target_keys: int | None = None,
    required_protocols: Sequence[str] = (),
) -> dict:
    sources = load_sources(sources_path or root / "sources.json")
    source_fetcher = fetcher or (lambda url: fetch_url(url, timeout=timeout, retries=retries))
    candidates, source_stats, recognized, rejected = collect_candidates(sources, source_fetcher)
    if not candidates:
        raise BuildError("no valid keys were collected")
    unique, duplicates = deduplicate(candidates)

    rdap: RdapGeoIndex | None = None
    if classifier is None:
        try:
            rdap_bootstrap = RdapBootstrap.from_documents(
                fetch_json_url(IANA_RDAP_IPV4_URL, timeout=timeout, retries=retries),
                fetch_json_url(IANA_RDAP_IPV6_URL, timeout=timeout, retries=retries),
            )
            rdap_url_for = rdap_bootstrap.url_for
        except BuildError as exc:
            warn(f"IANA RDAP bootstrap unavailable: {exc}; using rdap.org fallback")
            rdap_url_for = None
        rdap = RdapGeoIndex.load(
            root / "geo-cache.json",
            fetcher=lambda url: fetch_json_url(url, timeout=timeout, retries=retries),
            url_for_address=rdap_url_for,
        )
        try:
            delegated = fetch_url(RIPE_DELEGATED_URL, timeout=timeout, retries=retries)
            russian_networks = RussianNetworkIndex.from_text(delegated)
        except BuildError as exc:
            warn(f"RIPE delegated data unavailable: {exc}; RDAP remains authoritative")
            russian_networks = None
        geo = GeoClassifier(russian_networks, rdap)
        classifier = geo.classify
    filtered, geo_counts = filter_geography(unique, classifier, workers=workers)
    eligible_keys = len(filtered)
    if target_keys is not None:
        filtered = select_mixed(filtered, target_keys, required_protocols)
    protocol_lines: dict[str, list[str]] = {protocol: [] for protocol in PROTOCOL_FILES}
    for candidate in filtered:
        protocol_lines[candidate.parsed.protocol].append(candidate.parsed.original)
    stats = publish_build(
        protocol_lines,
        source_stats=source_stats,
        recognized=recognized,
        rejected=rejected,
        duplicates=duplicates,
        geo_counts=geo_counts,
        eligible_keys=eligible_keys,
        mix_target=target_keys,
        root=root,
        min_keys=min_keys,
        max_keys=max_keys,
    )
    if rdap is not None:
        rdap.save(root / "geo-cache.json")
        print(
            f"RDAP: {rdap.queries} queries, {rdap.cache_hits} range-cache hits, "
            f"{rdap.query_failures} failures"
        )
        if rdap.query_failures:
            warn(
                f"{rdap.query_failures} RDAP lookups failed; affected endpoints were kept as UNKNOWN"
            )
    return stats


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=SOURCES_PATH)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--min-keys", type=int, default=100)
    parser.add_argument("--max-keys", type=int, default=1000)
    parser.add_argument("--target-keys", type=int, default=1000)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        stats = build(
            root=ROOT,
            sources_path=args.sources,
            timeout=args.timeout,
            retries=args.retries,
            workers=args.workers,
            min_keys=args.min_keys,
            max_keys=args.max_keys,
            target_keys=args.target_keys,
            required_protocols=MIX_REQUIRED_PROTOCOLS,
        )
    except (BuildError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"WireVeil build complete: {stats['total_keys']} keys, "
        f"{stats['duplicates_removed']} duplicates removed, "
        f"{stats['geography']['ru_excluded']} RU endpoints excluded"
    )
    for protocol, count in stats["keys_by_protocol"].items():
        print(f"  {protocol}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
