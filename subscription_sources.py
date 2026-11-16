"""Persistent source list for the regular sing-box subscription checker."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import urllib.parse
import uuid
from pathlib import Path
from typing import Iterable, Sequence

from scripts import local_checker


SOURCES_VERSION = 1
MAX_SOURCES = 200
MAX_URL_LIST_BYTES = 1024 * 1024
VALID_SOURCE_KINDS = {"url", "file", "text"}


@dataclasses.dataclass(frozen=True)
class SubscriptionSource:
    source_id: str
    name: str
    kind: str
    value: str
    selected: bool = True

    @property
    def kind_label(self) -> str:
        return {"url": "URL", "file": "Файл", "text": "Текст"}.get(
            self.kind, self.kind
        )

    @property
    def display(self) -> str:
        if self.kind == "file":
            return str(Path(self.value))
        if self.kind != "url":
            return "Сохранённое содержимое"
        try:
            parsed = urllib.parse.urlsplit(self.value)
        except ValueError:
            return self.value
        host = parsed.hostname or parsed.netloc
        if parsed.port:
            host = f"{host}:{parsed.port}"
        path = parsed.path or "/"
        return urllib.parse.urlunsplit((parsed.scheme, host, path, "", ""))


def new_source_id() -> str:
    return uuid.uuid4().hex


def source_name_from_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "Подписка"
    path_name = Path(urllib.parse.unquote(parsed.path)).name
    host = parsed.hostname or "Подписка"
    return f"{host} · {path_name}" if path_name else host


def validate_subscription_url(value: str) -> str | None:
    url = value.strip()
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return url


def subscription_urls_from_text(value: str) -> tuple[str, ...] | None:
    """Parse a plain TXT manifest containing only HTTP(S) subscription URLs."""
    urls: list[str] = []
    seen: set[str] = set()
    for line in value.removeprefix("\ufeff").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        url = validate_subscription_url(candidate)
        if url is None:
            return None
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return tuple(urls) if urls else None


def subscription_url_list_text(sources: Iterable[SubscriptionSource]) -> str:
    """Return the unique URL sources as a portable one-URL-per-line TXT."""
    urls: list[str] = []
    seen: set[str] = set()
    for source in sources:
        if source.kind != "url":
            continue
        url = validate_subscription_url(source.value)
        if url is None or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return "".join(f"{url}\n" for url in urls)


def subscription_sources_from_file(path: Path) -> list[SubscriptionSource]:
    """Expand a portable TXT URL list, otherwise keep the file as one source."""
    resolved = Path(path).resolve()
    file_source = SubscriptionSource(
        new_source_id(), resolved.name, "file", str(resolved)
    )
    if resolved.suffix.casefold() != ".txt":
        return [file_source]
    try:
        if resolved.stat().st_size > MAX_URL_LIST_BYTES:
            return [file_source]
        text = resolved.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return [file_source]
    urls = subscription_urls_from_text(text)
    if urls is None:
        return [file_source]
    return [
        SubscriptionSource(
            new_source_id(), source_name_from_url(url), "url", url
        )
        for url in urls
    ]


def load_subscription_sources(path: Path) -> list[SubscriptionSource]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    if not isinstance(raw, dict) or raw.get("version") != SOURCES_VERSION:
        return []
    items = raw.get("sources")
    if not isinstance(items, list):
        return []
    sources: list[SubscriptionSource] = []
    known_ids: set[str] = set()
    for item in items[:MAX_SOURCES]:
        if not isinstance(item, dict):
            continue
        source_id = item.get("id")
        name = item.get("name")
        kind = item.get("kind")
        value = item.get("value")
        selected = item.get("selected", True)
        if (
            not isinstance(source_id, str)
            or not source_id.strip()
            or source_id in known_ids
            or not isinstance(name, str)
            or not name.strip()
            or not isinstance(kind, str)
            or kind not in VALID_SOURCE_KINDS
            or not isinstance(value, str)
            or not value.strip()
            or not isinstance(selected, bool)
        ):
            continue
        known_ids.add(source_id)
        sources.append(
            SubscriptionSource(
                source_id=source_id,
                name=name.strip()[:160],
                kind=kind,
                value=value,
                selected=selected,
            )
        )
    return sources


def save_subscription_sources(
    path: Path, sources: Sequence[SubscriptionSource]
) -> None:
    payload = {
        "version": SOURCES_VERSION,
        "warning": "Contains private subscription URLs, paths, or pasted keys. Do not share.",
        "sources": [
            {
                "id": source.source_id,
                "name": source.name,
                "kind": source.kind,
                "value": source.value,
                "selected": source.selected,
            }
            for source in sources[:MAX_SOURCES]
        ],
    }
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(path)


def selected_sources_identity(sources: Iterable[SubscriptionSource]) -> str:
    """Return a stable result-cache identity for the checked source set."""
    selected = sorted(
        (
            {
                "id": source.source_id,
                "kind": source.kind,
                "value_digest": hashlib.sha256(
                    source.value.encode("utf-8")
                ).hexdigest(),
            }
            for source in sources
            if source.selected
        ),
        key=lambda item: str(item["id"]),
    )
    return "selected-sources:\n" + json.dumps(
        selected, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def import_subscription_sources(
    sources: Sequence[SubscriptionSource],
) -> tuple[local_checker.ImportedSubscription, tuple[tuple[str, str], ...]]:
    """Load selected sources independently and merge their unique share URIs."""
    lines: list[str] = []
    seen: set[str] = set()
    rejected = 0
    duplicates = 0
    failures: list[tuple[str, str]] = []

    for source in sources:
        if not source.selected:
            continue
        try:
            imported = (
                local_checker.read_subscription_file(Path(source.value))
                if source.kind == "file"
                else local_checker.import_subscription(source.value)
            )
        except (local_checker.LocalCheckError, OSError) as exc:
            failures.append((source.name, str(exc)))
            continue
        rejected += imported.rejected
        duplicates += imported.duplicates
        for uri in imported.lines:
            if uri in seen:
                duplicates += 1
                continue
            seen.add(uri)
            lines.append(uri)

    if not lines:
        if failures:
            details = "; ".join(
                f"{name}: {detail}" for name, detail in failures[:3]
            )
            raise local_checker.LocalCheckError(
                f"Не удалось подготовить выбранные подписки. {details}"
            )
        raise local_checker.LocalCheckError(
            "Выберите хотя бы одну подписку для проверки."
        )
    return (
        local_checker.ImportedSubscription(
            tuple(lines), rejected=rejected, duplicates=duplicates
        ),
        tuple(failures),
    )
