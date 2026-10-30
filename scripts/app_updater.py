#!/usr/bin/env python3
"""Secure, installer-based updates for WireVeil Checker releases."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


REPOSITORY = "markKikhtenko/WireVeil"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASE_DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"
INSTALLER_ASSET_NAME = "WireVeilChecker-Setup-x64.exe"
CHECKSUM_ASSET_NAME = f"{INSTALLER_ASSET_NAME}.sha256"
USER_AGENT = "WireVeilChecker-Updater/1"
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_CHECKSUM_BYTES = 16 * 1024
MAX_INSTALLER_BYTES = 512 * 1024 * 1024
_VERSION_RE = re.compile(r"^(?:checker-v)?(\d+)\.(\d+)\.(\d+)$")


class UpdateError(RuntimeError):
    """The update could not be checked, verified, or started."""


@dataclass(frozen=True)
class ReleaseUpdate:
    version: str
    tag: str
    page_url: str
    notes: str
    installer_url: str
    checksum_url: str


def version_tuple(value: str) -> tuple[int, int, int]:
    """Return a comparable stable version tuple."""
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        raise UpdateError(f"Некорректная версия приложения: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def is_newer_version(candidate: str, current: str) -> bool:
    return version_tuple(candidate) > version_tuple(current)


def _request(url: str, *, accept: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={"Accept": accept, "User-Agent": USER_AGENT},
        method="GET",
    )


def _read_limited(
    url: str,
    *,
    accept: str,
    timeout: float,
    maximum: int,
    opener: Callable[..., object],
) -> bytes:
    try:
        response = opener(_request(url, accept=accept), timeout=timeout)
        with response:  # type: ignore[attr-defined]
            content_length = response.headers.get("Content-Length")  # type: ignore[attr-defined]
            if content_length is not None and int(content_length) > maximum:
                raise UpdateError("Ответ сервера обновлений слишком большой.")
            payload = response.read(maximum + 1)  # type: ignore[attr-defined]
    except UpdateError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise UpdateError(f"Не удалось связаться с сервером обновлений: {exc}") from exc
    if len(payload) > maximum:
        raise UpdateError("Ответ сервера обновлений слишком большой.")
    return payload


def _asset_url(assets: object, name: str) -> str:
    if not isinstance(assets, list):
        raise UpdateError("GitHub вернул релиз без списка файлов.")
    for asset in assets:
        if not isinstance(asset, dict) or asset.get("name") != name:
            continue
        url = asset.get("browser_download_url")
        if not isinstance(url, str) or not url.startswith(RELEASE_DOWNLOAD_PREFIX):
            raise UpdateError(f"Недопустимая ссылка для файла обновления {name}.")
        return url
    raise UpdateError(f"В новом релизе отсутствует файл {name}.")


def check_for_update(
    current_version: str,
    *,
    timeout: float = 15.0,
    opener: Callable[..., object] = urllib.request.urlopen,
) -> ReleaseUpdate | None:
    """Return the latest installable release when it is newer than current."""
    payload = _read_limited(
        LATEST_RELEASE_API,
        accept="application/vnd.github+json",
        timeout=timeout,
        maximum=MAX_METADATA_BYTES,
        opener=opener,
    )
    try:
        release = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError("GitHub вернул некорректные данные релиза.") from exc
    if not isinstance(release, dict):
        raise UpdateError("GitHub вернул некорректные данные релиза.")
    if release.get("draft") or release.get("prerelease"):
        raise UpdateError("Последний релиз не является стабильным.")

    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith("checker-v"):
        raise UpdateError("Последний релиз имеет неподдерживаемый тег.")
    latest = ".".join(str(part) for part in version_tuple(tag))
    if not is_newer_version(latest, current_version):
        return None

    page_url = release.get("html_url")
    expected_page_prefix = f"https://github.com/{REPOSITORY}/releases/"
    if not isinstance(page_url, str) or not page_url.startswith(expected_page_prefix):
        raise UpdateError("GitHub вернул недопустимую страницу релиза.")
    notes = release.get("body") if isinstance(release.get("body"), str) else ""
    assets = release.get("assets")
    return ReleaseUpdate(
        version=latest,
        tag=tag,
        page_url=page_url,
        notes=notes,
        installer_url=_asset_url(assets, INSTALLER_ASSET_NAME),
        checksum_url=_asset_url(assets, CHECKSUM_ASSET_NAME),
    )


def _expected_checksum(text: str) -> str:
    for line in text.splitlines():
        match = re.fullmatch(
            rf"\s*([0-9a-fA-F]{{64}})\s+\*?{re.escape(INSTALLER_ASSET_NAME)}\s*",
            line,
        )
        if match is not None:
            return match.group(1).lower()
    raise UpdateError("Файл контрольной суммы обновления имеет неверный формат.")


def _download_installer(
    url: str,
    destination: Path,
    *,
    timeout: float,
    opener: Callable[..., object],
    progress: Callable[[int, int | None], None] | None,
) -> str:
    digest = hashlib.sha256()
    downloaded = 0
    try:
        response = opener(
            _request(url, accept="application/octet-stream"), timeout=timeout
        )
        with response:  # type: ignore[attr-defined]
            raw_length = response.headers.get("Content-Length")  # type: ignore[attr-defined]
            total = int(raw_length) if raw_length is not None else None
            if total is not None and total > MAX_INSTALLER_BYTES:
                raise UpdateError("Установщик обновления слишком большой.")
            with destination.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > MAX_INSTALLER_BYTES:
                        raise UpdateError("Установщик обновления слишком большой.")
                    digest.update(chunk)
                    output.write(chunk)
                    if progress is not None:
                        progress(downloaded, total)
    except UpdateError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise UpdateError(f"Не удалось скачать установщик обновления: {exc}") from exc
    if downloaded == 0:
        raise UpdateError("GitHub вернул пустой установщик обновления.")
    return digest.hexdigest()


def download_update(
    release: ReleaseUpdate,
    *,
    timeout: float = 60.0,
    opener: Callable[..., object] = urllib.request.urlopen,
    progress: Callable[[int, int | None], None] | None = None,
) -> Path:
    """Download the release installer and verify its published SHA-256."""
    checksum_payload = _read_limited(
        release.checksum_url,
        accept="text/plain",
        timeout=timeout,
        maximum=MAX_CHECKSUM_BYTES,
        opener=opener,
    )
    try:
        expected = _expected_checksum(checksum_payload.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise UpdateError("Контрольная сумма обновления не является текстом ASCII.") from exc

    temporary_root = Path(tempfile.mkdtemp(prefix="WireVeilChecker-update-"))
    installer = temporary_root / INSTALLER_ASSET_NAME
    try:
        actual = _download_installer(
            release.installer_url,
            installer,
            timeout=timeout,
            opener=opener,
            progress=progress,
        )
        if actual != expected:
            raise UpdateError(
                "SHA-256 установщика не совпадает с опубликованной контрольной суммой."
            )
        return installer
    except Exception:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise


def launch_installer(installer: Path) -> None:
    """Start verified Inno Setup in update mode without blocking the UI."""
    if not installer.is_file() or installer.name != INSTALLER_ASSET_NAME:
        raise UpdateError("Проверенный установщик обновления не найден.")
    try:
        subprocess.Popen(
            [
                str(installer),
                "/SILENT",
                "/SUPPRESSMSGBOXES",
                "/NORESTART",
                "/CLOSEAPPLICATIONS",
                "/RESTARTAPPLICATIONS",
                "/WIREVEILUPDATE=1",
            ],
            close_fds=True,
        )
    except OSError as exc:
        raise UpdateError(f"Не удалось запустить установщик обновления: {exc}") from exc
