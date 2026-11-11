#!/usr/bin/env python3
"""Secure in-place updates for WireVeil Checker releases."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable


REPOSITORY = "markKikhtenko/WireVeil"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASE_DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"
INSTALLER_ASSET_NAME = "WireVeilChecker-Setup-x64.exe"
CHECKSUM_ASSET_NAME = f"{INSTALLER_ASSET_NAME}.sha256"
PORTABLE_ASSET_NAME = "WireVeilChecker-windows-x64.zip"
PORTABLE_CHECKSUM_ASSET_NAME = f"{PORTABLE_ASSET_NAME}.sha256"
USER_AGENT = "WireVeilChecker-Updater/1"
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_CHECKSUM_BYTES = 16 * 1024
MAX_INSTALLER_BYTES = 512 * 1024 * 1024
MAX_UPDATE_PACKAGE_BYTES = 768 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5_000
MAX_RELEASE_NOTES_CHARS = 20_000
DOWNLOAD_ATTEMPTS = 3
_VERSION_RE = re.compile(r"^(?:checker-v)?(\d+)\.(\d+)\.(\d+)$")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\([^\)]+\)")


class UpdateError(RuntimeError):
    """The update could not be checked, verified, or started."""


class _RetryableDownloadError(UpdateError):
    """A package download failed in a way that may succeed on retry."""


@dataclass(frozen=True)
class ReleaseUpdate:
    version: str
    tag: str
    page_url: str
    notes: str
    installer_url: str
    checksum_url: str
    asset_name: str = INSTALLER_ASSET_NAME


def version_tuple(value: str) -> tuple[int, int, int]:
    """Return a comparable stable version tuple."""
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        raise UpdateError(f"Некорректная версия приложения: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def is_newer_version(candidate: str, current: str) -> bool:
    return version_tuple(candidate) > version_tuple(current)


def format_release_notes(notes: str) -> str:
    """Convert GitHub release Markdown into compact readable plain text."""
    heading_names = {
        "what's changed": "Что изменилось",
        "new contributors": "Новые участники",
        "full changelog": "Полный список изменений",
    }
    formatted: list[str] = []
    normalized = notes.replace("\r\n", "\n").replace("\r", "\n")
    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        if not line:
            if formatted and formatted[-1]:
                formatted.append("")
            continue
        if line.startswith("#"):
            heading = line.lstrip("#").strip().strip("*")
            line = heading_names.get(heading.casefold(), heading)
        elif line.startswith(("* ", "- ")):
            line = f"• {line[2:].strip()}"
        line = re.sub(r"\*\*([^*]+)\*\*", r"\1", line)
        line = re.sub(r"\x60([^\x60]+)\x60", r"\1", line)
        line = _MARKDOWN_LINK_RE.sub(r"\1", line)
        if line.casefold().startswith("full changelog:"):
            line = "Полный список изменений:" + line.split(":", 1)[1]
        formatted.append(line)

    text = "\n".join(formatted).strip()
    if not text:
        return "Для этой версии список изменений не указан."
    if len(text) > MAX_RELEASE_NOTES_CHARS:
        text = text[: MAX_RELEASE_NOTES_CHARS - 2].rstrip() + "\n…"
    return text


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
    portable_published = isinstance(assets, list) and any(
        isinstance(asset, dict) and asset.get("name") == PORTABLE_ASSET_NAME
        for asset in assets
    )
    if portable_published:
        package_name = PORTABLE_ASSET_NAME
        package_url = _asset_url(assets, PORTABLE_ASSET_NAME)
        checksum_url = _asset_url(assets, PORTABLE_CHECKSUM_ASSET_NAME)
    else:
        package_name = INSTALLER_ASSET_NAME
        package_url = _asset_url(assets, INSTALLER_ASSET_NAME)
        checksum_url = _asset_url(assets, CHECKSUM_ASSET_NAME)

    return ReleaseUpdate(
        version=latest,
        tag=tag,
        page_url=page_url,
        notes=notes,
        installer_url=package_url,
        checksum_url=checksum_url,
        asset_name=package_name,
    )


def _expected_checksum(text: str, asset_name: str = INSTALLER_ASSET_NAME) -> str:
    for line in text.splitlines():
        match = re.fullmatch(
            rf"\s*([0-9a-fA-F]{{64}})\s+\*?{re.escape(asset_name)}\s*",
            line,
        )
        if match is not None:
            return match.group(1).lower()
    raise UpdateError("Файл контрольной суммы обновления имеет неверный формат.")


def _download_asset(
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
            if total is not None and total > MAX_UPDATE_PACKAGE_BYTES:
                raise UpdateError("Пакет обновления слишком большой.")
            if progress is not None:
                progress(0, total)
            with destination.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > MAX_UPDATE_PACKAGE_BYTES:
                        raise UpdateError("Пакет обновления слишком большой.")
                    digest.update(chunk)
                    output.write(chunk)
                    if progress is not None:
                        progress(downloaded, total)
    except UpdateError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise _RetryableDownloadError(
            f"Не удалось скачать пакет обновления: {exc}"
        ) from exc
    if downloaded == 0:
        raise _RetryableDownloadError("GitHub вернул пустой пакет обновления.")
    if total is not None and downloaded != total:
        raise _RetryableDownloadError(
            "Пакет обновления скачан не полностью "
            f"({downloaded} из {total} байт)."
        )
    return digest.hexdigest()


def download_update(
    release: ReleaseUpdate,
    *,
    timeout: float = 60.0,
    opener: Callable[..., object] = urllib.request.urlopen,
    progress: Callable[[int, int | None], None] | None = None,
) -> Path:
    """Download the release package and verify its published SHA-256."""
    checksum_payload = _read_limited(
        release.checksum_url,
        accept="text/plain",
        timeout=timeout,
        maximum=MAX_CHECKSUM_BYTES,
        opener=opener,
    )
    try:
        expected = _expected_checksum(
            checksum_payload.decode("ascii"), release.asset_name
        )
    except UnicodeDecodeError as exc:
        raise UpdateError("Контрольная сумма обновления не является текстом ASCII.") from exc

    temporary_root = Path(tempfile.mkdtemp(prefix="WireVeilChecker-update-"))
    package = temporary_root / release.asset_name
    try:
        last_error: UpdateError | None = None
        for attempt in range(DOWNLOAD_ATTEMPTS):
            try:
                actual = _download_asset(
                    release.installer_url,
                    package,
                    timeout=timeout,
                    opener=opener,
                    progress=progress,
                )
            except _RetryableDownloadError as exc:
                last_error = exc
            else:
                if actual == expected:
                    return package
                last_error = UpdateError(
                    "SHA-256 пакета не совпадает с опубликованной "
                    "контрольной суммой."
                )
            package.unlink(missing_ok=True)
            if attempt + 1 == DOWNLOAD_ATTEMPTS:
                assert last_error is not None
                raise last_error
        raise AssertionError("download retry loop ended unexpectedly")
    except Exception:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise


def extract_update_package(package: Path, destination: Path) -> Path:
    """Safely extract a verified portable package and return its app directory."""
    if not package.is_file() or package.name != PORTABLE_ASSET_NAME:
        raise UpdateError("Проверенный portable-пакет обновления не найден.")
    if destination.exists():
        raise UpdateError("Временный каталог обновления уже существует.")

    seen: set[str] = set()
    extracted_size = 0
    try:
        with zipfile.ZipFile(package) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                raise UpdateError("Архив обновления имеет недопустимый состав.")

            validated: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []
            for member in members:
                raw_name = member.filename
                if not raw_name or "\x00" in raw_name or "\\" in raw_name:
                    raise UpdateError("Архив обновления содержит недопустимый путь.")
                member_path = PurePosixPath(raw_name)
                parts = tuple(part for part in member_path.parts if part not in ("", "."))
                if (
                    member_path.is_absolute()
                    or not parts
                    or any(part == ".." for part in parts)
                    or ":" in parts[0]
                    or parts[0] != "WireVeilChecker"
                ):
                    raise UpdateError("Архив обновления содержит недопустимый путь.")
                key = "/".join(parts).casefold()
                if key in seen:
                    raise UpdateError("Архив обновления содержит повторяющийся путь.")
                seen.add(key)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode) or member.flag_bits & 0x1:
                    raise UpdateError("Архив обновления содержит неподдерживаемый файл.")
                extracted_size += member.file_size
                if extracted_size > MAX_EXTRACTED_BYTES:
                    raise UpdateError("Распакованный пакет обновления слишком большой.")
                validated.append((member, parts))

            destination.mkdir(parents=True)
            for member, parts in validated:
                target = destination.joinpath(*parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except UpdateError:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise UpdateError(f"Не удалось распаковать обновление: {exc}") from exc

    application = destination / "WireVeilChecker"
    required = (
        application / "WireVeilChecker.exe",
        application / "_internal" / "sing-box.exe",
        application / "_internal" / "mihomo.exe",
        application / "_internal" / "libcronet.dll",
        application / "_internal" / "scripts" / "inplace_update.ps1",
    )
    if not all(path.is_file() for path in required):
        shutil.rmtree(destination, ignore_errors=True)
        raise UpdateError("В portable-пакете отсутствуют обязательные файлы.")
    return application


def _bundled_update_helper() -> Path:
    if getattr(sys, "frozen", False):
        bundle_root = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    else:
        bundle_root = Path(__file__).resolve().parents[1]
    helper = bundle_root / "scripts" / "inplace_update.ps1"
    if not helper.is_file():
        raise UpdateError("В сборке отсутствует helper обновления.")
    return helper


def _requires_elevation(install_root: Path) -> bool:
    resolved_root = install_root.resolve()
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(variable)
        if not value:
            continue
        try:
            resolved_root.relative_to(Path(value).resolve())
        except ValueError:
            continue
        return True
    return not os.access(resolved_root, os.W_OK)


def _launch_update_script(
    script: Path,
    arguments: list[str],
    *,
    elevate: bool,
) -> None:
    if os.name != "nt":
        raise UpdateError("Автоматическое обновление поддерживается только в Windows.")
    powershell_arguments = [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        *arguments,
    ]
    try:
        if elevate:
            shell_execute = ctypes.windll.shell32.ShellExecuteW
            shell_execute.restype = ctypes.c_void_p
            result = shell_execute(
                None,
                "runas",
                "powershell.exe",
                subprocess.list2cmdline(powershell_arguments),
                None,
                0,
            )
            if int(result or 0) <= 32:
                raise UpdateError(
                    "Windows не разрешила заменить файлы приложения."
                )
            return
        subprocess.Popen(
            ["powershell.exe", *powershell_arguments],
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except UpdateError:
        raise
    except OSError as exc:
        raise UpdateError(f"Не удалось запустить helper обновления: {exc}") from exc


def launch_in_place_update(
    package: Path,
    *,
    current_version: str,
    new_version: str,
    executable: Path | None = None,
    parent_pid: int | None = None,
) -> Path:
    """Extract a verified package and start the post-exit file replacement helper."""
    version_tuple(current_version)
    version_tuple(new_version)
    if executable is None:
        if not getattr(sys, "frozen", False):
            raise UpdateError(
                "Автоматическая замена файлов доступна только в собранном приложении."
            )
        executable = Path(sys.executable)
    target_executable = executable.resolve()
    if target_executable.name.casefold() != "wireveilchecker.exe":
        raise UpdateError("Не удалось определить установленный WireVeil Checker.")
    install_root = target_executable.parent
    if not target_executable.is_file():
        raise UpdateError("Установленный WireVeil Checker не найден.")

    extraction_root = package.parent / "payload"
    payload_root = extract_update_package(package, extraction_root)
    helper = package.parent / "inplace_update.ps1"
    shutil.copy2(_bundled_update_helper(), helper)

    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise UpdateError("Windows не сообщила каталог LOCALAPPDATA.")
    backup_parent = Path(local_app_data) / "WireVeil Checker" / "update-backups"
    backup_parent.mkdir(parents=True, exist_ok=True)
    backup_root = backup_parent / (
        f"{current_version}-to-{new_version}-{uuid.uuid4().hex[:8]}"
    )
    result_path = package.parent / "update-result.json"
    helper_arguments = [
        "-InstallRoot",
        str(install_root),
        "-PayloadRoot",
        str(payload_root),
        "-BackupRoot",
        str(backup_root),
        "-ResultPath",
        str(result_path),
        "-ParentPid",
        str(parent_pid if parent_pid is not None else os.getpid()),
        "-NewVersion",
        new_version,
    ]
    elevate = _requires_elevation(install_root)
    if elevate:
        helper_arguments.append("-Elevated")
    _launch_update_script(helper, helper_arguments, elevate=elevate)
    return result_path


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
