"""Application and writable user-data paths for WireVeil Checker."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


APP_DATA_DIRECTORY = "WireVeil Checker"


def application_root() -> Path:
    """Return the directory containing the executable or source checkout."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
    except (OSError, ValueError):
        return False
    return True


def is_program_files_install() -> bool:
    """Return whether the frozen executable is installed under Program Files."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return False
    root = application_root()
    candidates = {
        value
        for name in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)")
        if (value := os.environ.get(name))
    }
    return any(_is_within(root, Path(candidate)) for candidate in candidates)


def user_data_root() -> Path:
    """Return a writable data directory while keeping portable builds portable."""
    root = application_root()
    if not is_program_files_install():
        return root
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return root
    target = Path(local_app_data) / APP_DATA_DIRECTORY
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        return root
    return target


def user_data_file(filename: str) -> Path:
    """Return a writable file path and migrate data from the 1.8.0 install."""
    target = user_data_root() / filename
    if target.exists() or target.parent == application_root():
        return target

    local_app_data = os.environ.get("LOCALAPPDATA")
    legacy_roots = [application_root()]
    if local_app_data:
        legacy_roots.append(
            Path(local_app_data) / "Programs" / APP_DATA_DIRECTORY
        )
    for legacy_root in legacy_roots:
        legacy = legacy_root / filename
        if not legacy.is_file() or legacy == target:
            continue
        try:
            shutil.copy2(legacy, target)
        except OSError:
            continue
        break
    return target
