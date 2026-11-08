import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts import app_updater


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.stream = io.BytesIO(payload)
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)


def portable_assets(version: str) -> list[dict[str, str]]:
    prefix = f"{app_updater.RELEASE_DOWNLOAD_PREFIX}checker-v{version}/"
    return [
        {
            "name": app_updater.INSTALLER_ASSET_NAME,
            "browser_download_url": prefix + app_updater.INSTALLER_ASSET_NAME,
        },
        {
            "name": app_updater.CHECKSUM_ASSET_NAME,
            "browser_download_url": prefix + app_updater.CHECKSUM_ASSET_NAME,
        },
        {
            "name": app_updater.PORTABLE_ASSET_NAME,
            "browser_download_url": prefix + app_updater.PORTABLE_ASSET_NAME,
        },
        {
            "name": app_updater.PORTABLE_CHECKSUM_ASSET_NAME,
            "browser_download_url": prefix + app_updater.PORTABLE_CHECKSUM_ASSET_NAME,
        },
    ]


def release_payload(version: str) -> bytes:
    tag = f"checker-v{version}"
    return json.dumps(
        {
            "tag_name": tag,
            "html_url": f"https://github.com/{app_updater.REPOSITORY}/releases/tag/{tag}",
            "draft": False,
            "prerelease": False,
            "body": "Release notes",
            "assets": portable_assets(version),
        }
    ).encode("utf-8")


def portable_zip_bytes(*, traversal: bool = False) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("WireVeilChecker/WireVeilChecker.exe", b"checker")
        archive.writestr("WireVeilChecker/_internal/sing-box.exe", b"sing-box")
        archive.writestr("WireVeilChecker/_internal/mihomo.exe", b"mihomo")
        archive.writestr("WireVeilChecker/_internal/libcronet.dll", b"cronet")
        archive.writestr(
            "WireVeilChecker/_internal/scripts/inplace_update.ps1", b"helper"
        )
        if traversal:
            archive.writestr("WireVeilChecker/../escape.txt", b"escape")
    return stream.getvalue()


class PortableReleaseTests(unittest.TestCase):
    def test_release_prefers_portable_package_over_installer(self):
        release = app_updater.check_for_update(
            "1.9.24",
            opener=mock.Mock(return_value=FakeResponse(release_payload("1.9.25"))),
        )

        self.assertIsNotNone(release)
        assert release is not None
        self.assertEqual(app_updater.PORTABLE_ASSET_NAME, release.asset_name)
        self.assertTrue(release.installer_url.endswith(".zip"))
        self.assertTrue(release.checksum_url.endswith(".zip.sha256"))

    def test_portable_download_is_verified_by_its_own_checksum(self):
        package_bytes = portable_zip_bytes()
        checksum = hashlib.sha256(package_bytes).hexdigest()
        version = "1.9.25"
        assets = portable_assets(version)
        release = app_updater.ReleaseUpdate(
            version=version,
            tag=f"checker-v{version}",
            page_url=f"https://github.com/{app_updater.REPOSITORY}/releases/tag/checker-v{version}",
            notes="",
            installer_url=assets[2]["browser_download_url"],
            checksum_url=assets[3]["browser_download_url"],
            asset_name=app_updater.PORTABLE_ASSET_NAME,
        )

        def opener(request, **_kwargs):
            if request.full_url == release.checksum_url:
                line = f"{checksum} *{app_updater.PORTABLE_ASSET_NAME}\n"
                return FakeResponse(line.encode("ascii"))
            if request.full_url == release.installer_url:
                return FakeResponse(package_bytes)
            raise AssertionError(request.full_url)

        with tempfile.TemporaryDirectory() as temporary:
            update_dir = Path(temporary) / "download"
            update_dir.mkdir()
            with mock.patch(
                "scripts.app_updater.tempfile.mkdtemp", return_value=str(update_dir)
            ):
                package = app_updater.download_update(release, opener=opener)
            self.assertEqual(app_updater.PORTABLE_ASSET_NAME, package.name)
            self.assertEqual(package_bytes, package.read_bytes())


class ArchiveSafetyTests(unittest.TestCase):
    def test_verified_archive_extracts_required_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / app_updater.PORTABLE_ASSET_NAME
            package.write_bytes(portable_zip_bytes())

            payload = app_updater.extract_update_package(package, root / "payload")

            self.assertTrue((payload / "WireVeilChecker.exe").is_file())
            self.assertTrue((payload / "_internal" / "mihomo.exe").is_file())

    def test_zip_slip_path_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / app_updater.PORTABLE_ASSET_NAME
            package.write_bytes(portable_zip_bytes(traversal=True))

            with self.assertRaises(app_updater.UpdateError):
                app_updater.extract_update_package(package, root / "payload")

            self.assertFalse((root / "escape.txt").exists())


class HelperLaunchTests(unittest.TestCase):
    def test_in_place_update_prepares_payload_backup_and_elevated_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / app_updater.PORTABLE_ASSET_NAME
            package.write_bytes(portable_zip_bytes())
            install_root = root / "Program Files" / "WireVeil Checker"
            install_root.mkdir(parents=True)
            executable = install_root / "WireVeilChecker.exe"
            executable.write_bytes(b"old checker")
            local_app_data = root / "LocalAppData"

            with (
                mock.patch.dict(
                    "os.environ", {"LOCALAPPDATA": str(local_app_data)}, clear=False
                ),
                mock.patch(
                    "scripts.app_updater._requires_elevation", return_value=True
                ),
                mock.patch("scripts.app_updater._launch_update_script") as launcher,
            ):
                result = app_updater.launch_in_place_update(
                    package,
                    current_version="1.9.24",
                    new_version="1.9.25",
                    executable=executable,
                    parent_pid=4321,
                )

            self.assertEqual(root / "update-result.json", result)
            script, arguments = launcher.call_args.args
            self.assertTrue(script.is_file())
            self.assertIn("-InstallRoot", arguments)
            self.assertIn(str(install_root.resolve()), arguments)
            self.assertIn("-PayloadRoot", arguments)
            self.assertIn("-Elevated", arguments)
            self.assertTrue(launcher.call_args.kwargs["elevate"])

    def test_release_workflow_bundles_the_in_place_helper(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "portable-checker.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('--add-data "scripts\\inplace_update.ps1;scripts"', workflow)

    @unittest.skipUnless(os.name == "nt", "PowerShell helper is Windows-only")
    def test_powershell_helper_replaces_files_and_preserves_uninstaller(self):
        root = Path(__file__).resolve().parents[1]
        script = root / "scripts" / "inplace_update.ps1"
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            backup_root = temporary_root / "backup"
            install_root = temporary_root / "install"
            payload_root = temporary_root / "payload"
            (install_root / "_internal").mkdir(parents=True)
            (payload_root / "_internal").mkdir(parents=True)
            (install_root / "WireVeilChecker.exe").write_bytes(b"old checker")
            (install_root / "_internal" / "old.dll").write_bytes(b"old")
            (install_root / "unins000.exe").write_bytes(b"uninstaller")
            (payload_root / "WireVeilChecker.exe").write_bytes(b"new checker")
            (payload_root / "_internal" / "sing-box.exe").write_bytes(b"sing")
            (payload_root / "_internal" / "mihomo.exe").write_bytes(b"mihomo")
            (payload_root / "_internal" / "libcronet.dll").write_bytes(b"cronet")
            (payload_root / "_internal" / "scripts").mkdir()
            (payload_root / "_internal" / "scripts" / "inplace_update.ps1").write_bytes(
                b"helper"
            )
            result_path = temporary_root / "result.json"

            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                    "-InstallRoot",
                    str(install_root),
                    "-PayloadRoot",
                    str(payload_root),
                    "-BackupRoot",
                    str(backup_root),
                    "-ResultPath",
                    str(result_path),
                    "-ParentPid",
                    "2147483646",
                    "-NewVersion",
                    "9.9.9",
                    "-NoRestart",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            result_text = (
                result_path.read_text(encoding="utf-8-sig")
                if result_path.exists()
                else "result file missing"
            )
            self.assertEqual(
                0,
                completed.returncode,
                f"stdout={completed.stdout}\nstderr={completed.stderr}\nresult={result_text}",
            )
            result = json.loads(result_path.read_text(encoding="utf-8-sig"))
            self.assertEqual("ok", result["Status"])
            self.assertEqual(
                b"new checker", (install_root / "WireVeilChecker.exe").read_bytes()
            )
            self.assertEqual(
                b"old checker", (backup_root / "WireVeilChecker.exe").read_bytes()
            )
            self.assertEqual(
                b"uninstaller", (install_root / "unins000.exe").read_bytes()
            )
            self.assertFalse((install_root / "_internal" / "old.dll").exists())


if __name__ == "__main__":
    unittest.main()
