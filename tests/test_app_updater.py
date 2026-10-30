import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import app_updater


class FakeResponse:
    def __init__(self, payload: bytes, *, content_length: bool = True) -> None:
        self.stream = io.BytesIO(payload)
        self.headers = (
            {"Content-Length": str(len(payload))} if content_length else {}
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)


def release_payload(version: str, *, assets: list[dict] | None = None) -> bytes:
    tag = f"checker-v{version}"
    return json.dumps(
        {
            "tag_name": tag,
            "html_url": f"https://github.com/{app_updater.REPOSITORY}/releases/tag/{tag}",
            "draft": False,
            "prerelease": False,
            "body": "Release notes",
            "assets": assets or [],
        }
    ).encode("utf-8")


def release_assets(version: str) -> list[dict]:
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
    ]


class VersionTests(unittest.TestCase):
    def test_versions_are_compared_numerically(self):
        self.assertTrue(app_updater.is_newer_version("1.10.0", "1.9.9"))
        self.assertFalse(app_updater.is_newer_version("1.7.0", "1.7.0"))

    def test_non_checker_version_is_rejected(self):
        with self.assertRaises(app_updater.UpdateError):
            app_updater.version_tuple("nightly")


class ReleaseCheckTests(unittest.TestCase):
    def test_current_release_needs_no_installer_assets(self):
        opener = mock.Mock(return_value=FakeResponse(release_payload("1.7.0")))
        self.assertIsNone(app_updater.check_for_update("1.7.0", opener=opener))

    def test_new_release_selects_installer_and_checksum(self):
        payload = release_payload("1.8.0", assets=release_assets("1.8.0"))
        release = app_updater.check_for_update(
            "1.7.0", opener=mock.Mock(return_value=FakeResponse(payload))
        )
        self.assertIsNotNone(release)
        assert release is not None
        self.assertEqual("1.8.0", release.version)
        self.assertTrue(release.installer_url.endswith(".exe"))
        self.assertTrue(release.checksum_url.endswith(".exe.sha256"))

    def test_release_cannot_redirect_asset_selection_to_another_host(self):
        assets = release_assets("1.8.0")
        assets[0]["browser_download_url"] = "https://example.com/update.exe"
        payload = release_payload("1.8.0", assets=assets)
        with self.assertRaises(app_updater.UpdateError):
            app_updater.check_for_update(
                "1.7.0", opener=mock.Mock(return_value=FakeResponse(payload))
            )


class DownloadTests(unittest.TestCase):
    def test_verified_installer_is_kept_for_launch(self):
        installer_bytes = b"verified installer bytes"
        checksum = hashlib.sha256(installer_bytes).hexdigest()
        version = "1.8.0"
        assets = release_assets(version)
        release = app_updater.ReleaseUpdate(
            version=version,
            tag=f"checker-v{version}",
            page_url=f"https://github.com/{app_updater.REPOSITORY}/releases/tag/checker-v{version}",
            notes="",
            installer_url=assets[0]["browser_download_url"],
            checksum_url=assets[1]["browser_download_url"],
        )

        def opener(request, **_kwargs):
            if request.full_url == release.checksum_url:
                line = f"{checksum} *{app_updater.INSTALLER_ASSET_NAME}\n"
                return FakeResponse(line.encode("ascii"))
            if request.full_url == release.installer_url:
                return FakeResponse(installer_bytes, content_length=False)
            raise AssertionError(request.full_url)

        with tempfile.TemporaryDirectory() as temporary:
            update_dir = Path(temporary) / "download"
            update_dir.mkdir()
            with mock.patch(
                "scripts.app_updater.tempfile.mkdtemp", return_value=str(update_dir)
            ):
                installer = app_updater.download_update(release, opener=opener)
            self.assertEqual(installer_bytes, installer.read_bytes())

    def test_checksum_mismatch_removes_download(self):
        version = "1.8.0"
        assets = release_assets(version)
        release = app_updater.ReleaseUpdate(
            version=version,
            tag=f"checker-v{version}",
            page_url="https://github.com/markKikhtenko/WireVeil/releases/tag/checker-v1.8.0",
            notes="",
            installer_url=assets[0]["browser_download_url"],
            checksum_url=assets[1]["browser_download_url"],
        )

        def opener(request, **_kwargs):
            if request.full_url == release.checksum_url:
                line = f"{'0' * 64} *{app_updater.INSTALLER_ASSET_NAME}\n"
                return FakeResponse(line.encode("ascii"))
            return FakeResponse(b"tampered")

        with tempfile.TemporaryDirectory() as temporary:
            update_dir = Path(temporary) / "download"
            update_dir.mkdir()
            with mock.patch(
                "scripts.app_updater.tempfile.mkdtemp", return_value=str(update_dir)
            ):
                with self.assertRaises(app_updater.UpdateError):
                    app_updater.download_update(release, opener=opener)
            self.assertFalse(update_dir.exists())


class InstallerDefinitionTests(unittest.TestCase):
    def test_installer_is_per_user_with_expected_default_path(self):
        root = Path(__file__).resolve().parents[1]
        definition = (root / "installer" / "WireVeilChecker.iss").read_text(
            encoding="utf-8"
        )
        self.assertIn(r"DefaultDirName={userpf}\WireVeil Checker", definition)
        self.assertIn("PrivilegesRequired=lowest", definition)
        self.assertIn("OutputBaseFilename=WireVeilChecker-Setup-x64", definition)
        self.assertIn("IsWireVeilUiUpdate", definition)

    def test_release_workflow_builds_and_publishes_installer_with_checksum(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "portable-checker.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("ISCC.exe", workflow)
        self.assertIn('"/DAppVersion=$env:WIREVEIL_VERSION"', workflow)
        self.assertGreaterEqual(
            workflow.count("WireVeilChecker-Setup-x64.exe"), 4
        )
        self.assertIn("WireVeilChecker-Setup-x64.exe.sha256", workflow)

    @mock.patch("scripts.app_updater.subprocess.Popen")
    def test_ui_update_flag_is_passed_to_installer(self, popen):
        with tempfile.TemporaryDirectory() as temporary:
            installer = Path(temporary) / app_updater.INSTALLER_ASSET_NAME
            installer.write_bytes(b"installer")
            app_updater.launch_installer(installer)
        arguments = popen.call_args.args[0]
        self.assertIn("/WIREVEILUPDATE=1", arguments)
        self.assertIn("/CLOSEAPPLICATIONS", arguments)


if __name__ == "__main__":
    unittest.main()
