import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import wireveil_paths


class WireVeilPathTests(unittest.TestCase):
    def test_source_and_portable_builds_keep_data_beside_application(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(wireveil_paths, "application_root", return_value=root):
                with mock.patch.object(wireveil_paths, "is_program_files_install", return_value=False):
                    self.assertEqual(
                        root / "settings.json",
                        wireveil_paths.user_data_file("settings.json"),
                    )

    def test_program_files_install_uses_local_app_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            local_app_data = Path(temporary) / "Local"
            application = Path(temporary) / "Program Files" / "WireVeil Checker"
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}):
                with mock.patch.object(wireveil_paths, "application_root", return_value=application):
                    with mock.patch.object(wireveil_paths, "is_program_files_install", return_value=True):
                        self.assertEqual(
                            local_app_data / "WireVeil Checker" / "settings.json",
                            wireveil_paths.user_data_file("settings.json"),
                        )

    def test_program_files_install_migrates_legacy_1_8_0_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            local_app_data = root / "Local"
            application = root / "Program Files" / "WireVeil Checker"
            legacy = local_app_data / "Programs" / "WireVeil Checker" / "settings.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("saved", encoding="utf-8")
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}):
                with mock.patch.object(wireveil_paths, "application_root", return_value=application):
                    with mock.patch.object(wireveil_paths, "is_program_files_install", return_value=True):
                        target = wireveil_paths.user_data_file("settings.json")
            self.assertEqual("saved", target.read_text(encoding="utf-8"))
            self.assertTrue(legacy.exists())


if __name__ == "__main__":
    unittest.main()
