"""Tests for portable/installed paths and Windows ACL helpers."""

import os
import tempfile
import unittest
from unittest import mock

from soc_log_anonymizer import paths
from soc_log_anonymizer.winsec import check_world_readable, restrict_sensitive_file
from soc_log_anonymizer.gui_logic import format_size_warning


class TestPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name

    def test_portable_marker_roundtrip(self):
        marker = paths.set_portable_mode(True, base=self.base)
        self.assertTrue(os.path.isfile(marker))
        self.assertTrue(paths.is_portable_mode(base=self.base))
        paths.set_portable_mode(False, base=self.base)
        self.assertFalse(os.path.isfile(marker))
        self.assertFalse(paths.is_portable_mode(base=self.base))

    def test_env_forces_portable(self):
        with mock.patch.dict(os.environ, {"SOC_ANON_PORTABLE": "1"}):
            self.assertTrue(paths.is_portable_mode(base=self.base))
        with mock.patch.dict(os.environ, {"SOC_ANON_PORTABLE": "0"}):
            paths.set_portable_mode(True, base=self.base)
            self.assertFalse(paths.is_portable_mode(base=self.base))

    def test_draft_path_under_cache(self):
        with mock.patch.dict(os.environ, {"SOC_ANON_PORTABLE": "1"}):
            with mock.patch.object(paths, "app_dir", return_value=self.base):
                draft = paths.draft_path_for_pid(12345, portable=True)
                self.assertIn("drafts", draft)
                self.assertTrue(draft.endswith("soc_log_anonymizer_draft_12345.txt"))
                self.assertTrue(os.path.isdir(os.path.dirname(draft)))


class TestWinsec(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "secret.txt")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("salt")

    def test_restrict_sensitive_file_posix_or_windows(self):
        warning = restrict_sensitive_file(self.path)
        # May return None (success) or a warning string; must not raise.
        self.assertTrue(warning is None or isinstance(warning, str))
        # After restrict, world-readable check should ideally be quiet on POSIX.
        if os.name == "posix":
            self.assertIsNone(check_world_readable(self.path))

    def test_check_missing_file(self):
        self.assertIsNone(check_world_readable(os.path.join(self.tmp.name, "missing")))
        self.assertIsNone(restrict_sensitive_file(os.path.join(self.tmp.name, "missing")))


class TestGuiLogicSizeWarning(unittest.TestCase):
    def test_format_size_warning_russian(self):
        text = format_size_warning(120.5, 50)
        self.assertIn("120.5", text)
        self.assertIn("50", text)


if __name__ == "__main__":
    unittest.main()
