"""Tests for Windows file drag-and-drop helpers (no live Tk window)."""

import os
import sys
import tempfile
import unittest
from unittest import mock

from soc_log_anonymizer.gui_dnd import (
    DRAG_QUERY_FILE_COUNT,
    enable_windows_file_drop,
    list_hdrop_paths,
)
from soc_log_anonymizer.gui_logic import expand_dropped_paths


class TestExpandDroppedPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name

    def test_files_and_folder(self):
        file_a = os.path.join(self.base, "a.log")
        nested = os.path.join(self.base, "nested")
        os.mkdir(nested)
        file_b = os.path.join(nested, "b.evtx")
        with open(file_a, "w", encoding="utf-8") as handle:
            handle.write("a")
        with open(file_b, "w", encoding="utf-8") as handle:
            handle.write("b")
        empty_dir = os.path.join(self.base, "empty")
        os.mkdir(empty_dir)
        result = expand_dropped_paths([file_a, nested, empty_dir, file_a])
        self.assertEqual(result, [file_a, file_b])

    def test_missing_ignored(self):
        self.assertEqual(expand_dropped_paths([os.path.join(self.base, "nope.log")]), [])


class TestHdropPaths(unittest.TestCase):
    def test_list_hdrop_paths(self):
        files = [r"C:\logs\a.log", r"C:\logs\b.evtx"]

        def fake_dqf(_hdrop, index, buf, _buflen):
            if index == DRAG_QUERY_FILE_COUNT:
                return len(files)
            path = files[index]
            if buf is None:
                return len(path)
            for i, char in enumerate(path):
                buf[i] = char
            buf[len(path)] = "\0"
            return len(path)

        self.assertEqual(list_hdrop_paths(fake_dqf, 1), files)


class TestEnableDropNoop(unittest.TestCase):
    def test_non_windows_is_false(self):
        if sys.platform == "win32":
            with mock.patch("soc_log_anonymizer.gui_dnd.sys.platform", "linux"):
                self.assertFalse(enable_windows_file_drop(object(), lambda _p: None))
        else:
            self.assertFalse(enable_windows_file_drop(object(), lambda _p: None))

    def test_missing_widget_is_false(self):
        with mock.patch("soc_log_anonymizer.gui_dnd.sys.platform", "win32"):
            self.assertFalse(enable_windows_file_drop(None, lambda _p: None))


if __name__ == "__main__":
    unittest.main()
