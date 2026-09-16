"""Tests for allowlist helpers and GUI HTML helpers."""

import unittest

from soc_log_anonymizer.gui_diff_html import build_diff_html, build_value_regex
from soc_log_anonymizer.gui_profiles import (
    ALLOWLIST_PRESETS,
    format_allowlist_lines,
    merge_lists,
    parse_allowlist_lines,
)


class TestAllowlistHelpers(unittest.TestCase):
    def test_parse_and_format(self):
        values = parse_allowlist_lines("8.8.8.8\nSYSTEM, admin\n8.8.8.8")
        self.assertEqual(values, ["8.8.8.8", "SYSTEM", "admin"])
        self.assertEqual(format_allowlist_lines(values).splitlines(), values)

    def test_merge_lists_case_insensitive(self):
        self.assertEqual(merge_lists(["Admin"], ["admin", "root"]), ["Admin", "root"])

    def test_presets_exist(self):
        self.assertIn("8.8.8.8", ALLOWLIST_PRESETS["dns_public"])
        self.assertIn("SYSTEM", ALLOWLIST_PRESETS["windows_builtin"])


class TestDiffHtmlHelpers(unittest.TestCase):
    def test_build_value_regex_longer_first(self):
        pattern = build_value_regex(["10.0.0.5", "10.0.0.50"])
        match = pattern.search("x 10.0.0.50 y")
        self.assertEqual(match.group(0), "10.0.0.50")

    def test_build_value_regex_skips_substring_inside_token(self):
        pattern = build_value_regex(["admin"])
        self.assertIsNone(pattern.search("AccountName=administrator"))
        self.assertEqual(pattern.search("user=admin").group(0), "admin")

    def test_build_diff_html_empty_change(self):
        doc = build_diff_html("same", "same", {}, {}, org_name="bank")
        self.assertIn("Изменений нет", doc)
        self.assertIn("bank", doc)


if __name__ == "__main__":
    unittest.main()
