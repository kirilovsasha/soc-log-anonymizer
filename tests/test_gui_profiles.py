"""Tests for source profiles and allowlist helpers."""

import unittest

from soc_log_anonymizer.config import AnonymizerConfig
from soc_log_anonymizer.gui_diff_html import build_diff_html, build_value_regex
from soc_log_anonymizer.gui_profiles import (
    ALLOWLIST_PRESETS,
    apply_source_profile,
    format_allowlist_lines,
    merge_lists,
    parse_allowlist_lines,
    profile_choices,
)


class TestProfiles(unittest.TestCase):
    def test_profile_choices_cover_known_ids(self):
        ids = {pid for pid, _ in profile_choices()}
        self.assertIn("default", ids)
        self.assertIn("windows", ids)
        self.assertIn("cisco", ids)

    def test_windows_profile_adds_builtin_allowlist(self):
        cfg = AnonymizerConfig(pbkdf2_iterations=100, allowlist=["8.8.8.8"])
        apply_source_profile(cfg, "windows")
        self.assertIn("8.8.8.8", cfg.allowlist)
        self.assertIn("SYSTEM", cfg.allowlist)
        self.assertIn("subjectaccountname", [x.lower() for x in cfg.user_field_names])

    def test_default_profile_resets_fields(self):
        cfg = AnonymizerConfig(pbkdf2_iterations=100, user_field_names=["only_custom"])
        apply_source_profile(cfg, "default")
        self.assertIn("user", cfg.user_field_names)
        self.assertNotEqual(cfg.user_field_names, ["only_custom"])

    def test_unknown_profile_raises(self):
        with self.assertRaises(KeyError):
            apply_source_profile(AnonymizerConfig(pbkdf2_iterations=100), "nope")


class TestAllowlistHelpers(unittest.TestCase):
    def test_parse_and_format(self):
        values = parse_allowlist_lines("8.8.8.8\nSYSTEM, admin\n8.8.8.8")
        self.assertEqual(values, ["8.8.8.8", "SYSTEM", "admin"])
        self.assertEqual(format_allowlist_lines(values).splitlines(), values)

    def test_merge_lists_case_insensitive(self):
        self.assertEqual(merge_lists(["Admin"], ["admin", "root"]), ["Admin", "root"])

    def test_presets_exist(self):
        self.assertIn("8.8.8.8", ALLOWLIST_PRESETS["dns_public"])


class TestDiffHtmlHelpers(unittest.TestCase):
    def test_build_value_regex_longer_first(self):
        pattern = build_value_regex(["10.0.0.5", "10.0.0.50"])
        match = pattern.search("x 10.0.0.50 y")
        self.assertEqual(match.group(0), "10.0.0.50")

    def test_build_diff_html_empty_change(self):
        doc = build_diff_html("same", "same", {}, {}, org_name="bank")
        self.assertIn("Изменений нет", doc)
        self.assertIn("bank", doc)


if __name__ == "__main__":
    unittest.main()
