"""
Тесты для soc_log_anonymizer.gui_logic — чистой логики GUI без
зависимости от tkinter. Эти тесты выполняются даже в окружениях, где
tkinter не установлен (в отличие от импорта soc_log_anonymizer.gui).
"""

import unittest

from soc_log_anonymizer.gui_logic import (
    compute_progress_pct,
    find_context_snippet,
    format_result_status,
    format_size_warning,
    salt_entropy_warning,
    status_style_name,
)


class TestSaltEntropyWarning(unittest.TestCase):
    def test_short_salt_warns(self):
        self.assertIsNotNone(salt_entropy_warning("short"))

    def test_low_diversity_salt_warns(self):
        self.assertIsNotNone(salt_entropy_warning("a" * 32))

    def test_good_salt_no_warning(self):
        self.assertIsNone(salt_entropy_warning("f3a9c8e1b2d4567890abcdef12345678"))


class TestFormatResultStatus(unittest.TestCase):
    def test_safe_result(self):
        text, kind = format_result_status(True, [])
        self.assertEqual(kind, "Success")
        self.assertIn("Безопасно", text)

    def test_unsafe_single_issue(self):
        text, kind = format_result_status(False, ["Обнаружен незамаскированный IP"])
        self.assertEqual(kind, "Danger")
        self.assertIn("Обнаружен незамаскированный IP", text)
        self.assertNotIn("+", text)

    def test_unsafe_multiple_issues_shows_count(self):
        text, kind = format_result_status(False, ["issue1", "issue2", "issue3"])
        self.assertEqual(kind, "Danger")
        self.assertIn("+2", text)

    def test_unsafe_empty_issues_list(self):
        text, kind = format_result_status(False, [])
        self.assertEqual(kind, "Danger")
        self.assertIn("Неизвестный риск", text)


class TestComputeProgressPct(unittest.TestCase):
    def test_normal_progress(self):
        self.assertEqual(compute_progress_pct(50, 100), 50)

    def test_zero_total_returns_100(self):
        self.assertEqual(compute_progress_pct(0, 0), 100)

    def test_negative_total_returns_100(self):
        self.assertEqual(compute_progress_pct(5, -1), 100)

    def test_clamped_to_100(self):
        self.assertEqual(compute_progress_pct(150, 100), 100)

    def test_zero_done(self):
        self.assertEqual(compute_progress_pct(0, 100), 0)


class TestStatusStyleName(unittest.TestCase):
    def test_capitalizes_kind(self):
        self.assertEqual(status_style_name("success"), "StatusSuccess.TLabel")
        self.assertEqual(status_style_name("DANGER"), "StatusDanger.TLabel")
        self.assertEqual(status_style_name("Idle"), "StatusIdle.TLabel")


class TestFormatSizeWarning(unittest.TestCase):
    def test_contains_size_and_limit(self):
        msg = format_size_warning(750.5, 500)
        self.assertIn("750.5", msg)
        self.assertIn("500", msg)


class TestFindContextSnippet(unittest.TestCase):
    def test_finds_value_with_surrounding_context(self):
        text = "some prefix text src=192.168.1.10 more text after here"
        snippet = find_context_snippet(text, "192.168.1.10", radius=10)
        self.assertIn("192.168.1.10", snippet)

    def test_value_not_found(self):
        snippet = find_context_snippet("some text", "nonexistent")
        self.assertIn("не найден", snippet)

    def test_empty_value(self):
        snippet = find_context_snippet("some text", "")
        self.assertIn("пустое", snippet)

    def test_ellipsis_added_when_truncated(self):
        text = "x" * 100 + "TARGET" + "y" * 100
        snippet = find_context_snippet(text, "TARGET", radius=10)
        self.assertTrue(snippet.startswith("…"))
        self.assertTrue(snippet.endswith("…"))

    def test_no_ellipsis_when_value_at_start(self):
        text = "TARGET" + "y" * 10
        snippet = find_context_snippet(text, "TARGET", radius=10)
        self.assertFalse(snippet.startswith("…"))


if __name__ == "__main__":
    unittest.main()
