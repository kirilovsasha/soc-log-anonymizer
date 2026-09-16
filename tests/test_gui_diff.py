"""Тесты для value-level diff и таблицы хоткеев.

Как и остальной test_gui_logic.py — без tkinter, работают в headless CI.
Положить в tests/ рядом с test_gui_logic.py.
"""
import unittest

from soc_log_anonymizer.gui_logic import (
    HOTKEYS,
    accelerator_to_sequence,
    changed_value_spans,
    inline_diff_spans,
    merge_spans,
    normalize_keysym,
    typed_value_spans,
)


class ChangedValueSpansTest(unittest.TestCase):
    def test_marks_only_the_value_not_the_line(self):
        line = "Oct 12 10:22:01 srv1 sshd[1]: Accepted password for admin from 10.0.0.5"
        spans = changed_value_spans(line, ["admin", "10.0.0.5"])
        self.assertEqual([line[a:b] for a, b in spans], ["admin", "10.0.0.5"])
        # Ключевой инвариант: суммарная длина подсветки << длины строки.
        self.assertLess(sum(b - a for a, b in spans), len(line) // 3)

    def test_longer_value_wins_over_its_own_prefix(self):
        text = "10.0.0.5 and 10.0.0.50"
        spans = changed_value_spans(text, ["10.0.0.5", "10.0.0.50"])
        self.assertEqual([text[a:b] for a, b in spans], ["10.0.0.5", "10.0.0.50"])

    def test_short_value_does_not_highlight_inside_longer_token(self):
        # Allowlist «administrator» остаётся в тексте; «admin» из mapping
        # не должен подсвечивать его префикс как «замаскированное».
        text = "AccountName=administrator user=admin"
        spans = changed_value_spans(text, ["admin"])
        self.assertEqual([text[a:b] for a, b in spans], ["admin"])
        self.assertNotIn("administrator", "".join(text[a:b] for a, b in spans))

    def test_ip_prefix_alone_does_not_match_longer_ip(self):
        text = "src=10.0.0.50"
        spans = changed_value_spans(text, ["10.0.0.5"])
        self.assertEqual(spans, [])

    def test_empty_inputs(self):
        self.assertEqual(changed_value_spans("", ["x"]), [])
        self.assertEqual(changed_value_spans("text", []), [])
        self.assertEqual(changed_value_spans("text", [""]), [])

    def test_regex_metacharacters_in_values_are_literal(self):
        text = "path=C:\\Users\\jdoe\\AppData"
        spans = changed_value_spans(text, ["C:\\Users\\jdoe"])
        self.assertEqual([text[a:b] for a, b in spans], ["C:\\Users\\jdoe"])

    def test_both_panes_produce_aligned_span_counts(self):
        original = "user=admin ip=10.0.0.5\nuser=admin\n"
        cleaned = original.replace("admin", "[USER_aa11]").replace("10.0.0.5", "[IP_bb22]")
        left = changed_value_spans(original, ["admin", "10.0.0.5"])
        right = changed_value_spans(cleaned, ["[USER_aa11]", "[IP_bb22]"])
        self.assertEqual(len(left), len(right))


class TypedValueSpansTest(unittest.TestCase):
    def test_each_span_carries_its_type(self):
        text = "user=admin from 10.0.0.5 password=hunter2"
        spans = typed_value_spans(text, {
            "admin": "USER", "10.0.0.5": "IP", "hunter2": "SECRET",
        })
        self.assertEqual([(text[a:b], t) for a, b, t in spans],
                         [("admin", "USER"), ("10.0.0.5", "IP"), ("hunter2", "SECRET")])

    def test_unknown_value_falls_back_to_default_type(self):
        spans = typed_value_spans("x=1", {"1": "VALUE"})
        self.assertEqual(spans[0][2], "VALUE")

    def test_same_value_gets_same_type_everywhere(self):
        text = "10.0.0.5 ... 10.0.0.5"
        types = {t for _, _, t in typed_value_spans(text, {"10.0.0.5": "IP"})}
        self.assertEqual(types, {"IP"})

    def test_empty_inputs(self):
        self.assertEqual(typed_value_spans("", {"a": "IP"}), [])
        self.assertEqual(typed_value_spans("text", {}), [])


class InlineDiffSpansTest(unittest.TestCase):
    def test_only_changed_token_is_reported(self):
        left, right = inline_diff_spans("user=admin ok", "user=[USER_1] ok")
        self.assertEqual([("user=admin ok")[a:b] for a, b in left], ["admin"])
        self.assertEqual([("user=[USER_1] ok")[a:b] for a, b in right], ["[USER_1]"])

    def test_identical_texts_have_no_spans(self):
        self.assertEqual(inline_diff_spans("same\ntext", "same\ntext"), ([], []))

    def test_spans_never_start_or_end_on_whitespace(self):
        original = "a b c\nd e f\n"
        cleaned = "a X c\nd e f\n"
        left, right = inline_diff_spans(original, cleaned)
        for text, spans in ((original, left), (cleaned, right)):
            for start, end in spans:
                self.assertFalse(text[start].isspace())
                self.assertFalse(text[end - 1].isspace())

    def test_falls_back_to_line_level_on_huge_input(self):
        original = "x y\n" * 50
        cleaned = original.replace("x", "z", 1)
        left, _ = inline_diff_spans(original, cleaned, max_tokens=4)
        self.assertTrue(left)


class MergeSpansTest(unittest.TestCase):
    def test_overlapping_spans_collapse(self):
        self.assertEqual(merge_spans([(0, 5), (3, 8), (20, 25)]), [(0, 8), (20, 25)])

    def test_gap_parameter(self):
        self.assertEqual(merge_spans([(0, 5), (6, 9)], gap=1), [(0, 9)])
        self.assertEqual(merge_spans([(0, 5), (6, 9)], gap=0), [(0, 5), (6, 9)])


class HotkeyTableTest(unittest.TestCase):
    def test_accelerators_are_unique(self):
        accelerators = [acc for acc, _, _ in HOTKEYS]
        self.assertEqual(len(accelerators), len(set(accelerators)))

    def test_sequence_conversion(self):
        self.assertEqual(accelerator_to_sequence("Ctrl+O"), "<Control-o>")
        self.assertEqual(accelerator_to_sequence("Ctrl+Shift+L"), "<Control-Shift-L>")
        self.assertEqual(accelerator_to_sequence("Ctrl+Enter"), "<Control-Return>")
        self.assertEqual(accelerator_to_sequence("Escape"), "<Escape>")

    def test_every_entry_converts_and_is_described(self):
        for accelerator, method, description in HOTKEYS:
            self.assertTrue(accelerator_to_sequence(accelerator).startswith("<"))
            self.assertTrue(method)
            self.assertTrue(description)

    def test_operation_undo_is_not_on_plain_ctrl_z(self):
        # Ctrl+Z принадлежит встроенному undo tk.Text (виджет создан с
        # undo=True) — откат операции анонимизации живёт на Ctrl+Alt+Z.
        accelerators = {acc for acc, _, _ in HOTKEYS}
        self.assertNotIn("Ctrl+Z", accelerators)
        self.assertIn("Ctrl+Alt+Z", accelerators)

    def test_cyrillic_keysym_maps_to_same_physical_key(self):
        self.assertEqual(normalize_keysym("Cyrillic_de"), "l")     # Ctrl+L
        self.assertEqual(normalize_keysym("Cyrillic_ya"), "z")     # Ctrl+Z
        self.assertEqual(normalize_keysym("Cyrillic_shcha"), "o")  # Ctrl+O
        self.assertEqual(normalize_keysym("Cyrillic_yeru"), "s")   # Ctrl+S

    def test_latin_keysym_passes_through(self):
        self.assertEqual(normalize_keysym("o"), "o")
        self.assertEqual(normalize_keysym("F3"), "F3")


class GuiMethodsExistTest(unittest.TestCase):
    """Таблица хоткеев ссылается на методы по имени — опечатка обнаружится
    только в рантайме, если её не проверить здесь. Тест пропускается, если
    tkinter в окружении нет (headless-раннер)."""

    def test_methods_exist_on_gui_class(self):
        try:
            from soc_log_anonymizer.gui import AnonymizerGUI
        except ImportError:
            self.skipTest("tkinter недоступен")
        for _, method, _ in HOTKEYS:
            self.assertTrue(hasattr(AnonymizerGUI, method), f"нет метода {method}")


if __name__ == "__main__":
    unittest.main()
