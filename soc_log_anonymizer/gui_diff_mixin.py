"""Mixin providing GuiDiffMixin methods for AnonymizerGUI."""
from __future__ import annotations

import logging
import os
import tempfile
import tkinter as tk
import webbrowser
from tkinter import messagebox
from typing import Dict

from .gui_diff_html import build_diff_html as _build_diff_html_doc
from .gui_logic import inline_diff_spans, typed_value_spans
from .gui_theme import HIGHLIGHT_TAG_NAMES
from .gui_theme import pseudonym_type as _pseudonym_type

logger = logging.getLogger("soc_log_anonymizer")


class GuiDiffMixin:
    # Пакетная отрисовка тегов через root.after — иначе тысячи tag_add
    # подряд блокируют event loop на больших логах.
    _HIGHLIGHT_BATCH_SIZE = 300
    _HIGHLIGHT_RENDER_LIMIT = 5_000

    def _pane_text(self, widget: tk.Text) -> str:
        """Ровно то, что лежит в виджете, без .strip() и без подстановки
        полного (неусечённого) текста вместо показанного.

        Именно этим отличается от _text_value: смещения символов,
        посчитанные по этому тексту, обязаны попадать в те же позиции
        виджета. _text_value для усечённого Input возвращает ПОЛНЫЙ текст,
        а .strip() сдвигает все смещения на длину ведущих пробелов — и
        подсветка уезжает относительно содержимого."""
        if getattr(widget, "_is_placeholder", False):
            return ""
        return widget.get("1.0", "end-1c")


    def _refresh_diff_highlighting(self) -> None:
        """Пересчитывает изменения и подсвечивает ТОЛЬКО заменённые
        значения, цветом по ТИПУ данных.

        Раньше поверх типовой подсветки вешался ещё и тег diff_changed на
        диапазон строки целиком (по номерам строк из changed_line_numbers)
        — на реальном логе меняется почти каждая строка, поэтому
        подсвечивался весь текст одним жёлтым, а типовые цвета под ним не
        были видны вообще. Никакого отдельного "цвета diff'а" больше нет:
        сам факт подсветки и есть diff, а цвет несёт тип данных.

        Diff строится по фактической таблице соответствия — мы точно
        знаем, какие значения заменены, и находим их вхождения напрямую,
        без эвристики "похожести" строк. Пословный difflib остаётся
        фолбэком на случай, когда таблицы нет (например, текст в Output
        отредактировали вручную); типа данных там взяться неоткуда,
        поэтому такие диапазоны красятся нейтральным hl_VALUE."""
        original = self._pane_text(self.txt_input)
        cleaned = self._pane_text(self.txt_output)

        mapping = getattr(self.anonymizer, "mapping_table", None) or {}
        reverse = getattr(self.anonymizer, "reverse_mapping", None) or {}
        if mapping and reverse:
            input_types = {value: _pseudonym_type(pseudo)
                           for value, pseudo in mapping.items() if value}
            output_types = {pseudo: _pseudonym_type(pseudo) for pseudo in reverse}
            input_spans = typed_value_spans(original, input_types)
            output_spans = typed_value_spans(cleaned, output_types)
        elif original and cleaned:
            left, right = inline_diff_spans(original, cleaned)
            input_spans = [(a, b, "VALUE") for a, b in left]
            output_spans = [(a, b, "VALUE") for a, b in right]
        else:
            input_spans, output_spans = [], []

        self._diff_input_spans = [(a, b) for a, b, _ in input_spans]
        self._diff_output_spans = [(a, b) for a, b, _ in output_spans]
        self._diff_cursor = -1

        # Легенда строится по тому, что реально подсвечено в Output
        # (в Input те же типы, но Output — источник истины о типе: он
        # разбирается из самого псевдонима).
        counts: Dict[str, int] = {}
        for _, _, value_type in (output_spans or input_spans):
            counts[value_type] = counts.get(value_type, 0) + 1
        self._legend_counts = counts
        self._render_type_legend()

        # Токен прохода: пакетная отрисовка через root.after может пережить
        # следующий вызов (пользователь нажал "Анонимизировать" второй раз,
        # пока красился предыдущий результат) — устаревший проход обязан
        # прекратиться, иначе он дорисует теги от уже неактуального diff'а.
        self._diff_render_token += 1
        token = self._diff_render_token

        for widget in (self.txt_input, self.txt_output):
            for tag in HIGHLIGHT_TAG_NAMES:
                widget.tag_remove(tag, "1.0", tk.END)
            widget.tag_remove("diff_current", "1.0", tk.END)
            # Метка текущего изменения при навигации должна быть видна
            # поверх типовой подсветки, а выделение мышью — поверх всего.
            widget.tag_raise("diff_current")
            widget.tag_raise("sel")

        pending = [
            (self.txt_input, iter(input_spans[:self._HIGHLIGHT_RENDER_LIMIT])),
            (self.txt_output, iter(output_spans[:self._HIGHLIGHT_RENDER_LIMIT])),
        ]
        self._render_spans_step(pending, token)


    def _render_spans_step(self, pending, token: int) -> None:
        if token != self._diff_render_token:
            return  # пришёл новый diff — этот проход устарел
        drawn = 0
        while pending and drawn < self._HIGHLIGHT_BATCH_SIZE:
            widget, spans_iter = pending[0]
            try:
                start, end, value_type = next(spans_iter)
            except StopIteration:
                pending.pop(0)
                continue
            widget.tag_add(f"hl_{value_type}",
                           f"1.0 + {start} chars",
                           f"1.0 + {end} chars")
            drawn += 1
        if pending:
            # Продолжение отдельным проходом event loop, а не рекурсивным
            # вызовом внутри текущего, чтобы GUI успевал перерисовываться
            # и реагировать на ввод между пачками.
            self.root.after(0, self._render_spans_step, pending, token)


    def _clear_diff_state(self) -> None:
        """Сбрасывает диапазоны, курсор и все теги подсветки — вызывается
        при очистке, чтобы навигация не прыгала по позициям уже удалённого
        текста, а подсветка не оставалась поверх нового."""
        self._diff_input_spans = []
        self._diff_output_spans = []
        self._diff_cursor = -1
        self._diff_render_token += 1
        self._legend_counts = {}
        self._render_type_legend()
        for widget in (self.txt_input, self.txt_output):
            for tag in HIGHLIGHT_TAG_NAMES:
                widget.tag_remove(tag, "1.0", tk.END)
            widget.tag_remove("diff_current", "1.0", tk.END)


    def _next_diff(self) -> None:
        self._navigate_diff(1)


    def _previous_diff(self) -> None:
        self._navigate_diff(-1)


    def _navigate_diff(self, direction: int = 1) -> None:
        """Переход по конкретным заменённым значениям в обеих панелях."""
        total = max(len(self._diff_input_spans), len(self._diff_output_spans))
        if total == 0:
            self._refresh_diff_highlighting()
            total = max(len(self._diff_input_spans), len(self._diff_output_spans))
        if total == 0:
            self._set_status("Изменений не найдено", "Muted")
            return
        self._diff_cursor = (self._diff_cursor + (1 if direction >= 0 else -1)) % total
        for widget in (self.txt_input, self.txt_output):
            widget.tag_remove("diff_current", "1.0", tk.END)
        for widget, spans in ((self.txt_input, self._diff_input_spans),
                              (self.txt_output, self._diff_output_spans)):
            if not spans:
                continue
            start, end = spans[min(self._diff_cursor, len(spans) - 1)]
            start_index = f"1.0 + {start} chars"
            widget.tag_add("diff_current", start_index, f"1.0 + {end} chars")
            widget.see(start_index)
        self._set_status(f"Изменение {self._diff_cursor + 1}/{total}", "Info")


    def _focus_log_search(self):
        self.log_search_entry.focus_set()
        self.log_search_entry.selection_range(0, tk.END)


    def _find_in_logs(self, direction: int = 1):
        query = self.log_search_entry.get()
        if not query:
            self._focus_log_search()
            return
        widget = self.txt_input if self.log_search_target.get() == "Input" else self.txt_output
        widget.tag_config("log_search_match", background="#FDE68A", foreground="#111827")
        widget.tag_remove("log_search_match", "1.0", tk.END)
        start = widget.index(tk.INSERT)
        if direction < 0:
            match = widget.search(query, start, stopindex="1.0", backwards=True)
            if not match:
                match = widget.search(query, tk.END, stopindex="1.0", backwards=True)
        else:
            match = widget.search(query, start, stopindex=tk.END)
            if not match:
                match = widget.search(query, "1.0", stopindex=tk.END)
        if not match:
            self._set_status("Совпадение не найдено", "Warning")
            return
        end = f"{match}+{len(query)}c"
        widget.tag_add("log_search_match", match, end)
        widget.mark_set(tk.INSERT, end if direction > 0 else match)
        widget.see(match)
        self._set_status(f"Найдено в {self.log_search_target.get()}", "Info")


    def copy_result(self):
        result_text = (self._full_output_text or self.txt_output.get("1.0", tk.END)).strip()
        if result_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(result_text)
            messagebox.showinfo("Успех", "Скопировано в буфер обмена!")
        else:
            messagebox.showwarning("Предупреждение", "Нет данных для копирования!")


    def _build_diff_html(self, original: str, cleaned: str) -> str:
        mapping_table = self.anonymizer.mapping_table if self.anonymizer else {}
        reverse_mapping = self.anonymizer.reverse_mapping if self.anonymizer else {}
        org_name = self.anonymizer.config.org_name if self.anonymizer else ""
        return _build_diff_html_doc(
            original, cleaned, mapping_table, reverse_mapping, org_name=org_name,
        )


    def export_diff_html(self):
        """Экспорт diff'а в отдельный HTML-файл."""
        original = self._text_value(self.txt_input)
        cleaned = self.txt_output.get("1.0", tk.END)
        if not original.strip() or not cleaned.strip():
            messagebox.showwarning("Предупреждение", "Нужны и исходный текст, и результат анонимизации!")
            return
        if not self._confirm_sensitive_export():
            return

        try:
            html_doc = self._build_diff_html(original, cleaned)
        except Exception as exc:
            logger.exception("Не удалось построить HTML diff-отчёт")
            messagebox.showerror("Ошибка", f"Не удалось построить diff-отчёт: {exc}")
            return

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
                os.chmod(f.name, 0o600)
                f.write(html_doc)
                tmp_path = f.name
            webbrowser.open("file://" + tmp_path)
        except OSError as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть diff в браузере: {e}")


    def show_stats(self):
        if not self.anonymizer or not self.anonymizer.get_stats():
            messagebox.showinfo("Статистика", "Замен пока не было.")
            return
        stats = self.anonymizer.get_stats()
        lines = [f"{tag}: {count}" for tag, count in sorted(stats.items(), key=lambda kv: -kv[1])]
        lines.append(f"\nВсего уникальных значений: {len(self.anonymizer.mapping_table)}")
        if self._last_file_report:
            lines.append("\nОтчет по файлу:")
            lines.extend(
                f"- {item.get('file', 'input')}: {item.get('status')} / "
                f"{item.get('structural_status', 'unknown')}, "
                f"замен: {item.get('replacements', 0)}"
                for item in self._last_file_report
            )
        messagebox.showinfo("Статистика замен (тип: число вхождений)", "\n".join(lines))
