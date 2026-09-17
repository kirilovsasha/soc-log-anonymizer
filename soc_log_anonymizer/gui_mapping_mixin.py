"""Mixin providing GuiMappingMixin methods for AnonymizerGUI."""
from __future__ import annotations

import csv
import logging
import os
import tkinter as tk
from tkinter import filedialog, messagebox

from .gui_constants import FONT_UI
from .gui_logic import find_context_snippet, mapping_rows_filtered
from .gui_theme import pseudonym_type as _pseudonym_type
from .io_utils import restrict_sensitive_file

logger = logging.getLogger("soc_log_anonymizer")


class GuiMappingMixin:
    def refresh_mapping_table(self):
        types = {"Все типы"}
        if self.anonymizer and self.anonymizer.mapping_table:
            types.update(_pseudonym_type(p) for p in self.anonymizer.mapping_table.values())
        if hasattr(self, "mapping_type_filter"):
            current = self.mapping_type_filter.get() or "Все типы"
            self.mapping_type_filter.configure(values=tuple(sorted(types, key=lambda x: (x != "Все типы", x))))
            if current not in types:
                current = "Все типы"
            self.mapping_type_filter.set(current)
        self.filter_mapping_table()


    def filter_mapping_table(self, event=None):
        query = self.entry_search.get().strip() if hasattr(self, "entry_search") else ""
        type_filter = self.mapping_type_filter.get() if hasattr(self, "mapping_type_filter") else ""
        for item in self.map_tree.get_children():
            self.map_tree.delete(item)
        mapping = getattr(self.anonymizer, "mapping_table", None) or {}
        for orig, pseudo in mapping_rows_filtered(mapping, query, type_filter, _pseudonym_type):
            self.map_tree.insert("", tk.END, values=(orig, pseudo))


    def _jump_from_mapping(self, event=None):
        selection = self.map_tree.selection()
        if not selection:
            return
        orig = str(self.map_tree.item(selection[0], "values")[0])
        haystack = self._text_value(self.txt_input)
        idx = haystack.find(orig)
        if idx < 0:
            self._set_status("Значение не найдено в Input", "Warning")
            return
        self.notebook.select(0)
        start = f"1.0 + {idx} chars"
        self.txt_input.tag_remove("sel", "1.0", tk.END)
        self.txt_input.tag_add("sel", start, f"1.0 + {idx + len(orig)} chars")
        self.txt_input.see(start)
        self._set_status("Переход к значению в Input", "Info")


    def export_mapping_csv(self):
        if not self.anonymizer or not self.anonymizer.mapping_table:
            messagebox.showwarning("Предупреждение", "Таблица соответствия пуста!")
            return
        if not self._confirm_sensitive_export():
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
        try:
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Original", "Pseudonym"])
                for orig, pseudo in self.anonymizer.mapping_table.items():
                    writer.writerow([orig, pseudo])
            warning = restrict_sensitive_file(file_path)
            if warning:
                logger.warning("%s", warning)
            messagebox.showinfo(
                "Успех",
                "Таблица соответствия экспортирована в CSV "
                "(доступ ограничен текущим пользователем).",
            )
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать CSV: {e}")


    def export_mapping_json(self):
        """Экспорт таблицы соответствия вместе с солью в JSON — этот файл
        можно позже передать в CLI (`deanonymize --mapping ...`) для
        восстановления исходных данных в новом процессе/сессии."""
        if not self.anonymizer or not self.anonymizer.mapping_table:
            messagebox.showwarning("Предупреждение", "Таблица соответствия пуста!")
            return
        if not self._confirm_sensitive_export():
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not file_path:
            return
        try:
            self.anonymizer.save_mapping(file_path)
            messagebox.showinfo(
                "Успех",
                "Таблица соответствия экспортирована в JSON "
                "(доступ ограничен текущим пользователем).",
            )
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать JSON: {e}")


    def _confirm_sensitive_export(self) -> bool:
        return messagebox.askokcancel(
            "Внимание — чувствительные данные",
            "Экспортируемый файл содержит исходные чувствительные значения "
            "(IP-адреса, логины, домены и т.д.) в открытом виде — по сути, "
            "это ключ деанонимизации.\n\n"
            "Не кладите salt/mapping на общий диск и в OneDrive без шифрования. "
            "На Windows доступ ограничивается ACL текущего пользователя; "
            "на POSIX — chmod 600.\n\n"
            "Продолжить экспорт?"
        )


    def _on_tree_motion(self, event):
        row_id = self.map_tree.identify_row(event.y)
        if not row_id:
            self._hide_tooltip()
            return
        if row_id == self._tooltip_row:
            return
        self._tooltip_row = row_id
        values = self.map_tree.item(row_id, "values")
        if not values:
            self._hide_tooltip()
            return
        original = values[0]
        context = find_context_snippet(self.txt_input.get("1.0", tk.END), original)
        self._show_tooltip(event.x_root, event.y_root, context)


    def _attach_tooltip_text(self, widget, text: str) -> None:
        """Статический tooltip для произвольного виджета (чипы легенды).

        Отличается от _on_input_motion тем, что текст фиксирован и не
        зависит от позиции курсора внутри виджета."""
        if not text:
            return
        widget.bind("<Enter>",
                    lambda e: self._show_tooltip(e.x_root, e.y_root, text), add="+")
        widget.bind("<Leave>", lambda e: self._hide_tooltip(), add="+")


    def _show_tooltip(self, x: int, y: int, text: str):
        self._hide_tooltip()
        p = self._palette()
        tw = tk.Toplevel(self.root)
        tw.wm_overrideredirect(True)
        try:
            tw.attributes("-topmost", True)
        except tk.TclError:
            pass
        # Place off-screen first so we can measure without a flash at a bad spot.
        tw.wm_geometry("+-10000+-10000")
        lbl = tk.Label(tw, text=text, background=p["surface"], foreground=p["text"],
                       relief=tk.SOLID, borderwidth=1, font=(FONT_UI, 9),
                       wraplength=420, justify=tk.LEFT, padx=8, pady=6)
        lbl.pack()
        tw.update_idletasks()

        tip_w = tw.winfo_reqwidth()
        tip_h = tw.winfo_reqheight()
        screen_w = tw.winfo_screenwidth()
        screen_h = tw.winfo_screenheight()
        margin = 8
        offset = 14

        pos_x = x + offset
        if pos_x + tip_w > screen_w - margin:
            pos_x = x - tip_w - offset
        if pos_x < margin:
            pos_x = max(margin, screen_w - tip_w - margin)

        pos_y = y + offset
        if pos_y + tip_h > screen_h - margin:
            pos_y = y - tip_h - offset
        if pos_y < margin:
            pos_y = max(margin, screen_h - tip_h - margin)

        tw.wm_geometry(f"+{pos_x}+{pos_y}")
        self._tooltip_window = tw


    def _hide_tooltip(self):
        if self._tooltip_window is not None:
            try:
                self._tooltip_window.destroy()
            except tk.TclError:
                pass
            self._tooltip_window = None
        self._tooltip_row = None
        self._tooltip_input_range = None
