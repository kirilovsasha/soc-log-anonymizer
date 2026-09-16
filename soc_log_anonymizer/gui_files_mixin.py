"""Mixin providing GuiFilesMixin methods for AnonymizerGUI."""
from __future__ import annotations

import logging
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Iterable, Optional, Tuple

from .gui_constants import FONT_MONO, GUI_DISPLAY_CHAR_LIMIT, GUI_SIDECAR_AUTO_MB
from .gui_logic import format_size_warning, truncate_display_text
from .gui_theme import HIGHLIGHT_TAG_NAMES
from .io_utils import format_size_mb, read_file_auto_encoding

logger = logging.getLogger("soc_log_anonymizer")


class GuiFilesMixin:
    def _add_placeholder(self, widget, text: str):
        """Показывает серую подсказку в пустом Entry/Text и убирает её по
        фокусу — реализовано на стандартных событиях <FocusIn>/<FocusOut>,
        без сторонних виджетов."""
        is_text_widget = isinstance(widget, tk.Text)
        muted = self._palette()["text_secondary"]
        normal_fg = self._palette()["input_fg"]

        def _get() -> str:
            return widget.get("1.0", tk.END) if is_text_widget else widget.get()

        def _clear():
            self._suppress_input_modified = True
            try:
                if is_text_widget:
                    widget.delete("1.0", tk.END)
                else:
                    widget.delete(0, tk.END)
            finally:
                self._suppress_input_modified = False

        def _show_placeholder():
            if _get().strip():
                return
            widget._is_placeholder = True
            self._suppress_input_modified = True
            try:
                if is_text_widget:
                    widget.insert("1.0", text)
                    widget.configure(fg=muted)
                else:
                    widget.insert(0, text)
                    widget.configure(foreground=muted)
            finally:
                self._suppress_input_modified = False

        def _on_focus_in(_event=None):
            if getattr(widget, "_is_placeholder", False):
                _clear()
                widget._is_placeholder = False
                if is_text_widget:
                    widget.configure(fg=normal_fg)
                else:
                    widget.configure(foreground=normal_fg)

        def _on_focus_out(_event=None):
            _show_placeholder()

        widget._is_placeholder = False
        widget.bind("<FocusIn>", _on_focus_in, add="+")
        widget.bind("<FocusOut>", _on_focus_out, add="+")
        _show_placeholder()


    def _on_input_modified(self, event=None):
        """Колбэк виртуального события <<Modified>> на Input: срабатывает
        при ЛЮБОМ изменении содержимого — наборе текста, вставке (Ctrl+V),
        удалении, программной записи. Реальный ввод пользователя делает
        старый Output неактуальным (он соответствует прежнему тексту
        Input) — если его не очистить, легко случайно скопировать/
        отправить результат анонимизации ПРЕДЫДУЩЕГО текста, решив, что
        он относится к текущему. Программные изменения (переключение
        placeholder'а — см. _add_placeholder) исключены через
        _suppress_input_modified, иначе клик в пустое поле и клик мимо
        него без единого нажатия клавиши уже очищал бы Output."""
        if not self.txt_input.edit_modified():
            return
        if not self._suppress_input_modified:
            self._full_input_text = None
            self._input_display_truncated = False
            had_output = bool(self.txt_output.get("1.0", tk.END).strip())
            if had_output:
                self.txt_output.delete("1.0", tk.END)
                self._set_status("Input изменён — Output очищен, нажмите «Анонимизировать» снова", "Muted")
            # Старая подсветка "исходное значение -> тип" в Input больше не
            # соответствует изменившемуся тексту (диапазоны тегов могли
            # съехать на другой текст) — снимаем её независимо от того,
            # был ли Output непустым, чтобы не оставлять "разъехавшуюся"
            # подсветку поверх нового текста.
            for tag in HIGHLIGHT_TAG_NAMES:
                self.txt_input.tag_remove(tag, "1.0", tk.END)
        # edit_modified(False) сам генерирует ещё одно событие <<Modified>>
        # (переход True -> False тоже смена состояния) — при повторном
        # входе edit_modified() будет уже False, и функция просто выйдет
        # по первому return выше, без повторной обработки.
        self.txt_input.edit_modified(False)


    def _on_input_motion(self, event):
        """Наведение на подсвеченное (заменённое при анонимизации)
        значение в Input показывает tooltip с тем, на что именно оно было
        заменено — не нужно идти в отдельную таблицу соответствия, чтобы
        узнать конкретный псевдоним."""
        if not self.anonymizer or not self.anonymizer.mapping_table:
            self._hide_tooltip()
            return
        index = self.txt_input.index(f"@{event.x},{event.y}")
        hl_tags = [t for t in self.txt_input.tag_names(index) if t.startswith("hl_")]
        if not hl_tags:
            self._hide_tooltip()
            return
        rng = self._tag_range_at_index(self.txt_input, hl_tags[0], index)
        if not rng:
            self._hide_tooltip()
            return
        if rng == self._tooltip_input_range:
            return  # мышь всё ещё над тем же диапазоном — не пересчитываем
        self._tooltip_input_range = rng
        original = self.txt_input.get(rng[0], rng[1])
        pseudo = self.anonymizer.mapping_table.get(original)
        if not pseudo:
            # Диапазон помечен тегом hl_*, но текста уже нет в mapping_table
            # (например, пользователь вручную отредактировал Input после
            # анонимизации, и старый диапазон "съехал" на другой текст) —
            # просто скрываем tooltip, не сбрасывая _tooltip_input_range,
            # чтобы не пересчитывать это на каждый следующий мелкий сдвиг
            # мыши в том же диапазоне.
            if self._tooltip_window is not None:
                self._tooltip_window.destroy()
                self._tooltip_window = None
            return
        self._show_tooltip(event.x_root, event.y_root, f"→ заменено на {pseudo}")


    @staticmethod
    def _tag_range_at_index(widget: tk.Text, tag: str, index: str) -> Optional[Tuple[str, str]]:
        """Возвращает (start, end) диапазона применения tag, содержащий
        index, или None. Использует tag_prevrange (эффективный поиск в
        Tk, а не ручной перебор ВСЕХ диапазонов тега через tag_ranges() —
        это было бы O(n) на каждое событие <Motion>, а оно стреляет очень
        часто при движении мыши; для лога с тысячами подсвеченных
        значений разница ощутима)."""
        prev = widget.tag_prevrange(tag, f"{index}+1c")
        if prev and widget.compare(prev[0], "<=", index) and widget.compare(index, "<", prev[1]):
            return str(prev[0]), str(prev[1])
        return None


    def _create_scrolled_text(self, parent, on_yscroll) -> Tuple[tk.Text, ttk.Scrollbar, ttk.Scrollbar]:
        text_container = ttk.Frame(parent, style="Card.TFrame")
        text_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        v_scroll = ttk.Scrollbar(text_container, orient=tk.VERTICAL)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # yscrollcommand=on_yscroll — стандартный Tkinter-паттерн двусторонней
        # привязки: он вызывается Text-виджетом при ЛЮБОМ изменении видимой
        # области (колесо мыши, стрелки/PageUp/PageDown/Home/End, resize,
        # редактирование текста, а не только программный yview() или
        # перетаскивание самого скроллбара). Именно поэтому синхронизация
        # между input/output строится через него, а не через `command`
        # скроллбара (который срабатывает ТОЛЬКО при взаимодействии с самим
        # скроллбаром и поэтому не ловит скролл колесом мыши/клавиатурой —
        # это и было причиной "не работающего" синхронного скролла).
        #
        # wrap=tk.WORD — перенос длинных строк по словам на ширину окна
        # (раньше wrap=tk.NONE заставлял листать очень длинные строки лога
        # горизонтально). Горизонтальный скроллбар больше не нужен и не
        # создаётся — при переносе по словам горизонтальной прокрутки не
        # бывает в принципе.
        txt_widget = tk.Text(text_container, wrap=tk.WORD, font=(FONT_MONO, self.font_size.get()),
                              yscrollcommand=on_yscroll, undo=True,
                              relief=tk.FLAT, borderwidth=0, highlightthickness=0, padx=8, pady=6)
        txt_widget.pack(fill=tk.BOTH, expand=True)
        v_scroll.config(command=txt_widget.yview)

        return txt_widget, v_scroll, None


    def _sync_yscroll(self, scrollbar: ttk.Scrollbar, other_widgets: Iterable[tk.Text],
                       first: str, last: str) -> None:
        """Колбэк yscrollcommand одной из связанных синхронным скроллом
        панелей: всегда обновляет "родной" скроллбар этой панели и, если
        включён чекбокс "Синхронный скролл", подтягивает КАЖДУЮ из
        `other_widgets` на ту же относительную позицию (`first`).
        `_syncing_scroll` защищает от бесконечной рекурсии: программный
        yview_moveto() на другой панели сам вызовет её собственный
        yscrollcommand, который без guard'а попытался бы синхронизировать
        обратно текущую панель.

        Сейчас единственная связка — input<->output (видны одновременно,
        бок о бок в редакторе логов); `other_widgets` оставлен как
        коллекция (а не одиночный виджет), чтобы при необходимости можно
        было добавить ещё одну синхронизируемую панель, не меняя саму
        функцию."""
        scrollbar.set(first, last)
        if self.sync_scroll_var.get() and not self._syncing_scroll:
            self._syncing_scroll = True
            try:
                for widget in other_widgets:
                    widget.yview_moveto(first)
            finally:
                self._syncing_scroll = False


    def _entry_value(self, entry: ttk.Entry) -> str:
        """Возвращает содержимое Entry, трактуя placeholder как пустую
        строку — иначе подсказка вида "например, bank" могла бы случайно
        попасть в реальную обработку, если поле не в фокусе."""
        if getattr(entry, "_is_placeholder", False):
            return ""
        return entry.get().strip()


    def _text_value(self, widget: tk.Text) -> str:
        if getattr(widget, "_is_placeholder", False):
            return ""
        if widget is getattr(self, "txt_input", None) and self._input_display_truncated:
            return self._full_input_text or widget.get("1.0", tk.END).strip()
        return widget.get("1.0", tk.END).strip()


    def _set_widget_content(self, widget, content: str):
        """Заменяет содержимое Entry/Text реальными данными и снимает
        флаг placeholder — используется при загрузке файла/восстановлении
        черновика, чтобы не перепутать реальный контент с подсказкой."""
        is_text_widget = isinstance(widget, tk.Text)
        widget._is_placeholder = False
        fg = self._palette()["input_fg"]
        if is_text_widget:
            widget.configure(fg=fg)
            self._suppress_input_modified = True
            try:
                widget.delete("1.0", tk.END)
                if widget is getattr(self, "txt_input", None):
                    self._full_input_text = content
                    display_content, truncated = truncate_display_text(content, GUI_DISPLAY_CHAR_LIMIT)
                    self._input_display_truncated = truncated
                    widget.insert(tk.END, display_content)
                else:
                    widget.insert(tk.END, content)
            finally:
                self._suppress_input_modified = False
            if widget is getattr(self, "txt_input", None):
                widget.edit_modified(False)
            if widget is getattr(self, "txt_input", None) and self._input_display_truncated:
                self._set_status("Input отображается частично; обработка использует полный текст", "Warning")
        else:
            widget.configure(foreground=fg)
            widget.delete(0, tk.END)
            widget.insert(0, content)


    def open_file(self):
        file_paths = filedialog.askopenfilenames(
            filetypes=[("Log files", "*.log *.txt *.json *.cef *.xml *.gz"), ("All files", "*.*")]
        )
        if not file_paths:
            return
        self._load_selected_files(tuple(file_paths))


    def open_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку с логами")
        if not folder:
            return
        paths = tuple(os.path.join(folder, name) for name in sorted(os.listdir(folder))
                      if os.path.isfile(os.path.join(folder, name)))
        if not paths:
            messagebox.showwarning("Папка пуста", "В выбранной папке нет файлов.")
            return
        self._load_selected_files(paths)


    def _load_selected_files(self, file_paths: Tuple[str, ...]):

        # Для .gz-файлов это размер СЖАТОГО файла на диске — реальный
        # объём после распаковки будет больше (обычно в разы), но
        # получение точного несжатого размера потребовало бы либо
        # распаковки файлов целиком, либо ненадёжного чтения ISIZE-трейлера
        # gzip. Суммарный размер даёт консервативное предупреждение для
        # пакетной загрузки.
        size_mb = 0.0
        for file_path in file_paths:
            try:
                size_mb += format_size_mb(os.path.getsize(file_path))
            except OSError:
                continue
        prefer_sidecar = False
        if size_mb > self.config.max_input_size_mb or (
            self.auto_sidecar_large.get() and size_mb >= GUI_SIDECAR_AUTO_MB
        ):
            choice = messagebox.askyesnocancel(
                "Большой файл",
                format_size_warning(size_mb, self.config.max_input_size_mb)
                + "\n\nДа — загрузить превью и писать полный результат в *.anon.log\n"
                "Нет — загрузить целиком в редактор (может быть медленно)\n"
                "Отмена — не открывать",
            )
            if choice is None:
                return
            prefer_sidecar = bool(choice)
            if not prefer_sidecar and size_mb > self.config.max_input_size_mb:
                proceed = messagebox.askyesno(
                    "Подтверждение",
                    "Полная загрузка большого файла в GUI может исчерпать память.\n"
                    "Продолжить?",
                )
                if not proceed:
                    return

        self._prefer_sidecar = prefer_sidecar
        self.btn_open.config(state=tk.DISABLED)
        self.btn_open_folder.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.NORMAL)
        self._cancel_event.clear()
        self._set_status(
            f"Загрузка файлов ({len(file_paths)})…" if len(file_paths) > 1 else "Загрузка файла…",
            "Info",
        )
        threading.Thread(target=self._async_open_files, args=(tuple(file_paths),), daemon=True).start()


    def _async_open_files(self, file_paths: Tuple[str, ...]):
        contents = []
        loaded = []
        errors = []
        for file_path in file_paths:
            if self._cancel_event.is_set():
                break
            try:
                contents.append(read_file_auto_encoding(file_path))
                loaded.append(file_path)
            except (OSError, UnicodeError, ValueError) as exc:
                errors.append(f"{os.path.basename(file_path)}: {exc}")
        try:
            content = contents[0] if contents else ""
            for next_content in contents[1:]:
                if content and not content.endswith(("\r", "\n")):
                    content += "\n" + ("-" * 72) + "\n"
                content += next_content
            self.root.after(0, self._on_file_loaded, content, errors, loaded)
        except Exception as e:
            self.root.after(0, self._on_file_loaded, None, [str(e)], loaded)


    def _on_file_loaded(self, content: Optional[str], errors=None, loaded=None):
        self.btn_open.config(state=tk.NORMAL)
        self.btn_open_folder.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)
        self._loaded_files = list(loaded or [])
        self.files_list.delete(0, tk.END)
        for path in self._loaded_files:
            self.files_list.insert(tk.END, os.path.basename(path))
        self._update_file_summary()
        if self._cancel_event.is_set():
            self._set_status("Загрузка отменена", "Muted")
            return
        if errors and not content:
            logger.error("Не удалось открыть файлы: %s", errors)
            messagebox.showerror("Ошибка загрузки", "\n".join(errors))
            self._set_status("Ошибка загрузки", "Danger")
            return
        if errors:
            messagebox.showwarning("Частичная загрузка",
                                   "Некоторые файлы пропущены:\n" + "\n".join(errors))
        if content and self._prefer_sidecar:
            self._set_widget_content(self.txt_input, content)
            # Keep full text even if display was not truncated (sidecar path).
            self._full_input_text = content
            self._input_display_truncated = True
            self._set_status(
                f"Превью загружено ({len(self._loaded_files)} файл(ов)); "
                "полный результат уйдёт в *.anon.log",
                "Warning",
            )
        else:
            self._prefer_sidecar = False
            self._set_widget_content(self.txt_input, content)
            self._set_status(f"Загружено файлов: {len(self._loaded_files)}", "Info")
        logger.info("Загружены файлы (%d символов)", len(content or ""))


    def cancel_operation(self):
        self._cancel_event.set()
        self._set_status("Отмена запрошена…", "Warning")


    def remove_loaded_file(self):
        selection = self.files_list.curselection()
        if not selection:
            return
        index = selection[0]
        self._loaded_files.pop(index)
        self.files_list.delete(index)
        self._update_file_summary()
        self._rebuild_loaded_text()


    def move_loaded_file(self, delta: int):
        selection = self.files_list.curselection()
        if not selection:
            return
        index = selection[0]
        target = index + delta
        if not 0 <= target < len(self._loaded_files):
            return
        self._loaded_files[index], self._loaded_files[target] = (
            self._loaded_files[target], self._loaded_files[index])
        self.files_list.delete(0, tk.END)
        for path in self._loaded_files:
            self.files_list.insert(tk.END, os.path.basename(path))
        self.files_list.selection_set(target)
        self._update_file_summary()
        self._rebuild_loaded_text()


    def _rebuild_loaded_text(self):
        parts = []
        for path in self._loaded_files:
            try:
                parts.append(read_file_auto_encoding(path))
            except (OSError, UnicodeError, ValueError):
                continue
        self._set_widget_content(self.txt_input, "\n" + ("-" * 72) + "\n".join(parts)
                                 if parts else "")


    def save_file(self):
        result_text = (self._full_output_text or self.txt_output.get("1.0", tk.END)).strip()
        if not result_text:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения!")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Text files", "*.log *.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(result_text)
                messagebox.showinfo("Успех", "Файл успешно сохранен!")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")


    def clear_all(self, confirm: bool = True):
        """Полный сброс сессии: оба окна, таблица соответствия, история
        отмены и загруженные файлы.

        Подтверждение спрашивается, когда есть что терять: с появлением
        хоткея (Ctrl+L) промах по клавише стал куда вероятнее промаха по
        кнопке, а таблица соответствия после очистки не восстанавливается
        — деанонимизировать ответ LLM будет уже нечем."""
        has_content = bool(self._pane_text(self.txt_input) or self._pane_text(self.txt_output))
        if confirm and has_content and not messagebox.askyesno(
            "Очистить всё",
            "Очистить оба окна и таблицу соответствия?\n\n"
            "Таблица соответствия будет удалена из памяти — после этого "
            "де-анонимизировать ответ LLM этой сессией уже не получится. "
            "Экспортируйте её заранее, если она ещё нужна.",
        ):
            return
        self.txt_input.delete("1.0", tk.END)
        self.txt_output.delete("1.0", tk.END)
        self._clear_diff_state()
        self._undo_stack.clear()
        if hasattr(self, "btn_undo"):
            self.btn_undo.config(state=tk.DISABLED)
        self._full_input_text = None
        self._input_display_truncated = False
        for item in self.map_tree.get_children():
            self.map_tree.delete(item)
        if self.anonymizer:
            self.anonymizer.clear_sensitive_data()
        self._loaded_files.clear()
        if hasattr(self, "files_list"):
            self.files_list.delete(0, tk.END)
        self._update_file_summary()
        self._set_progress(0)
        if hasattr(self, "progress_label"):
            self.progress_label.configure(text="0%")
        self._set_status("Очищено", "Muted")
