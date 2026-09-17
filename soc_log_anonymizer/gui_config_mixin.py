"""Mixin providing GuiConfigMixin methods for AnonymizerGUI."""
from __future__ import annotations

import json
import logging
import os
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional

from .config import AnonymizerConfig
from .gui_constants import ICON_TAB_CONFIG, ICON_WARN
from .gui_logic import salt_entropy_warning
from .gui_profiles import format_allowlist_lines, parse_allowlist_lines
from .paths import app_dir

logger = logging.getLogger("soc_log_anonymizer")


class GuiConfigMixin:
    def _default_config_save_path(self) -> str:
        """Путь, по которому конфиг будет сохранён, если ни один файл ещё
        не был явно загружен/сохранён в этой сессии — тот же путь, что
        ищет автопоиск при следующем запуске (см.
        config.find_default_config_path), чтобы "Сохранить" без диалога
        сразу создавало файл там, где его подхватит автозагрузка."""
        return os.path.join(app_dir(), "soc_log_anonymizer.json")


    def _refresh_config_editor(self) -> None:
        """Перерисовывает текстовое поле вкладки "Конфигурация" текущим
        состоянием self.config и обновляет баннер с путём к файлу."""
        if self._config_path:
            self.lbl_config_path.configure(
                text=f"{ICON_TAB_CONFIG} Текущий файл: {self._config_path}\n"
                     f"Изменения применяются к текущей сессии сразу после «Сохранить» и "
                     f"будут подхвачены автоматически при следующем запуске программы."
            )
        else:
            default_path = self._default_config_save_path()
            self.lbl_config_path.configure(
                text=f"{ICON_WARN} Конфиг-файл ещё не найден и не сохранён — используются "
                     f"значения по умолчанию. «Сохранить» создаст файл здесь:\n{default_path}\n"
                     f"(эта папка автоматически проверяется при каждом запуске программы)."
            )
        self.txt_config.delete("1.0", tk.END)
        self.txt_config.insert(tk.END, json.dumps(self.config.as_dict(), ensure_ascii=False, indent=2))
        self._refresh_allowlist_widget()


    def _parse_config_editor(self) -> Optional[AnonymizerConfig]:
        """Парсит текущее содержимое текстового поля в AnonymizerConfig.
        Возвращает None и показывает messagebox с ошибкой, если JSON
        битый или не является объектом — используется всеми кнопками
        вкладки (Сохранить/Сохранить как/Проверить), чтобы не дублировать
        обработку ошибок трижды."""
        raw = self.txt_config.get("1.0", tk.END)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            messagebox.showerror("Некорректный JSON", f"Не удалось разобрать JSON:\n{e}")
            return None
        if not isinstance(data, dict):
            messagebox.showerror("Некорректный JSON", "Верхний уровень конфигурации должен быть JSON-объектом ({...}).")
            return None
        try:
            if hasattr(self, "txt_allowlist"):
                data["allowlist"] = parse_allowlist_lines(
                    self.txt_allowlist.get("1.0", tk.END)
                )
            return AnonymizerConfig.from_dict(data)
        except (TypeError, ValueError) as e:
            messagebox.showerror("Некорректная конфигурация", f"Не удалось построить конфигурацию из JSON:\n{e}")
            return None


    def validate_config_editor(self) -> None:
        """Проверяет ТЕКУЩЕЕ содержимое редактора (ещё не обязательно
        сохранённое) через AnonymizerConfig.validate(), не трогая файл на
        диске и не применяя изменения к текущей сессии — для итеративного
        редактирования "проверил -> поправил -> проверил снова"."""
        config = self._parse_config_editor()
        if config is None:
            return
        issues = config.validate()
        if issues:
            messagebox.showwarning("Найдены замечания", "\n".join(f"- {i}" for i in issues))
        else:
            messagebox.showinfo("Всё в порядке", "Конфигурация корректна, замечаний нет.")


    def _apply_and_save_config(self, path: str) -> None:
        config = self._parse_config_editor()
        if config is None:
            return
        issues = config.validate()
        if issues:
            proceed = messagebox.askyesno(
                "Найдены замечания",
                "Конфигурация содержит потенциальные проблемы:\n\n" +
                "\n".join(f"- {i}" for i in issues) +
                "\n\nСохранить и применить всё равно?"
            )
            if not proceed:
                return
        try:
            config.save(path)
        except OSError as e:
            messagebox.showerror(
                "Не удалось сохранить",
                f"Не удалось записать {path}:\n{e}\n\n"
                f"Попробуйте «Сохранить как…» и выбрать доступную для записи папку "
                f"(например, если приложение установлено в защищённый системный каталог)."
            )
            return
        self.config = config
        self._config_path = path
        self._refresh_config_editor()
        self._reset_session_timer()
        logger.info("Конфигурация сохранена: %s", path)
        self._set_status(f"Конфигурация сохранена: {os.path.basename(path)}", "Success")


    def save_config_editor(self) -> None:
        """Сохраняет по текущему известному пути (self._config_path) —
        либо, если в этой сессии ещё ни один конфиг-файл не использовался,
        по тому же пути, который проверяет автопоиск при следующем
        запуске (см. _default_config_save_path), без лишнего диалога."""
        path = self._config_path or self._default_config_save_path()
        self._apply_and_save_config(path)


    def save_config_editor_as(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("INI", "*.ini *.cfg"), ("All files", "*.*")],
            initialfile=os.path.basename(self._config_path) if self._config_path else "soc_log_anonymizer.json",
            initialdir=os.path.dirname(self._config_path) if self._config_path else app_dir(),
        )
        if not path:
            return
        self._apply_and_save_config(path)


    def reload_config_editor(self) -> None:
        """Перечитывает конфиг с диска по self._config_path, отбрасывая
        несохранённые правки в редакторе — полезно, если файл поменяли
        внешним редактором прямо во время работы приложения (само
        приложение не "следит" за файлом непрерывно — перечитывание
        происходит по явному запросу здесь или заново при следующем
        запуске приложения)."""
        if not self._config_path:
            messagebox.showinfo("Нет файла", "Пока не сохранено и не загружено ни одного файла конфигурации.")
            return
        try:
            self.config = AnonymizerConfig.load(self._config_path)
        except (OSError, json.JSONDecodeError) as e:
            messagebox.showerror("Ошибка", f"Не удалось перечитать {self._config_path}:\n{e}")
            return
        self._refresh_config_editor()
        self._set_status(f"Конфигурация перечитана: {os.path.basename(self._config_path)}", "Muted")


    def reset_config_editor(self) -> None:
        """Сбрасывает ТОЛЬКО текст в редакторе к значениям по умолчанию —
        не трогает файл на диске и не применяет ничего к текущей сессии,
        пока пользователь не нажмёт "Сохранить" сам."""
        proceed = messagebox.askyesno(
            "Сбросить к умолчаниям",
            "Заменить содержимое редактора значениями конфигурации по умолчанию?\n"
            "Файл на диске не изменится, пока вы не нажмёте «Сохранить»."
        )
        if not proceed:
            return
        defaults = AnonymizerConfig()
        self.txt_config.delete("1.0", tk.END)
        self.txt_config.insert(tk.END, json.dumps(defaults.as_dict(), ensure_ascii=False, indent=2))
        if hasattr(self, "txt_allowlist"):
            self.txt_allowlist.delete("1.0", tk.END)
            self.txt_allowlist.insert(tk.END, format_allowlist_lines(defaults.allowlist))


    def _refresh_allowlist_widget(self) -> None:
        if not hasattr(self, "txt_allowlist"):
            return
        self.txt_allowlist.delete("1.0", tk.END)
        self.txt_allowlist.insert(tk.END, format_allowlist_lines(self.config.allowlist))


    def _patch_config_editor_allowlist(self) -> None:
        """Keep advanced JSON in sync with the allowlist text section."""
        if not hasattr(self, "txt_config") or not hasattr(self, "txt_allowlist"):
            return
        try:
            data = json.loads(self.txt_config.get("1.0", tk.END))
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        data["allowlist"] = parse_allowlist_lines(self.txt_allowlist.get("1.0", tk.END))
        self.txt_config.delete("1.0", tk.END)
        self.txt_config.insert(tk.END, json.dumps(data, ensure_ascii=False, indent=2))


    def load_config_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Config", "*.json *.ini *.cfg"), ("All files", "*.*")])
        if not file_path:
            return
        try:
            self.config = AnonymizerConfig.load(file_path)
            self._config_path = file_path
            issues = self.config.validate()
            self._reset_session_timer()
            self._refresh_config_editor()
            logger.info("Конфигурация загружена: %s", file_path)
            if issues:
                messagebox.showwarning(
                    "Конфигурация загружена с замечаниями",
                    f"{os.path.basename(file_path)} загружен, но найдены потенциальные проблемы:\n\n" +
                    "\n".join(f"- {i}" for i in issues)
                )
            else:
                messagebox.showinfo("Успех", f"Конфигурация загружена из {os.path.basename(file_path)}")
        except Exception as e:
            logger.error("Не удалось загрузить конфигурацию %s: %s", file_path, e)
            messagebox.showerror("Ошибка", f"Не удалось загрузить конфигурацию: {e}")


    def generate_new_salt(self):
        self.entry_salt.delete(0, tk.END)
        self.entry_salt.insert(0, secrets.token_hex(16))
        self.entry_salt._is_placeholder = False
        self.entry_salt.configure(foreground=self._palette()["input_fg"])
        self._validate_salt_live(self.entry_salt.get())


    def _validate_salt_live(self, proposed: str) -> bool:
        """Обратный вызов ttk validatecommand — не блокирует ввод (всегда
        возвращает True), но помечает поле стилем "WeakSalt.TEntry", если
        текущая соль выглядит слабой, — предупреждение видно ещё до
        нажатия «Анонимизировать», а не только по клику."""
        warning = salt_entropy_warning(proposed)
        self.entry_salt.configure(style="WeakSalt.TEntry" if warning else "TEntry")
        return True
