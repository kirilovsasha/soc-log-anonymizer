"""Mixin providing GuiChromeMixin methods for AnonymizerGUI."""
from __future__ import annotations

import logging
import os
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Tuple

from .gui_constants import (
    _STATUS_KINDS,
    FONT_MONO,
    FONT_UI,
    MAX_FONT_SIZE,
    MIN_FONT_SIZE,
)
from .gui_logic import (
    HOTKEYS,
    accelerator_to_sequence,
    format_shortcuts_help,
    normalize_keysym,
    status_style_name,
)
from .gui_theme import (
    _TYPE_LEGEND_RU,
    PALETTE_DARK,
    PALETTE_LIGHT,
    TAG_COLORS_DARK,
    TAG_COLORS_LIGHT,
)
from .paths import (
    app_dir,
    crash_log_path,
    ensure_dir,
    open_in_file_manager,
    user_data_dir,
)

logger = logging.getLogger("soc_log_anonymizer")


class GuiChromeMixin:
    def _bind_hotkeys(self):
        """Навешивает биндинги по таблице HOTKEYS из gui_logic.

        Один источник правды для биндингов, акселераторов в меню и
        справки по F1 — иначе при добавлении сочетания легко забыть
        обновить меню или справку.

        Обработчики возвращают "break": у tk.Text есть собственные
        class-level биндинги (в частности на <Control-z> — виджет создан
        с undo=True), и без "break" после нашего обработчика отработал бы
        ещё и штатный undo виджета."""
        self._hotkey_actions = {}
        for accelerator, method_name, _ in HOTKEYS:
            handler = getattr(self, method_name, None)
            if handler is None:  # опечатка в таблице не должна ронять GUI
                logger.warning("Хоткей %s ссылается на несуществующий метод %s",
                               accelerator, method_name)
                continue
            sequence = accelerator_to_sequence(accelerator)
            self.root.bind_all(sequence, self._hotkey_callback(handler), add="+")
            self._hotkey_actions[self._hotkey_signature(accelerator)] = handler

        # Фолбэк для не-латинских раскладок: при русской раскладке Tk
        # отдаёт кириллический keysym, и <Control-l> просто не
        # срабатывает. Ловим Control-нажатия отдельно и сопоставляем
        # клавишу по её латинскому эквиваленту на той же физической
        # кнопке.
        self.root.bind_all("<Control-KeyPress>", self._on_control_keypress, add="+")


    @staticmethod
    def _hotkey_signature(accelerator: str) -> Tuple[bool, bool, str]:
        parts = [p.strip().lower() for p in accelerator.split("+")]
        key = parts[-1]
        return ("shift" in parts, "alt" in parts, key)


    @staticmethod
    def _hotkey_callback(handler):
        def _callback(event=None):
            handler()
            return "break"
        return _callback


    def _on_control_keypress(self, event):
        latin = normalize_keysym(event.keysym)
        if not latin or len(latin) != 1:
            return None
        shift = bool(event.state & 0x0001)
        alt = bool(event.state & 0x0008) or bool(event.state & 0x20000)
        handler = self._hotkey_actions.get((shift, alt, latin))
        if handler is None:
            return None
        if event.keysym.lower() == latin:
            return None  # латинская раскладка — уже отработал обычный биндинг
        handler()
        return "break"


    def show_shortcuts(self):
        """Справка по горячим клавишам (F1)."""
        messagebox.showinfo("Горячие клавиши", format_shortcuts_help())


    def _find_next(self):
        self._find_in_logs(1)


    def _find_previous(self):
        self._find_in_logs(-1)


    def clear_focused_pane(self):
        """Очищает только то текстовое поле, в котором сейчас фокус.

        Отдельно от clear_all: "хочу переписать ввод" и "хочу стереть всю
        сессию вместе с таблицей соответствия" — разные намерения, и
        второе необратимо."""
        widget = self.root.focus_get()
        if widget is self.txt_input:
            self._set_widget_content(self.txt_input, "")
            self._full_input_text = None
            self._input_display_truncated = False
        elif widget is self.txt_output:
            self.txt_output.delete("1.0", tk.END)
        else:
            self._set_status("Поставьте курсор в Input или Output", "Muted")
            return
        self._clear_diff_state()
        self._set_status("Поле очищено", "Muted")


    def _build_menu(self):
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Открыть файл", command=self.open_file, accelerator=self._accelerator_for("open_file"))
        file_menu.add_command(label="Открыть папку…", command=self.open_folder)
        file_menu.add_command(label="Сохранить результат", command=self.save_file, accelerator=self._accelerator_for("save_file"))
        file_menu.add_separator()
        file_menu.add_command(label="Открыть папку приложения", command=self.open_app_folder)
        file_menu.add_command(label="Открыть папку данных / конфига", command=self.open_data_folder)
        file_menu.add_command(label="Открыть журнал ошибок", command=self.open_crash_log)
        file_menu.add_separator()
        file_menu.add_command(label="HTML Diff отчёт", command=self.export_diff_html)
        file_menu.add_command(label="Статистика", command=self.show_stats)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self._on_close)
        edit_menu = tk.Menu(menu, tearoff=False)
        edit_menu.add_command(label="Анонимизировать", command=self.start_processing_thread,
                              accelerator=self._accelerator_for("start_processing_thread"))
        edit_menu.add_command(label="Отменить последнюю операцию", command=self.undo_last,
                              accelerator=self._accelerator_for("undo_last"))
        edit_menu.add_command(label="Де-анонимизировать", command=self.deanonymize_text,
                              accelerator=self._accelerator_for("deanonymize_text"))
        edit_menu.add_command(label="Скопировать результат", command=self.copy_result,
                              accelerator=self._accelerator_for("copy_result"))
        edit_menu.add_separator()
        edit_menu.add_command(label="Очистить активное поле", command=self.clear_focused_pane,
                              accelerator=self._accelerator_for("clear_focused_pane"))
        edit_menu.add_command(label="Очистить всё", command=self.clear_all,
                              accelerator=self._accelerator_for("clear_all"))
        view_menu = tk.Menu(menu, tearoff=False)
        view_menu.add_checkbutton(
            label="Тёмная тема", variable=self.dark_mode, command=self._apply_theme,
        )
        view_menu.add_checkbutton(
            label="Синхронизация скролла", variable=self.sync_scroll_var,
        )
        font_menu = tk.Menu(view_menu, tearoff=False)
        for size in range(MIN_FONT_SIZE, MAX_FONT_SIZE + 1):
            font_menu.add_radiobutton(
                label=f"{size} pt",
                value=size,
                variable=self.font_size,
                command=self._apply_font_size,
            )
        view_menu.add_cascade(label="Размер шрифта", menu=font_menu)
        view_menu.add_separator()
        view_menu.add_command(label="Поиск по логам", command=self._focus_log_search,
                              accelerator=self._accelerator_for("_focus_log_search"))
        view_menu.add_command(label="Следующее совпадение", command=lambda: self._find_in_logs(1),
                              accelerator=self._accelerator_for("_find_next"))
        view_menu.add_command(label="Предыдущее совпадение", command=lambda: self._find_in_logs(-1),
                              accelerator=self._accelerator_for("_find_previous"))
        view_menu.add_separator()
        view_menu.add_command(label="Следующее изменение", command=lambda: self._navigate_diff(1),
                              accelerator=self._accelerator_for("_next_diff"))
        view_menu.add_command(label="Предыдущее изменение", command=lambda: self._navigate_diff(-1),
                              accelerator=self._accelerator_for("_previous_diff"))
        settings_menu = tk.Menu(menu, tearoff=False)
        settings_menu.add_checkbutton(
            label="Автосохранение черновика ввода",
            variable=self.autosave_drafts,
            command=self._on_autosave_toggle,
        )
        settings_menu.add_checkbutton(
            label="Большие файлы → превью + sidecar",
            variable=self.auto_sidecar_large,
        )
        settings_menu.add_checkbutton(
            label="Portable-режим (данные рядом с exe)",
            variable=self.portable_mode_var,
            command=self._on_portable_toggle,
        )
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Горячие клавиши", command=self.show_shortcuts,
                              accelerator=self._accelerator_for("show_shortcuts"))
        help_menu.add_command(label="О программе", command=self.show_about)
        menu.add_cascade(label="Файл", menu=file_menu)
        menu.add_cascade(label="Правка", menu=edit_menu)
        menu.add_cascade(label="Вид", menu=view_menu)
        menu.add_cascade(label="Настройки", menu=settings_menu)
        menu.add_cascade(label="Справка", menu=help_menu)
        self.root.configure(menu=menu)


    def open_app_folder(self):
        open_in_file_manager(app_dir())


    def open_data_folder(self):
        open_in_file_manager(ensure_dir(user_data_dir(self._portable)))


    def open_crash_log(self):
        path = crash_log_path(self._portable)
        ensure_dir(os.path.dirname(path) or ".")
        if not os.path.isfile(path):
            with open(path, "a", encoding="utf-8"):
                pass
        open_in_file_manager(path)


    def show_about(self):
        from . import __version__
        mode = "portable" if self._portable else "installed"
        messagebox.showinfo(
            "О программе",
            f"SOC Log Anonymizer {__version__}\n"
            f"Режим данных: {mode}\n"
            f"Приложение: {app_dir()}\n"
            f"Данные: {user_data_dir(self._portable)}\n"
            f"Журнал ошибок: {crash_log_path(self._portable)}\n",
        )


    @staticmethod
    def _accelerator_for(method_name: str) -> str:
        """Акселератор для пункта меню берётся из той же таблицы, что и
        сам биндинг — чтобы меню не обещало сочетание, которого нет."""
        for accelerator, name, _ in HOTKEYS:
            if name == method_name:
                return accelerator
        return ""


    def _action_tooltip(self, method_name: str, description: str) -> str:
        """Текст hover-подсказки: описание + горячая клавиша из HOTKEYS."""
        accel = self._accelerator_for(method_name)
        return f"{description} ({accel})" if accel else description


    def _palette(self) -> dict:
        return PALETTE_DARK if self.dark_mode.get() else PALETTE_LIGHT


    def _configure_styles(self):
        """(Пере)регистрирует все именованные ttk-стили под текущую
        палитру. Вызывается один раз при старте и повторно при
        переключении темы — виджеты, созданные со `style=...`, обновляют
        внешний вид автоматически, без обхода дерева и без хранения
        списков "каких виджетов чем покрасить"."""
        p = self._palette()
        style = ttk.Style()
        # 'clam' — единственная встроенная тема, которая честно
        # применяет наши цвета на всех платформах. Нативные темы Windows
        # ('vista'/'winnative') рисуют кнопки через Win32 Theme API и
        # игнорируют большинство настроек style.configure(), поэтому без
        # этой строки кастомная палитра на Windows была бы не видна.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.root.configure(bg=p["bg"])

        style.configure("App.TFrame", background=p["bg"])
        style.configure("Card.TFrame", background=p["surface"])
        style.configure("Border.TFrame", background=p["border"])
        style.configure("SurfaceAlt.TFrame", background=p["surface_alt"])

        style.configure("TLabel", background=p["bg"], foreground=p["text"], font=(FONT_UI, 10))
        style.configure("Card.TLabel", background=p["surface"], foreground=p["text"], font=(FONT_UI, 10))
        style.configure("Muted.TLabel", background=p["surface"], foreground=p["text_secondary"], font=(FONT_UI, 9))
        style.configure("Heading.TLabel", background=p["surface"], foreground=p["text"], font=(FONT_UI, 10, "bold"))
        style.configure("Section.TLabel", background=p["surface"], foreground=p["text_secondary"],
                         font=(FONT_UI, 9, "bold"), padding=(0, 2))
        style.configure("StatusBar.TFrame", background=p["surface_alt"])
        style.configure("StatusBar.TLabel", background=p["surface_alt"], foreground=p["text"],
                        font=(FONT_UI, 9))
        style.configure("Banner.TLabel", background=p["warning"], foreground=p["warning_fg"],
                         font=(FONT_UI, 9), padding=(12, 7))

        style.configure("TCheckbutton", background=p["surface"], foreground=p["text"], font=(FONT_UI, 9))
        style.map("TCheckbutton", background=[("active", p["surface"])])

        style.configure("TEntry", fieldbackground=p["input_bg"], foreground=p["input_fg"],
                         bordercolor=p["border"], lightcolor=p["input_bg"], darkcolor=p["input_bg"],
                         insertcolor=p["input_fg"], padding=4)
        style.map("TEntry", bordercolor=[("focus", p["accent"])])

        # Отдельный стиль для поля соли, когда её энтропия признана слабой
        # (см. _validate_salt_live) — красная рамка видна ещё до нажатия
        # кнопки «Анонимизировать», а не только по клику.
        style.configure("WeakSalt.TEntry", fieldbackground=p["input_bg"], foreground=p["input_fg"],
                         bordercolor=p["danger"], lightcolor=p["input_bg"], darkcolor=p["input_bg"],
                         insertcolor=p["input_fg"], padding=4)
        style.map("WeakSalt.TEntry", bordercolor=[("focus", p["danger"])])

        style.configure("TSpinbox", fieldbackground=p["input_bg"], foreground=p["input_fg"],
                         bordercolor=p["border"], arrowsize=12, padding=3)

        # --- Кнопки ---
        style.configure("Primary.TButton", background=p["accent"], foreground=p["accent_fg"],
                         borderwidth=0, padding=(16, 9), font=(FONT_UI, 10, "bold"))
        style.map("Primary.TButton",
                  background=[("disabled", p["disabled_bg"]), ("pressed", p["accent_hover"]),
                              ("active", p["accent_hover"])],
                  foreground=[("disabled", p["disabled_fg"])])

        style.configure("Purple.TButton", background=p["purple"], foreground="#ffffff",
                         borderwidth=0, padding=(16, 9), font=(FONT_UI, 10, "bold"))
        style.map("Purple.TButton",
                  background=[("disabled", p["disabled_bg"]), ("pressed", p["purple_hover"]),
                              ("active", p["purple_hover"])],
                  foreground=[("disabled", p["disabled_fg"])])

        style.configure("Ghost.TButton", background=p["surface"], foreground=p["text"],
                         bordercolor=p["border"], borderwidth=1, padding=(12, 8), font=(FONT_UI, 9))
        style.map("Ghost.TButton",
                  background=[("disabled", p["surface"]), ("pressed", p["surface_alt"]),
                              ("active", p["surface_alt"])],
                  foreground=[("disabled", p["disabled_fg"])])

        style.configure("Ghost.TMenubutton", background=p["surface"], foreground=p["text"],
                         bordercolor=p["border"], borderwidth=1, padding=(12, 8), font=(FONT_UI, 9),
                         relief="raised")
        style.map("Ghost.TMenubutton",
                  background=[("disabled", p["surface"]), ("pressed", p["surface_alt"]),
                              ("active", p["surface_alt"])],
                  foreground=[("disabled", p["disabled_fg"])])

        style.configure("Danger.TButton", background=p["surface"], foreground=p["danger"],
                         bordercolor=p["danger"], borderwidth=1, padding=(12, 8), font=(FONT_UI, 9))
        style.map("Danger.TButton",
                  background=[("active", p["danger"]), ("pressed", p["danger_hover"])],
                  foreground=[("active", "#ffffff"), ("pressed", "#ffffff")])

        style.configure("IconGhost.TButton", background=p["surface"], foreground=p["text"],
                         bordercolor=p["border"], borderwidth=1, padding=(8, 6), font=(FONT_UI, 10))
        style.map("IconGhost.TButton", background=[("active", p["surface_alt"])])

        # Keep secondary controls visually consistent with the primary actions.
        style.configure("TButton", font=(FONT_UI, 9), padding=(12, 7))

        # --- Статусные чипы ---
        status_colors = {
            "Idle": (p["surface_alt"], p["text_secondary"]),
            "Muted": (p["surface_alt"], p["text_secondary"]),
            "Info": (p["accent"], "#ffffff"),
            "Success": (p["success"], "#ffffff"),
            "Danger": (p["danger"], "#ffffff"),
            "Warning": (p["warning"], p["warning_fg"]),
            "Purple": (p["purple"], "#ffffff"),
        }
        for name in _STATUS_KINDS:
            bg, fg = status_colors[name]
            style.configure(f"Status{name}.TLabel", background=bg, foreground=fg,
                             font=(FONT_UI, 9, "bold"), padding=(12, 6))

        # --- Notebook / вкладки ---
        style.configure("TNotebook", background=p["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=p["surface_alt"], foreground=p["text_secondary"],
                         padding=(16, 9), font=(FONT_UI, 9, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", p["surface"])],
                  foreground=[("selected", p["text"])])

        # --- Treeview (таблица соответствия) ---
        style.configure("Treeview", background=p["surface"], fieldbackground=p["surface"],
                         foreground=p["text"], rowheight=26, borderwidth=0, font=(FONT_UI, 9))
        style.configure("Treeview.Heading", background=p["surface_alt"], foreground=p["text"],
                         font=(FONT_UI, 9, "bold"), relief="flat")
        style.map("Treeview.Heading", background=[("active", p["surface_alt"])])
        style.map("Treeview", background=[("selected", p["highlight_bg"])],
                  foreground=[("selected", p["highlight_fg"])])

        # --- Progressbar ---
        style.configure("TProgressbar", background=p["accent"], troughcolor=p["surface_alt"],
                         borderwidth=0, thickness=8)

        # --- Scrollbar (тонкий, плоский) ---
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", background=p["surface_alt"], troughcolor=p["surface"],
                             bordercolor=p["surface"], arrowsize=12, width=12)

        style.configure("TPanedwindow", background=p["bg"])
        style.configure("Sash", sashthickness=6, gripcount=0)

        # --- tk.Text (не ttk — красим вручную) ---
        if hasattr(self, "txt_input") and hasattr(self, "txt_output"):
            type_colors = TAG_COLORS_DARK if self.dark_mode.get() else TAG_COLORS_LIGHT
            for txt in (self.txt_input, self.txt_output):
                txt.configure(bg=p["surface"], fg=p["text"], insertbackground=p["text"],
                              selectbackground=p["highlight_bg"], selectforeground=p["highlight_fg"],
                              font=(FONT_MONO, self.font_size.get()))
                for type_name, (bg, fg) in type_colors.items():
                    txt.tag_config(f"hl_{type_name}", background=bg, foreground=fg)
                # Метка текущего изменения при навигации (Ctrl+Alt+Down/Up).
                # Рамка, а не заливка: заливка перекрыла бы цвет типа
                # данных ровно у того значения, которое пользователь и
                # пришёл разглядывать.
                txt.tag_config("diff_current", relief=tk.SOLID, borderwidth=2,
                               underline=True)
                txt.tag_raise("diff_current")
                txt.tag_raise("sel")
            if hasattr(self, "txt_config"):
                self.txt_config.configure(bg=p["surface"], fg=p["text"], insertbackground=p["text"],
                                           selectbackground=p["highlight_bg"], selectforeground=p["highlight_fg"],
                                           font=(FONT_MONO, self.font_size.get()))
        if hasattr(self, "files_list"):
            self.files_list.configure(
                bg=p["surface"], fg=p["text"], selectbackground=p["highlight_bg"],
                selectforeground=p["highlight_fg"], font=(FONT_UI, 9),
            )


    def _apply_theme(self):
        self._configure_styles()
        self._render_type_legend()


    def _toggle_dark_mode(self) -> None:
        self.dark_mode.set(not self.dark_mode.get())
        self._apply_theme()


    def _render_type_legend(self) -> None:
        """Перерисовывает легенду по self._legend_counts.

        Отдельно от подсчёта, потому что вызывается ещё и при
        переключении темы: цвета типов у светлой и тёмной палитры разные
        (TAG_COLORS_LIGHT/TAG_COLORS_DARK), и легенда, оставшаяся от
        прошлой темы, показывала бы цвета, которых в тексте уже нет."""
        if not hasattr(self, "legend_frame"):
            return
        for child in self.legend_frame.winfo_children():
            child.destroy()
        if not self._legend_counts:
            return
        colors = TAG_COLORS_DARK if self.dark_mode.get() else TAG_COLORS_LIGHT
        ttk.Label(self.legend_frame, text="Заменено:", style="Section.TLabel"
                  ).pack(side=tk.LEFT, padx=(0, 8))
        for type_name, count in sorted(self._legend_counts.items(),
                                       key=lambda kv: (-kv[1], kv[0])):
            bg, fg = colors.get(type_name, colors["VALUE"])
            title = _TYPE_LEGEND_RU.get(type_name, (type_name, ""))[0]
            chip = tk.Label(self.legend_frame, text=f" {title}: {count} ",
                            bg=bg, fg=fg, font=(FONT_UI, 8), padx=2)
            chip.pack(side=tk.LEFT, padx=2, pady=2)
            self._attach_tooltip_text(chip, _TYPE_LEGEND_RU.get(type_name, ("", ""))[1])


    def _apply_font_size(self):
        size = self.font_size.get()
        self.txt_input.configure(font=(FONT_MONO, size))
        self.txt_output.configure(font=(FONT_MONO, size))
        if hasattr(self, "txt_config"):
            self.txt_config.configure(font=(FONT_MONO, size))


    def _set_status(self, text: str, kind: str = "Idle"):
        """Единая точка установки статуса. kind — один из _STATUS_KINDS
        (без учёта регистра). Цвет чипа полностью определяется стилем
        Status{Kind}.TLabel, который _configure_styles() пересчитывает
        при каждом переключении темы — самому статус-лейблу ничего
        обновлять вручную не нужно."""
        self.status_label.configure(text=text, style=status_style_name(kind))


    def _card(self, parent, padding_x=1, padding_y=1) -> Tuple[ttk.Frame, ttk.Frame]:
        """Карточка с тонкой 1px рамкой: внешний Frame цвета границы +
        внутренний Frame цвета поверхности с отступом в 1px — простой и
        надёжный способ получить аккуратную рамку средствами tk/ttk без
        сторонних библиотек и без изображений."""
        outer = ttk.Frame(parent, style="Border.TFrame")
        inner = ttk.Frame(outer, style="Card.TFrame")
        inner.pack(fill=tk.BOTH, expand=True, padx=padding_x, pady=padding_y)
        return outer, inner
