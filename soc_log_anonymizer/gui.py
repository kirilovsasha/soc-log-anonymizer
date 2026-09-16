import atexit
import base64
import csv
import glob
import json
import logging
import os
import re
import secrets
import sys
import tempfile
import threading
import tkinter as tk
import webbrowser
from collections import deque
from tkinter import filedialog, messagebox, ttk
from typing import Dict, Iterable, List, Optional, Tuple

from .anonymizer import SOCLogAnonymizer
from .audit import log_audit_event
from .config import AnonymizerConfig, find_default_config_path, _app_dir
from .gui_session import (
    extract_session_profile,
    session_fields_from_config,
)
from .gui_theme import (
    HIGHLIGHT_TAG_NAMES,
    PALETTE_DARK,
    PALETTE_LIGHT,
    TAG_COLORS_DARK,
    TAG_COLORS_LIGHT,
    _TYPE_LEGEND_RU,
    pseudonym_type as _pseudonym_type,
)
from .gui_logic import (
    HOTKEYS,
    accelerator_to_sequence,
    changed_line_numbers,
    compute_progress_pct,
    format_shortcuts_help,
    inline_diff_spans,
    normalize_keysym,
    typed_value_spans,
    find_context_snippet,
    format_result_status,
    format_result_payload,
    format_size_warning,
    salt_entropy_warning,
    status_style_name,
    truncate_display_text,
    validate_regex_pattern,
    mapping_rows_filtered,
)
from .gui_constants import (
    AUTOSAVE_INTERVAL_MS,
    DEFAULT_FONT_SIZE,
    FONT_MONO,
    FONT_UI,
    GUI_DISPLAY_CHAR_LIMIT,
    GUI_STATE_FILENAME,
    ICON_TAB_CONFIG,
    ICON_WARN,
    MAX_FONT_SIZE,
    MIN_FONT_SIZE,
    PLACEHOLDER_FG,
    UNDO_HISTORY_SIZE,
    _STATUS_KINDS,
)
from .gui_diff_html import build_diff_html as _build_diff_html_doc
from .gui_layout import build_main_ui
from .gui_profiles import (
    ALLOWLIST_PRESETS,
    apply_source_profile,
    merge_lists,
)
from .io_utils import format_size_mb, read_file_auto_encoding

logger = logging.getLogger("soc_log_anonymizer")


class AnonymizerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOC Log Anonymizer")
        self.root.geometry("1440x960")
        self.root.minsize(1000, 700)
        self._gui_state_path = os.path.join(
            os.environ.get("APPDATA", tempfile.gettempdir()),
            GUI_STATE_FILENAME,
        )
        self._gui_state = self._load_gui_state()
        # The editor is the primary workspace. Start maximized on Windows so
        # the input and output panes use the available screen instead of
        # leaving most of the desktop unused.
        if sys.platform == "win32":
            self.root.state("zoomed")

        # self.anonymizer создаётся и переприсваивается ТОЛЬКО в главном
        # потоке, чтобы исключить гонку между фоновым потоком обработки и
        # обработчиками кнопок GUI.
        #
        # Автопоиск конфига рядом с приложением (см.
        # config.find_default_config_path) — работает и для обычного
        # запуска, и для собранного PyInstaller .exe: если рядом лежит
        # soc_log_anonymizer.json/.ini, он подхватывается автоматически,
        # без необходимости открывать вкладку "⚙ Конфигурация" каждый раз. Так как
        # это происходит в __init__ (то есть при каждом запуске
        # приложения), любые изменения файла между запусками подхватятся
        # сами — заново перечитывать во время уже работающей сессии не
        # нужно (см. вкладку "Конфигурация" для перечитывания вручную,
        # если конфиг поменяли прямо во время работы приложения).
        self._config_path: Optional[str] = find_default_config_path()
        if self._config_path:
            self.config = AnonymizerConfig.load(self._config_path)
            issues = self.config.validate()
            for issue in issues:
                logger.warning("Автозагруженный конфиг %s: %s", self._config_path, issue)
            logger.info("Автоматически загружен конфиг: %s", self._config_path)
        else:
            self.config = AnonymizerConfig()
        self.anonymizer: Optional[SOCLogAnonymizer] = SOCLogAnonymizer(config=self.config)

        # История для отмены последней операции (undo)
        self._undo_stack: deque = deque(maxlen=UNDO_HISTORY_SIZE)

        # Таймер автоочистки сессии по бездействию
        self._session_timer: Optional[threading.Timer] = None
        self._cancel_event = threading.Event()
        self._loaded_files: List[str] = []
        self._full_input_text: Optional[str] = None
        self._full_output_text: Optional[str] = None
        self._input_display_truncated = False
        # Диапазоны (start, end) в символах — не номера строк: подсветка
        # и навигация идут по конкретным заменённым значениям.
        self._diff_input_spans: List[Tuple[int, int]] = []
        self._diff_output_spans: List[Tuple[int, int]] = []
        self._diff_cursor = -1
        # Токен текущего прохода подсветки: пакетная отрисовка через
        # root.after может пережить следующий вызов _refresh_diff_highlighting
        # (пользователь нажал "Анонимизировать" второй раз, пока красился
        # предыдущий результат) — устаревший проход обязан прекратиться,
        # иначе он дорисует теги от уже неактуального diff'а.
        self._diff_render_token = 0
        self._last_file_report: List[dict] = []

        # Тема и размер шрифта (сохраняются только на время сессии)
        self.dark_mode = tk.BooleanVar(value=False)
        self.font_size = tk.IntVar(value=DEFAULT_FONT_SIZE)

        # Путь автосохранения черновика ввода (см. _schedule_autosave) —
        # уникален для процесса, чтобы несколько запущенных копий
        # приложения не затирали черновики друг друга.
        self._autosave_path = os.path.join(
            tempfile.gettempdir(), f"soc_log_anonymizer_draft_{os.getpid()}.txt"
        )
        self._tooltip_window: Optional[tk.Toplevel] = None
        self._tooltip_row: Optional[str] = None
        # Аналог _tooltip_row, но для подсвеченных значений в Input (см.
        # _on_input_motion) — кэширует текущий диапазон (start, end) под
        # курсором, чтобы не пересчитывать tooltip на каждый мелкий сдвиг
        # мыши внутри одного и того же подсвеченного значения.
        self._tooltip_input_range: Optional[Tuple[str, str]] = None

        # Guard от рекурсии в _sync_yscroll: при синхронизации скролла между
        # input/output панелями программный yview_moveto() на одной панели
        # сам провоцирует её собственный yscrollcommand — без guard'а это
        # приводило бы к обратному вызову на первую панель и т.д.
        self._syncing_scroll = False

        # Guard от ложного срабатывания автоочистки Output (см.
        # _on_input_modified): переключение placeholder'а в Input
        # (программные insert/delete в _add_placeholder) — не реальный
        # ввод пользователя и не должно расцениваться как "пользователь
        # изменил Input, старый Output больше не актуален".
        self._suppress_input_modified = False

        self._set_window_icon()
        self._configure_styles()  # стили нужны ДО построения виджетов
        self._build_ui()
        self._configure_styles()  # второй проход — раскрашивает уже созданные tk.Text
        self._restore_gui_state()
        self.root.bind("<Configure>", self._on_window_resize, add="+")
        self._build_menu()

        self._add_placeholder(self.entry_org, "например, bank")
        self._add_placeholder(self.entry_salt, "случайная строка…")
        self._add_placeholder(self.txt_input, "Вставьте лог сюда или нажмите «Открыть» (Ctrl+O)…")

        self._bind_hotkeys()
        self._reset_session_timer()
        self._offer_draft_recovery()
        self._schedule_autosave()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Иконка окна (генерируется программно — без внешних файлов/Pillow)
    # ------------------------------------------------------------------

    def _load_gui_state(self) -> dict:
        """Load window-only state; this is not an import/export setting."""
        try:
            with open(self._gui_state_path, "r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def _restore_gui_state(self) -> None:
        geometry = self._gui_state.get("geometry")
        if isinstance(geometry, str) and geometry:
            try:
                self.root.geometry(geometry)
            except tk.TclError:
                logger.debug("Saved GUI geometry is invalid: %r", geometry)
        if self._gui_state.get("zoomed") and sys.platform == "win32":
            try:
                self.root.state("zoomed")
            except tk.TclError:
                pass
        self.dark_mode.set(bool(self._gui_state.get("dark_mode", False)))
        try:
            self.font_size.set(max(MIN_FONT_SIZE, min(MAX_FONT_SIZE,
                                                       int(self._gui_state.get("font_size", DEFAULT_FONT_SIZE)))))
        except (TypeError, ValueError):
            self.font_size.set(DEFAULT_FONT_SIZE)
        self._configure_styles()
        self._apply_font_size()
        profile = extract_session_profile(self._gui_state)
        if hasattr(self, "entry_org") and profile.get("org_name"):
            self._set_widget_content(self.entry_org, profile["org_name"])
        self.root.after_idle(self._restore_editor_sash)

    def _restore_editor_sash(self) -> None:
        sash = self._gui_state.get("editor_sash")
        if sash is None or not hasattr(self, "editor_paned"):
            return
        try:
            self.editor_paned.sashpos(0, int(sash))
        except (tk.TclError, TypeError, ValueError):
            logger.debug("Saved editor sash is invalid: %r", sash)

    def _save_gui_state(self) -> None:
        state = {
            "geometry": self.root.geometry(),
            "zoomed": sys.platform == "win32" and self.root.state() == "zoomed",
            "dark_mode": bool(self.dark_mode.get()),
            "font_size": int(self.font_size.get()),
        }
        if hasattr(self, "entry_org"):
            org = self._entry_value(self.entry_org) or self.config.org_name
            state.update(session_fields_from_config(org))
        try:
            state["editor_sash"] = int(self.editor_paned.sashpos(0))
        except (AttributeError, tk.TclError):
            pass
        try:
            os.makedirs(os.path.dirname(self._gui_state_path), exist_ok=True)
            with open(self._gui_state_path, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, indent=2)
        except OSError as exc:
            logger.debug("Could not save GUI state: %s", exc)

    def _set_window_icon(self):
        """Генерирует простую иконку (закрашенный круг фирменного цвета)
        в формате PPM и передаёт её как tk.PhotoImage. Без сторонних
        библиотек и файлов изображений — PPM поддерживается tkinter "из
        коробки", нужно только собрать байты и закодировать в base64."""
        try:
            size = 32
            cx = cy = size / 2
            r = size / 2 - 2
            accent = bytes((0x4F, 0x46, 0xE5))  # PALETTE_LIGHT["accent"]
            bg = bytes((0xFF, 0xFF, 0xFF))
            pixels = bytearray()
            for y in range(size):
                for x in range(size):
                    dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
                    pixels += accent if dist <= r else bg
            ppm = f"P6\n{size} {size}\n255\n".encode("ascii") + bytes(pixels)
            self._icon_photo = tk.PhotoImage(data=base64.b64encode(ppm).decode("ascii"))
            self.root.iconphoto(True, self._icon_photo)
        except tk.TclError as e:
            logger.debug("Не удалось установить иконку окна: %s", e)

    # ------------------------------------------------------------------
    # Placeholder-текст в полях ввода
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Автосохранение черновика ввода + восстановление после сбоя
    # ------------------------------------------------------------------

    def _schedule_autosave(self):
        self.root.after(AUTOSAVE_INTERVAL_MS, self._autosave_tick)

    def _autosave_tick(self):
        try:
            if not getattr(self.txt_input, "_is_placeholder", False):
                content = self.txt_input.get("1.0", tk.END)
                if content.strip():
                    self._write_draft_file(self._autosave_path, content)
        except OSError as e:
            logger.debug("Автосохранение черновика не удалось: %s", e)
        self._schedule_autosave()

    @staticmethod
    def _write_draft_file(path: str, content: str) -> None:
        """Пишет черновик лога (потенциально НЕанонимизированные, т.е.
        чувствительные данные) во временный файл с правами 0600 —
        аналогично save_mapping()/save_salt(). Файл создаётся через
        os.open с явным режимом доступа, а не через open(), чтобы не
        зависеть от umask процесса: на многопользовательской системе
        обычный open() мог бы оставить файл доступным на чтение другим
        локальным пользователям, что для черновика с сырым логом
        недопустимо."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)

    def _offer_draft_recovery(self):
        """При старте ищет файлы черновиков от предыдущих (аварийно
        завершённых) сессий и предлагает восстановить самый свежий."""
        pattern = os.path.join(tempfile.gettempdir(), "soc_log_anonymizer_draft_*.txt")
        candidates = [p for p in glob.glob(pattern) if p != self._autosave_path]
        if not candidates:
            return
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        latest = candidates[0]
        try:
            proceed = messagebox.askyesno(
                "Восстановление черновика",
                f"Найден несохранённый черновик от предыдущей сессии "
                f"({os.path.basename(latest)}). Восстановить его в поле ввода?"
            )
            if proceed:
                with open(latest, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                self._set_widget_content(self.txt_input, content)
        finally:
            for p in candidates:
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _cleanup_autosave_file(self):
        try:
            if os.path.exists(self._autosave_path):
                os.remove(self._autosave_path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Горячие клавиши
    # ------------------------------------------------------------------

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
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Горячие клавиши", command=self.show_shortcuts,
                              accelerator=self._accelerator_for("show_shortcuts"))
        menu.add_cascade(label="Файл", menu=file_menu)
        menu.add_cascade(label="Правка", menu=edit_menu)
        menu.add_cascade(label="Вид", menu=view_menu)
        menu.add_cascade(label="Справка", menu=help_menu)
        self.root.configure(menu=menu)

    @staticmethod
    def _accelerator_for(method_name: str) -> str:
        """Акселератор для пункта меню берётся из той же таблицы, что и
        сам биндинг — чтобы меню не обещало сочетание, которого нет."""
        for accelerator, name, _ in HOTKEYS:
            if name == method_name:
                return accelerator
        return ""

    # ------------------------------------------------------------------
    # Тема / стили (единственный источник истины для всех цветов UI)
    # ------------------------------------------------------------------

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

    def _on_window_resize(self, event):
        """Adapt the status meter to the available width."""
        if event.widget is not self.root:
            return
        if hasattr(self, "progress"):
            self.progress.configure(length=max(120, min(260, event.width // 5)))

    def _set_status(self, text: str, kind: str = "Idle"):
        """Единая точка установки статуса. kind — один из _STATUS_KINDS
        (без учёта регистра). Цвет чипа полностью определяется стилем
        Status{Kind}.TLabel, который _configure_styles() пересчитывает
        при каждом переключении темы — самому статус-лейблу ничего
        обновлять вручную не нужно."""
        self.status_label.configure(text=text, style=status_style_name(kind))

    # ------------------------------------------------------------------
    # Построение интерфейса
    # ------------------------------------------------------------------

    def _card(self, parent, padding_x=1, padding_y=1) -> Tuple[ttk.Frame, ttk.Frame]:
        """Карточка с тонкой 1px рамкой: внешний Frame цвета границы +
        внутренний Frame цвета поверхности с отступом в 1px — простой и
        надёжный способ получить аккуратную рамку средствами tk/ttk без
        сторонних библиотек и без изображений."""
        outer = ttk.Frame(parent, style="Border.TFrame")
        inner = ttk.Frame(outer, style="Card.TFrame")
        inner.pack(fill=tk.BOTH, expand=True, padx=padding_x, pady=padding_y)
        return outer, inner

    def _build_ui(self):
        build_main_ui(self)

    # ------------------------------------------------------------------
    # Вкладка "Конфигурация" — редактирование и сохранение JSON-конфига
    # прямо в GUI, без похода во внешний текстовый редактор.
    # ------------------------------------------------------------------

    def _default_config_save_path(self) -> str:
        """Путь, по которому конфиг будет сохранён, если ни один файл ещё
        не был явно загружен/сохранён в этой сессии — тот же путь, что
        ищет автопоиск при следующем запуске (см.
        config.find_default_config_path), чтобы "Сохранить" без диалога
        сразу создавало файл там, где его подхватит автозагрузка."""
        return os.path.join(_app_dir(), "soc_log_anonymizer.json")

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
            if hasattr(self, "allowlist_list"):
                data["allowlist"] = list(self.allowlist_list.get(0, tk.END))
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
        self.entry_org.delete(0, tk.END)
        self.entry_org.insert(0, self.config.org_name)
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
            initialdir=os.path.dirname(self._config_path) if self._config_path else _app_dir(),
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
        self.entry_org.delete(0, tk.END)
        self.entry_org.insert(0, self.config.org_name)
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
        if hasattr(self, "allowlist_list"):
            self.allowlist_list.delete(0, tk.END)
            for value in defaults.allowlist:
                self.allowlist_list.insert(tk.END, value)

    def _refresh_allowlist_widget(self) -> None:
        if not hasattr(self, "allowlist_list"):
            return
        self.allowlist_list.delete(0, tk.END)
        for value in self.config.allowlist:
            self.allowlist_list.insert(tk.END, value)

    def _sync_allowlist_from_widget(self) -> None:
        if not hasattr(self, "allowlist_list"):
            return
        self.config.allowlist = list(self.allowlist_list.get(0, tk.END))

    def add_allowlist_value(self) -> None:
        value = (self.allowlist_entry.get() or "").strip()
        if not value:
            return
        current = list(self.allowlist_list.get(0, tk.END))
        merged = merge_lists(current, [value])
        self.allowlist_list.delete(0, tk.END)
        for item in merged:
            self.allowlist_list.insert(tk.END, item)
        self.allowlist_entry.delete(0, tk.END)
        self._sync_allowlist_from_widget()
        self._patch_config_editor_allowlist()

    def remove_allowlist_value(self) -> None:
        selection = list(self.allowlist_list.curselection())
        if not selection:
            return
        for index in reversed(selection):
            self.allowlist_list.delete(index)
        self._sync_allowlist_from_widget()
        self._patch_config_editor_allowlist()

    def add_allowlist_preset(self, preset_id: str) -> None:
        extras = ALLOWLIST_PRESETS.get(preset_id, [])
        if not extras:
            return
        merged = merge_lists(self.allowlist_list.get(0, tk.END), extras)
        self.allowlist_list.delete(0, tk.END)
        for item in merged:
            self.allowlist_list.insert(tk.END, item)
        self._sync_allowlist_from_widget()
        self._patch_config_editor_allowlist()
        self._set_status(f"Allowlist: добавлен пресет {preset_id}", "Info")

    def _patch_config_editor_allowlist(self) -> None:
        """Keep advanced JSON in sync with the allowlist listbox."""
        if not hasattr(self, "txt_config"):
            return
        try:
            data = json.loads(self.txt_config.get("1.0", tk.END))
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        data["allowlist"] = list(self.allowlist_list.get(0, tk.END))
        self.txt_config.delete("1.0", tk.END)
        self.txt_config.insert(tk.END, json.dumps(data, ensure_ascii=False, indent=2))

    def apply_selected_profile(self) -> None:
        title = self.profile_combo.get()
        profile_id = getattr(self, "_profile_titles", {}).get(title)
        if not profile_id:
            messagebox.showwarning("Профиль", "Выберите профиль источника.")
            return
        proceed = messagebox.askyesno(
            "Профиль источника",
            f"Применить профиль «{title}»?\n"
            "Обновятся списки полей (user/secret/CEF/JSON) и при необходимости allowlist.\n"
            "Нажмите «Сохранить» на вкладке Конфигурация, чтобы записать на диск.",
        )
        if not proceed:
            return
        apply_source_profile(self.config, profile_id)
        self.entry_org.delete(0, tk.END)
        self.entry_org.insert(0, self.config.org_name)
        self._refresh_config_editor()
        self._set_status(f"Профиль применён: {title}", "Success")

    # ------------------------------------------------------------------
    # Тултип с контекстом в таблице соответствия
    # ------------------------------------------------------------------

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
        tw.wm_geometry(f"+{x + 14}+{y + 14}")
        lbl = tk.Label(tw, text=text, background=p["surface"], foreground=p["text"],
                       relief=tk.SOLID, borderwidth=1, font=(FONT_UI, 9),
                       wraplength=420, justify=tk.LEFT, padx=8, pady=6)
        lbl.pack()
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

    # ------------------------------------------------------------------
    # Тултип "→ заменено на ..." над подсвеченными значениями в Input
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Таймаут сессии
    # ------------------------------------------------------------------

    def _reset_session_timer(self):
        if self._session_timer:
            self._session_timer.cancel()
        minutes = self.config.session_timeout_minutes
        if minutes and minutes > 0:
            self._session_timer = threading.Timer(minutes * 60, self._on_session_timeout)
            self._session_timer.daemon = True
            self._session_timer.start()

    def _on_session_timeout(self):
        self.root.after(0, self._session_timeout_ui)

    def _session_timeout_ui(self):
        if self.anonymizer and self.anonymizer.mapping_table:
            self.anonymizer.clear_sensitive_data()
            self.anonymizer = SOCLogAnonymizer(config=self.config)
            self.refresh_mapping_table()
            self._set_status("Сессия истекла — таблица соответствия очищена", "Warning")
            logger.info("Сессия истекла по таймауту — mapping-таблица очищена")
        self._reset_session_timer()

    def _on_close(self):
        if self._session_timer:
            self._session_timer.cancel()
        self._save_gui_state()
        if self.anonymizer:
            self.anonymizer.clear_sensitive_data()
        self._cleanup_autosave_file()
        self.root.destroy()

    # ------------------------------------------------------------------
    # Прочие вспомогательные методы
    # ------------------------------------------------------------------

    def generate_new_salt(self):
        self.entry_salt.delete(0, tk.END)
        self.entry_salt.insert(0, secrets.token_hex(16))
        self.entry_salt._is_placeholder = False
        self.entry_salt.configure(foreground=self._palette()["input_fg"])
        self._validate_salt_live(self.entry_salt.get())

    def load_config_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Config", "*.json *.ini *.cfg"), ("All files", "*.*")])
        if not file_path:
            return
        try:
            self.config = AnonymizerConfig.load(file_path)
            self._config_path = file_path
            issues = self.config.validate()
            self.entry_org.delete(0, tk.END)
            self.entry_org.insert(0, self.config.org_name)
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

    def _set_progress(self, pct: int):
        self.progress["value"] = pct
        if hasattr(self, "progress_label"):
            self.progress_label.configure(text=f"{int(pct)}%")

    def _update_file_summary(self):
        """Keep the file panel summary in sync without changing file order."""
        if hasattr(self, "files_count_label"):
            count = len(self._loaded_files)
            self.files_count_label.configure(
                text=f"{count} файл" if count == 1 else f"{count} файлов"
            )

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

    def _validate_salt_live(self, proposed: str) -> bool:
        """Обратный вызов ttk validatecommand — не блокирует ввод (всегда
        возвращает True), но помечает поле стилем "WeakSalt.TEntry", если
        текущая соль выглядит слабой, — предупреждение видно ещё до
        нажатия «Анонимизировать», а не только по клику."""
        warning = salt_entropy_warning(proposed)
        self.entry_salt.configure(style="WeakSalt.TEntry" if warning else "TEntry")
        return True

    # ------------------------------------------------------------------
    # Открытие файла (асинхронно)
    # ------------------------------------------------------------------

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
        if size_mb > self.config.max_input_size_mb:
            proceed = messagebox.askyesno(
                "Большой файл",
                format_size_warning(size_mb, self.config.max_input_size_mb) +
                "\n\nПродолжить загрузку файлов в редактор?"
            )
            if not proceed:
                return

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
        content, extension = format_result_payload(result_text, self.result_format.get())
        file_path = filedialog.asksaveasfilename(
            defaultextension=extension,
            filetypes=[("Text files", "*.log *.txt"), ("JSON files", "*.json"),
                       ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
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

    # ------------------------------------------------------------------
    # Анонимизация (асинхронно, с реальным прогрессом по строкам)
    # ------------------------------------------------------------------

    def start_processing_thread(self):
        raw_text = self._text_value(self.txt_input)
        if not raw_text:
            messagebox.showwarning("Предупреждение", "Введите или загрузите текст логов!")
            return

        # Проверка размера при "Открыть файл" покрывает только этот путь —
        # текст, вставленный напрямую (Ctrl+V) или набранный в Input, её
        # не проходит. Мегабайты текста в tk.Text и так не самый быстрый
        # виджет, а дальнейшая подсветка заменённых значений (см.
        # _refresh_diff_highlighting) добавляет накладных расходов сверху
        # — предупреждаем и даём выбор, а не подвешиваем интерфейс молча.
        size_mb = len(raw_text.encode("utf-8")) / (1024 * 1024)
        if size_mb > self.config.max_input_size_mb:
            proceed = messagebox.askyesno(
                "Большой объём текста",
                format_size_warning(size_mb, self.config.max_input_size_mb) +
                "\n\nДля файлов такого размера обычно быстрее и надёжнее использовать "
                "CLI (soc-log-anonymizer anonymize --files ...), где нет накладных расходов "
                "на отрисовку в графическом виджете.\n\nПродолжить в этом окне?"
            )
            if not proceed:
                return

        org_name = self._entry_value(self.entry_org) or "bank"
        salt = self._entry_value(self.entry_salt) or secrets.token_hex(16)

        warning = salt_entropy_warning(salt)
        if warning:
            proceed = messagebox.askyesno("Слабая соль", f"{warning}\n\nПродолжить с этой солью?")
            if not proceed:
                return

        self.btn_process.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.NORMAL)
        self._cancel_event.clear()
        self._set_progress(0)
        self._set_status("Обработка…", "Info")

        new_anonymizer = SOCLogAnonymizer(salt=salt, org_name=org_name, config=self.config)

        threading.Thread(
            target=self._async_process,
            args=(raw_text, new_anonymizer),
            daemon=True
        ).start()

    def _async_process(self, raw_text: str, new_anonymizer: SOCLogAnonymizer):
        stripped = raw_text.strip()
        is_single_json = (stripped.startswith("{") and stripped.endswith("}")) or \
                          (stripped.startswith("[") and stripped.endswith("]"))

        if is_single_json:
            # Единый JSON-документ нельзя обрабатывать построчно —
            # прогресс покажет только начало и конец.
            self.root.after(0, self._set_progress, 10)
            cleaned_text = new_anonymizer.anonymize(raw_text)
            if self._cancel_event.is_set():
                self.root.after(0, self._processing_cancelled, new_anonymizer)
                return
            self.root.after(0, self._set_progress, 100)
        else:
            lines = raw_text.splitlines(keepends=True)
            total = max(len(lines), 1)
            out_parts = []
            for i, out_line in enumerate(new_anonymizer.anonymize_stream(lines), 1):
                out_parts.append(out_line)
                if self._cancel_event.is_set():
                    self.root.after(0, self._processing_cancelled, new_anonymizer,
                                    "".join(out_parts), i, total)
                    return
                if i % 25 == 0 or i == total:
                    self.root.after(0, self._set_progress, compute_progress_pct(i, total))
            cleaned_text = "".join(out_parts)

        is_safe, issues = new_anonymizer.verify(cleaned_text)
        self.root.after(0, self._update_ui_after_processing, new_anonymizer, cleaned_text, is_safe, issues)

    def _processing_cancelled(self, anonymizer, partial_text: str = "", processed: int = 0,
                              total: int = 0):
        if partial_text:
            safe, issues = anonymizer.verify(partial_text)
            self.txt_output.delete("1.0", tk.END)
            self.txt_output.insert(tk.END, partial_text)
            self.anonymizer = anonymizer
            self.refresh_mapping_table()
            self._refresh_diff_highlighting()
            self._last_file_report = [{
                "status": "cancelled_partial",
                "processed_lines": processed,
                "total_lines": total,
                "safe": safe,
                "issues": issues,
            }]
            self._set_progress(compute_progress_pct(processed, total))
            self._set_status(
                f"Отменено: сохранён частичный результат ({processed}/{total} строк)",
                "Warning",
            )
        anonymizer.clear_sensitive_data()
        self.btn_process.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)
        if not partial_text:
            self._set_status("Обработка отменена", "Muted")

    def _update_ui_after_processing(self, new_anonymizer: SOCLogAnonymizer, cleaned_text: str,
                                     is_safe: bool, issues: List[str]):
        # Сохраняем предыдущее состояние для отмены (undo)
        prev_output = self.txt_output.get("1.0", tk.END)
        self._undo_stack.append((self.anonymizer, prev_output))
        self.btn_undo.config(state=tk.NORMAL)

        # Единственное место, где self.anonymizer переприсваивается —
        # выполняется в главном потоке.
        self.anonymizer = new_anonymizer
        self.config = new_anonymizer.config
        self._reset_session_timer()

        self.txt_output.delete("1.0", tk.END)
        display, truncated = truncate_display_text(cleaned_text, GUI_DISPLAY_CHAR_LIMIT)
        self._full_output_text = cleaned_text if truncated else None
        self.txt_output.insert(tk.END, display)
        if truncated and self._loaded_files:
            out_path = self._loaded_files[0] + ".anon.log"
            try:
                with open(out_path, "w", encoding="utf-8") as handle:
                    handle.write(cleaned_text)
                self._set_status(
                    f"Полный результат записан в {os.path.basename(out_path)}; в окне превью",
                    "Warning",
                )
            except OSError as exc:
                logger.warning("Could not write preview sidecar: %s", exc)
        self.refresh_mapping_table()
        self._refresh_diff_highlighting()
        self.btn_process.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)
        self._set_progress(100)

        status_text, status_kind = format_result_status(is_safe, issues)
        self._set_status(status_text, status_kind)
        if is_safe:
            logger.info("Анонимизация завершена: безопасно, %d значений в mapping",
                        len(new_anonymizer.mapping_table))
        else:
            for issue in issues:
                logger.warning("Gatekeeper: %s", issue)

        log_audit_event(new_anonymizer.config.audit_log_path, {
            "action": "anonymize",
            "source": "gui",
            "org_name": new_anonymizer.config.org_name,
            "stats_by_type": new_anonymizer.get_stats(),
            "unique_values_replaced": len(new_anonymizer.mapping_table),
            "gatekeeper_safe": is_safe,
            "gatekeeper_issue_count": len(issues),
        }, max_bytes=new_anonymizer.config.audit_log_max_bytes, backup_count=new_anonymizer.config.audit_log_backup_count)
        self._last_file_report = [{
            "file": os.path.basename(self._loaded_files[0]) if len(self._loaded_files) == 1 else "combined input",
            "status": "ok" if is_safe else "unsafe",
            "structural_status": "structured" if new_anonymizer.get_stats() else "fallback",
            "replacements": sum(new_anonymizer.get_stats().values()),
            "safe": is_safe,
            "issues": issues,
        }]

    def undo_last(self):
        if not self._undo_stack:
            return
        prev_anonymizer, prev_output = self._undo_stack.pop()
        self.anonymizer = prev_anonymizer
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, prev_output.rstrip("\n"))
        self.refresh_mapping_table()
        self._refresh_diff_highlighting()
        self._set_status("Отменено", "Muted")
        if not self._undo_stack:
            self.btn_undo.config(state=tk.DISABLED)

    # Подсветка Input/Output и навигация по изменениям — ОДИН проход.
    #
    # Раньше здесь было две независимые механики: _highlight_original_values
    # (поиск исходных значений в Input через widget.search по каждому ключу
    # mapping_table) и _apply_type_highlighting (то же самое для псевдонимов
    # в Output), плюс третья — построчный diff поверх них. Они сканировали
    # один и тот же текст несколько раз, разными способами, и результаты
    # расходились. Теперь диапазоны считаются один раз в gui_logic
    # (typed_value_spans — один скомпилированный регэксп на весь текст), из
    # одного набора строится и подсветка по типу, и список для навигации.

    # Сколько диапазонов размечать за один проход event loop, прежде чем
    # отдать управление обратно через root.after(0, ...). Число подобрано
    # эмпирически: достаточно крупное, чтобы не плодить избыточные
    # callback'и на обычных логах, и достаточно маленькое, чтобы при
    # десятках тысяч замен GUI не подвисал целиком за один вызов.
    _HIGHLIGHT_BATCH_SIZE = 300

    # Верхняя граница числа подсвечиваемых диапазонов. Смысл подсветки —
    # "посмотреть глазами, что поменялось"; при десятках тысяч значений
    # она перестаёт быть читаемой, но продолжает стоить тегов и памяти
    # Tk. Навигация (Ctrl+Alt+Down) при этом работает по всем диапазонам.
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

    def deanonymize_text(self):
        input_text = self._text_value(self.txt_input)
        if not input_text:
            messagebox.showwarning("Предупреждение", "Введите текст для де-анонимизации в левое окно!")
            return
        if not self.anonymizer or not self.anonymizer.reverse_mapping:
            messagebox.showwarning("Предупреждение", "Таблица замен пуста! Сначала выполните анонимизацию.")
            return

        restored_text = self.anonymizer.deanonymize(input_text)
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, restored_text)
        # Раньше вызывалось ДО insert — diff считался по ещё пустому
        # Output, и подсветка/навигация после де-анонимизации всегда были
        # пустыми.
        self._refresh_diff_highlighting()
        self._reset_session_timer()
        self._set_status("Де-анонимизировано", "Purple")
        log_audit_event(self.anonymizer.config.audit_log_path, {
            "action": "deanonymize",
            "source": "gui",
            "unique_values_available": len(self.anonymizer.reverse_mapping),
        }, max_bytes=self.anonymizer.config.audit_log_max_bytes, backup_count=self.anonymizer.config.audit_log_backup_count)

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

    # ------------------------------------------------------------------
    # Таблица соответствия
    # ------------------------------------------------------------------

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
            messagebox.showinfo("Успех", "Таблица соответствия экспортирована в CSV (права доступа 0600).")
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
            messagebox.showinfo("Успех", "Таблица соответствия экспортирована в JSON (права доступа 0600).")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать JSON: {e}")

    def _confirm_sensitive_export(self) -> bool:
        return messagebox.askokcancel(
            "Внимание — чувствительные данные",
            "Экспортируемый файл содержит исходные чувствительные значения "
            "(IP-адреса, логины, домены и т.д.) в открытом виде — по сути, "
            "это ключ деанонимизации.\n\n"
            "Храните и передавайте его так же, как исходный лог "
            "(ограниченный доступ, шифрование при необходимости).\n\n"
            "Продолжить экспорт?"
        )

    def copy_result(self):
        result_text = (self._full_output_text or self.txt_output.get("1.0", tk.END)).strip()
        if result_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(result_text)
            messagebox.showinfo("Успех", "Скопировано в буфер обмена!")
        else:
            messagebox.showwarning("Предупреждение", "Нет данных для копирования!")

    # ------------------------------------------------------------------
    # Diff и статистика
    # ------------------------------------------------------------------

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


def main():
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=None,
    )
    logging.getLogger("soc_log_anonymizer").setLevel(logging.INFO)
    root = tk.Tk()
    app = AnonymizerGUI(root)
    # Дополнительная страховка поверх WM_DELETE_WINDOW/_on_close — на
    # случай аварийного завершения процесса, не прошедшего через штатный
    # обработчик закрытия окна.
    atexit.register(lambda: app.anonymizer and app.anonymizer.clear_sensitive_data())
    root.mainloop()


if __name__ == "__main__":
    main()
