import atexit
import base64
import csv
import difflib
import glob
import logging
import os
import secrets
import tempfile
import threading
import tkinter as tk
import webbrowser
from collections import deque
from tkinter import filedialog, messagebox, ttk
from typing import Iterable, List, Optional, Tuple

from .anonymizer import SOCLogAnonymizer
from .audit import log_audit_event
from .config import AnonymizerConfig
from .gui_logic import (
    compute_progress_pct,
    find_context_snippet,
    format_result_status,
    format_size_warning,
    salt_entropy_warning,
    status_style_name,
)
from .io_utils import format_size_mb, read_file_auto_encoding

logger = logging.getLogger("soc_log_anonymizer")

UNDO_HISTORY_SIZE = 10
MIN_FONT_SIZE = 8
MAX_FONT_SIZE = 18
DEFAULT_FONT_SIZE = 10
AUTOSAVE_INTERVAL_MS = 30_000

FONT_UI = "Segoe UI"
FONT_MONO = "Consolas"

PLACEHOLDER_FG = "_placeholder_"  # маркер-состояние, см. _add_placeholder

# ----------------------------------------------------------------------
# Цветовые палитры. Всё темизируемое оформление построено ИСКЛЮЧИТЕЛЬНО
# через именованные ttk.Style — виджет хранит ссылку на ИМЯ стиля
# ("Primary.TButton", "StatusSuccess.TLabel" и т.д.), а не на конкретный
# цвет. Переключение темы = переконфигурация стилей с этими именами
# (_configure_styles), и все виджеты, ссылающиеся на них, обновляются
# автоматически. Это устраняет целый класс багов "часть окна не
# перекрасилась при переключении темы", свойственных ручному обходу
# дерева виджетов и точечной установке bg/fg.
#
# Единственное исключение — tk.Text (у ttk нет многострочного
# редактируемого текстового виджета), его перекрашиваем вручную в
# _configure_styles() при каждом вызове.
# ----------------------------------------------------------------------

PALETTE_LIGHT = {
    "bg": "#eef0f4", "surface": "#ffffff", "surface_alt": "#f5f6fa", "border": "#e1e4ea",
    "text": "#1f2430", "text_secondary": "#6b7280",
    "accent": "#4f46e5", "accent_hover": "#4338ca", "accent_fg": "#ffffff",
    "purple": "#7c3aed", "purple_hover": "#6d28d9",
    "success": "#16a34a", "danger": "#dc2626", "danger_hover": "#b91c1c",
    "warning": "#d97706", "warning_fg": "#3a2a06",
    "input_bg": "#ffffff", "input_fg": "#1f2430",
    "highlight_bg": "#e0e7ff", "highlight_fg": "#3730a3",
    "disabled_bg": "#e5e7eb", "disabled_fg": "#9ca3af",
}

PALETTE_DARK = {
    "bg": "#14161c", "surface": "#1c1f27", "surface_alt": "#20242e", "border": "#2b2f3a",
    "text": "#e5e7eb", "text_secondary": "#9aa0ac",
    "accent": "#6366f1", "accent_hover": "#818cf8", "accent_fg": "#ffffff",
    "purple": "#a78bfa", "purple_hover": "#c4b5fd",
    "success": "#22c55e", "danger": "#f87171", "danger_hover": "#fca5a5",
    "warning": "#fbbf24", "warning_fg": "#3a2a06",
    "input_bg": "#20242e", "input_fg": "#e5e7eb",
    "highlight_bg": "#312e81", "highlight_fg": "#c7d2fe",
    "disabled_bg": "#2b2f3a", "disabled_fg": "#6b7280",
}

# ----------------------------------------------------------------------
# Цвета подсветки псевдонимов ПО ТИПУ данных (IP/EMAIL/USER/SECRET/...),
# вместо одного общего цвета — так в окне результата и в diff'е сразу
# видно не только ЧТО заменено, но и КАКОГО РОДА была замена. Тип
# определяется по префиксу самого псевдонима (см. _pseudonym_type),
# поэтому подсветка работает даже без доступа к исходному значению.
# "VALUE" — цвет для типов без специальной классификации (совпадает со
# старым единым цветом "highlight", ради визуальной преемственности).
# ----------------------------------------------------------------------

TAG_COLORS_LIGHT = {
    "IP":      ("#dbeafe", "#1e40af"),
    "IP_NET":  ("#c7d2fe", "#3730a3"),
    "EMAIL":   ("#dcfce7", "#166534"),
    "USER":    ("#fef9c3", "#854d0e"),
    "FQDN":    ("#ffedd5", "#9a3412"),
    "ORG":     ("#fae8ff", "#86198f"),
    "SID":     ("#e0f2fe", "#075985"),
    "UUID":    ("#f3e8ff", "#6b21a8"),
    "MAC":     ("#fce7f3", "#9d174d"),
    "PHONE":   ("#ccfbf1", "#115e59"),
    "HASH":    ("#e5e7eb", "#374151"),
    "JWT":     ("#fee2e2", "#991b1b"),
    "SECRET":  ("#fecaca", "#7f1d1d"),
    "B64_CMD": ("#fed7aa", "#7c2d12"),
    "VALUE":   ("#e0e7ff", "#3730a3"),
}

TAG_COLORS_DARK = {
    "IP":      ("#1e3a8a", "#bfdbfe"),
    "IP_NET":  ("#312e81", "#c7d2fe"),
    "EMAIL":   ("#14532d", "#bbf7d0"),
    "USER":    ("#713f12", "#fef08a"),
    "FQDN":    ("#7c2d12", "#fed7aa"),
    "ORG":     ("#701a75", "#f5d0fe"),
    "SID":     ("#0c4a6e", "#bae6fd"),
    "UUID":    ("#581c87", "#e9d5ff"),
    "MAC":     ("#831843", "#fbcfe8"),
    "PHONE":   ("#134e4a", "#99f6e4"),
    "HASH":    ("#374151", "#e5e7eb"),
    "JWT":     ("#7f1d1d", "#fecaca"),
    "SECRET":  ("#7f1d1d", "#fca5a5"),
    "B64_CMD": ("#7c2d12", "#fdba74"),
    "VALUE":   ("#312e81", "#c7d2fe"),
}

# Отсортировано по убыванию длины: важно для корректного разбора префикса
# псевдонима вида "[IP_NET_ab12cd34]" — без сортировки "IP" совпал бы
# раньше "IP_NET" и тип определился бы неверно.
_PSEUDONYM_TYPE_PREFIXES = sorted(TAG_COLORS_LIGHT.keys(), key=len, reverse=True)
HIGHLIGHT_TAG_NAMES = [f"hl_{t}" for t in TAG_COLORS_LIGHT]


def _pseudonym_type(pseudo: str) -> str:
    """Определяет тип псевдонима по его префиксу: "[EMAIL_ab12cd34ef56]"
    -> "EMAIL", "[IP_NET_...]" -> "IP_NET". Неизвестный/нестандартный
    формат (например, из mapping-файла старой версии инструмента) даёт
    безопасный fallback "VALUE"."""
    inner = pseudo.strip("[]")
    for prefix in _PSEUDONYM_TYPE_PREFIXES:
        if inner == prefix or inner.startswith(prefix + "_"):
            return prefix
    return "VALUE"

# Статусные "чипы" (badge) для status_label: имя_состояния -> (фон, текст).
# Определяются относительно палитры в _configure_styles().
_STATUS_KINDS = ("Idle", "Info", "Success", "Danger", "Warning", "Purple", "Muted")

# Иконки для кнопок и меток — сознательно ограничены НАБОРОМ ОДИНОЧНЫХ
# кодовых точек с эмодзи-представлением по умолчанию (без ZWJ-последова-
# тельностей и без вариационного селектора U+FE0F). Составные/VS16-эмодзи
# (например "🗺️", "⚙️", "⚠️") на части шрифтов Windows рендерятся
# непредсказуемо — то как два глифа, то как "квадратик", из-за чего
# tk-виджет неверно считает ширину контента и обрезает подпись кнопки.
ICON_OPEN = "📁"
ICON_RUN = "⚡"
ICON_DEANON = "🔄"
ICON_UNDO = "↩"
ICON_COPY = "📋"
ICON_SAVE = "💾"
ICON_DIFF = "🔀"
ICON_STATS = "📊"
ICON_CLEAR = "🗑"
ICON_DICE = "🎲"
ICON_GEAR = "⚙"
ICON_MOON = "🌙"
ICON_SEARCH = "🔍"
ICON_EXPORT = "📤"
ICON_LOCK = "🔐"
ICON_WARN = "⚠"
ICON_TAB_LOG = "📄"
ICON_TAB_MAP = "🗂"


class AnonymizerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOC Log Anonymizer")
        self.root.geometry("1360x900")
        self.root.minsize(1040, 680)

        # self.anonymizer создаётся и переприсваивается ТОЛЬКО в главном
        # потоке, чтобы исключить гонку между фоновым потоком обработки и
        # обработчиками кнопок GUI.
        self.config = AnonymizerConfig()
        self.anonymizer: Optional[SOCLogAnonymizer] = SOCLogAnonymizer(config=self.config)

        # История для отмены последней операции (undo)
        self._undo_stack: deque = deque(maxlen=UNDO_HISTORY_SIZE)

        # Таймер автоочистки сессии по бездействию
        self._session_timer: Optional[threading.Timer] = None

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

        self._set_window_icon()
        self._configure_styles()  # стили нужны ДО построения виджетов
        self._build_ui()
        self._configure_styles()  # второй проход — раскрашивает уже созданные tk.Text

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
            if is_text_widget:
                widget.delete("1.0", tk.END)
            else:
                widget.delete(0, tk.END)

        def _show_placeholder():
            if _get().strip():
                return
            widget._is_placeholder = True
            if is_text_widget:
                widget.insert("1.0", text)
                widget.configure(fg=muted)
            else:
                widget.insert(0, text)
                widget.configure(foreground=muted)

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
        self.root.bind_all("<Control-o>", lambda e: self.open_file())
        self.root.bind_all("<Control-Return>", lambda e: self.start_processing_thread())
        self.root.bind_all("<Control-z>", lambda e: self.undo_last())

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

    def _apply_theme(self):
        self._configure_styles()

    def _apply_font_size(self):
        size = self.font_size.get()
        self.txt_input.configure(font=(FONT_MONO, size))
        self.txt_output.configure(font=(FONT_MONO, size))

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
        main = ttk.Frame(self.root, style="App.TFrame")
        main.pack(fill=tk.BOTH, expand=True)

        # ---------------- Панель инструментов ----------------
        toolbar_outer, toolbar = self._card(main)
        toolbar_outer.pack(fill=tk.X, padx=12, pady=(12, 8))

        actions_row = ttk.Frame(toolbar, style="Card.TFrame")
        actions_row.pack(fill=tk.X, padx=14, pady=(14, 8))

        self.btn_open = ttk.Button(actions_row, text=f"{ICON_OPEN}  Открыть", style="Ghost.TButton",
                                    command=self.open_file)
        self.btn_open.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_process = ttk.Button(actions_row, text=f"{ICON_RUN}  Анонимизировать", style="Primary.TButton",
                                       command=self.start_processing_thread)
        self.btn_process.pack(side=tk.LEFT, padx=6)

        self.btn_deanonymize = ttk.Button(actions_row, text=f"{ICON_DEANON}  Де-анонимизировать",
                                           style="Purple.TButton", command=self.deanonymize_text)
        self.btn_deanonymize.pack(side=tk.LEFT, padx=6)

        self.btn_undo = ttk.Button(actions_row, text=f"{ICON_UNDO}  Отменить", style="Ghost.TButton",
                                    command=self.undo_last, state=tk.DISABLED)
        self.btn_undo.pack(side=tk.LEFT, padx=6)

        ttk.Separator(actions_row, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=2)

        ttk.Button(actions_row, text=f"{ICON_COPY}  Копировать", style="Ghost.TButton",
                   command=self.copy_result).pack(side=tk.LEFT, padx=6)
        ttk.Button(actions_row, text=f"{ICON_SAVE}  Сохранить", style="Ghost.TButton",
                   command=self.save_file).pack(side=tk.LEFT, padx=6)
        ttk.Button(actions_row, text=f"{ICON_DIFF}  HTML Diff отчёт", style="Ghost.TButton",
                   command=self.export_diff_html).pack(side=tk.LEFT, padx=6)
        ttk.Button(actions_row, text=f"{ICON_STATS}  Статистика", style="Ghost.TButton",
                   command=self.show_stats).pack(side=tk.LEFT, padx=6)

        ttk.Separator(actions_row, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=2)

        ttk.Button(actions_row, text=f"{ICON_CLEAR}  Очистить всё", style="Danger.TButton",
                   command=self.clear_all).pack(side=tk.LEFT, padx=6)

        ttk.Separator(toolbar, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=14)

        settings_row = ttk.Frame(toolbar, style="Card.TFrame")
        settings_row.pack(fill=tk.X, padx=14, pady=(8, 14))

        ttk.Label(settings_row, text="Организация", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self.entry_org = ttk.Entry(settings_row, width=12, font=(FONT_UI, 9))
        self.entry_org.insert(0, self.config.org_name)
        self.entry_org.pack(side=tk.LEFT, padx=(0, 14))

        ttk.Label(settings_row, text="Соль", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self.entry_salt = ttk.Entry(settings_row, width=22, font=(FONT_UI, 9))
        self.entry_salt.insert(0, secrets.token_hex(16))
        self.entry_salt.pack(side=tk.LEFT)
        # Живая проверка энтропии соли: не блокирует ввод, только меняет
        # стиль поля (см. _validate_salt_live).
        vcmd = (self.root.register(self._validate_salt_live), "%P")
        self.entry_salt.configure(validate="key", validatecommand=vcmd)

        ttk.Button(settings_row, text=ICON_DICE, style="IconGhost.TButton", width=3,
                   command=self.generate_new_salt).pack(side=tk.LEFT, padx=(4, 14))

        ttk.Button(settings_row, text=f"{ICON_GEAR}  Конфиг", style="Ghost.TButton",
                   command=self.load_config_file).pack(side=tk.LEFT, padx=(0, 14))

        self.dark_mode_chk = ttk.Checkbutton(settings_row, text=f"{ICON_MOON} Тёмная тема",
                                              variable=self.dark_mode, command=self._apply_theme)
        self.dark_mode_chk.pack(side=tk.LEFT, padx=(0, 14))

        ttk.Label(settings_row, text="Шрифт", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 4))
        spin_font = ttk.Spinbox(settings_row, from_=MIN_FONT_SIZE, to=MAX_FONT_SIZE, width=3,
                                 textvariable=self.font_size, command=self._apply_font_size)
        spin_font.pack(side=tk.LEFT, padx=(0, 14))

        self.sync_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_row, text="Синхронный скролл", variable=self.sync_scroll_var
                         ).pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(settings_row, orient=tk.HORIZONTAL, length=130,
                                         mode="determinate", style="TProgressbar")
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))

        self.status_label = ttk.Label(settings_row, text="Готов к работе", style="StatusIdle.TLabel")
        self.status_label.pack(side=tk.RIGHT)

        # ---------------- Вкладки ----------------
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        tab_logs = ttk.Frame(self.notebook, style="App.TFrame")
        self.notebook.add(tab_logs, text=f"{ICON_TAB_LOG}  Редактор логов")

        tab_mapping = ttk.Frame(self.notebook, style="App.TFrame")
        self.notebook.add(tab_mapping, text=f"{ICON_TAB_MAP}  Таблица соответствия")

        # --- Вкладка "Редактор логов" ---
        paned = ttk.PanedWindow(tab_logs, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left_outer, left_card = self._card(paned)
        ttk.Label(left_card, text="Исходные логи / Ответ LLM (Input)", style="Heading.TLabel"
                  ).pack(anchor="w", padx=12, pady=(10, 4))
        self.txt_input, self.v_scroll_left, _ = self._create_scrolled_text(
            left_card, lambda first, last: self._sync_yscroll(self.v_scroll_left, (self.txt_output,), first, last))
        self.txt_input.bind("<Motion>", self._on_input_motion)
        self.txt_input.bind("<Leave>", lambda e: self._hide_tooltip())
        paned.add(left_outer, weight=1)

        right_outer, right_card = self._card(paned)
        ttk.Label(right_card, text="Результат (Output)", style="Heading.TLabel"
                  ).pack(anchor="w", padx=12, pady=(10, 4))
        self.txt_output, self.v_scroll_right, _ = self._create_scrolled_text(
            right_card, lambda first, last: self._sync_yscroll(self.v_scroll_right, (self.txt_input,), first, last))
        paned.add(right_outer, weight=1)

        # --- Вкладка "Таблица соответствия" ---
        search_outer, search_card = self._card(tab_mapping)
        search_outer.pack(fill=tk.X, padx=8, pady=(8, 6))

        search_row = ttk.Frame(search_card, style="Card.TFrame")
        search_row.pack(fill=tk.X, padx=12, pady=10)

        ttk.Label(search_row, text=f"{ICON_SEARCH}  Поиск", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self.entry_search = ttk.Entry(search_row, width=28, font=(FONT_UI, 9))
        self.entry_search.pack(side=tk.LEFT)
        self.entry_search.bind("<KeyRelease>", self.filter_mapping_table)

        ttk.Button(search_row, text=f"{ICON_LOCK}  Экспорт JSON (mapping)", style="Ghost.TButton",
                   command=self.export_mapping_json).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(search_row, text=f"{ICON_EXPORT}  Экспорт CSV", style="Ghost.TButton",
                   command=self.export_mapping_csv).pack(side=tk.RIGHT)

        ttk.Label(tab_mapping,
                  text=f"{ICON_WARN}  Эта таблица содержит исходные чувствительные данные. "
                       f"Обращайтесь с ней и с экспортированными файлами так же, как с исходным логом.",
                  style="Banner.TLabel", anchor="w").pack(fill=tk.X, padx=8, pady=(0, 6))

        table_outer, table_card = self._card(tab_mapping)
        table_outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        table_inner = ttk.Frame(table_card, style="Card.TFrame")
        table_inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        self.map_tree = ttk.Treeview(table_inner, columns=("Original", "Pseudonym"),
                                      show="headings", selectmode="browse")
        self.map_tree.heading("Original", text="Оригинальное значение (чувствительные данные)")
        self.map_tree.heading("Pseudonym", text="Псевдоним (safe for LLM)")
        self.map_tree.column("Original", width=450)
        self.map_tree.column("Pseudonym", width=450)

        map_scroll = ttk.Scrollbar(table_inner, orient=tk.VERTICAL, command=self.map_tree.yview)
        self.map_tree.configure(yscroll=map_scroll.set)
        self.map_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        map_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.map_tree.bind("<Motion>", self._on_tree_motion)
        self.map_tree.bind("<Leave>", lambda e: self._hide_tooltip())

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

        h_scroll = ttk.Scrollbar(text_container, orient=tk.HORIZONTAL)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        # yscrollcommand=on_yscroll — стандартный Tkinter-паттерн двусторонней
        # привязки: он вызывается Text-виджетом при ЛЮБОМ изменении видимой
        # области (колесо мыши, стрелки/PageUp/PageDown/Home/End, resize,
        # редактирование текста, а не только программный yview() или
        # перетаскивание самого скроллбара). Именно поэтому синхронизация
        # между input/output строится через него, а не через `command`
        # скроллбара (который срабатывает ТОЛЬКО при взаимодействии с самим
        # скроллбаром и поэтому не ловит скролл колесом мыши/клавиатурой —
        # это и было причиной "не работающего" синхронного скролла).
        txt_widget = tk.Text(text_container, wrap=tk.NONE, font=(FONT_MONO, self.font_size.get()),
                              xscrollcommand=h_scroll.set, yscrollcommand=on_yscroll, undo=True,
                              relief=tk.FLAT, borderwidth=0, highlightthickness=0, padx=8, pady=6)
        txt_widget.pack(fill=tk.BOTH, expand=True)
        h_scroll.config(command=txt_widget.xview)
        v_scroll.config(command=txt_widget.yview)

        return txt_widget, v_scroll, h_scroll

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
            issues = self.config.validate()
            self.entry_org.delete(0, tk.END)
            self.entry_org.insert(0, self.config.org_name)
            self._reset_session_timer()
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
            widget.delete("1.0", tk.END)
            widget.insert(tk.END, content)
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
        file_path = filedialog.askopenfilename(
            filetypes=[("Log files", "*.log *.txt *.json *.cef *.xml *.gz"), ("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            # Для .gz-файлов это размер СЖАТОГО файла на диске — реальный
            # объём после распаковки будет больше (обычно в разы), но
            # получение точного несжатого размера потребовало бы либо
            # распаковки файла целиком, либо ненадёжного чтения ISIZE-
            # трейлера gzip (не работает для файлов >4 ГБ и мультипоточных
            # архивов) — предупреждение по факту консервативнее, чем
            # хотелось бы, но не даёт ложных срабатываний.
            size_mb = format_size_mb(os.path.getsize(file_path))
        except OSError:
            size_mb = 0.0
        if size_mb > self.config.max_input_size_mb:
            proceed = messagebox.askyesno(
                "Большой файл",
                format_size_warning(size_mb, self.config.max_input_size_mb) +
                "\n\nПродолжить загрузку в редактор?"
            )
            if not proceed:
                return

        self.btn_open.config(state=tk.DISABLED)
        self._set_status("Загрузка файла…", "Info")
        threading.Thread(target=self._async_open_file, args=(file_path,), daemon=True).start()

    def _async_open_file(self, file_path: str):
        try:
            content = read_file_auto_encoding(file_path)
            self.root.after(0, self._on_file_loaded, content, None)
        except Exception as e:
            self.root.after(0, self._on_file_loaded, None, e)

    def _on_file_loaded(self, content: Optional[str], error):
        self.btn_open.config(state=tk.NORMAL)
        if error is not None:
            logger.error("Не удалось открыть файл: %s", error)
            messagebox.showerror("Ошибка", f"Не удалось открыть файл: {error}")
            self._set_status("Ошибка загрузки", "Danger")
            return
        self._set_widget_content(self.txt_input, content)
        self._set_status("Файл загружен", "Info")
        logger.info("Файл загружен (%d символов)", len(content or ""))

    def save_file(self):
        result_text = self.txt_output.get("1.0", tk.END).strip()
        if not result_text:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения!")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log *.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(result_text)
                messagebox.showinfo("Успех", "Файл успешно сохранен!")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

    def clear_all(self):
        self.txt_input.delete("1.0", tk.END)
        self.txt_output.delete("1.0", tk.END)
        for item in self.map_tree.get_children():
            self.map_tree.delete(item)
        if self.anonymizer:
            self.anonymizer.clear_sensitive_data()
        self.progress["value"] = 0
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
        # виджет, а дальнейшая построчная подсветка (см.
        # _highlight_original_values) добавляет накладных расходов сверху
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
        self.progress["value"] = 0
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
            self.root.after(0, self._set_progress, 100)
        else:
            lines = raw_text.splitlines(keepends=True)
            total = max(len(lines), 1)
            out_parts = []
            for i, out_line in enumerate(new_anonymizer.anonymize_stream(lines), 1):
                out_parts.append(out_line)
                if i % 25 == 0 or i == total:
                    self.root.after(0, self._set_progress, compute_progress_pct(i, total))
            cleaned_text = "".join(out_parts)

        is_safe, issues = new_anonymizer.verify(cleaned_text)
        self.root.after(0, self._update_ui_after_processing, new_anonymizer, cleaned_text, is_safe, issues)

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
        self.txt_output.insert(tk.END, cleaned_text)
        self._highlight_pseudonyms()
        self._highlight_original_values()
        self.refresh_mapping_table()
        self.btn_process.config(state=tk.NORMAL)
        self.progress["value"] = 100

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

    def undo_last(self):
        if not self._undo_stack:
            return
        prev_anonymizer, prev_output = self._undo_stack.pop()
        self.anonymizer = prev_anonymizer
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert(tk.END, prev_output.rstrip("\n"))
        self._highlight_pseudonyms()
        self._highlight_original_values()
        self.refresh_mapping_table()
        self._set_status("Отменено", "Muted")
        if not self._undo_stack:
            self.btn_undo.config(state=tk.DISABLED)

    def _highlight_pseudonyms(self):
        self._apply_type_highlighting(self.txt_output)

    # Сколько значений mapping_table обрабатывать за один проход event
    # loop в _highlight_original_values_step, прежде чем отдать управление
    # обратно и запланировать продолжение через root.after(0, ...). Число
    # подобрано эмпирически: достаточно крупное, чтобы не создавать
    # избыточное количество callback'ов на обычных логах, но достаточно
    # маленькое, чтобы даже при mapping_table на десятки тысяч уникальных
    # значений GUI не подвисал целиком за один вызов.
    _HIGHLIGHT_BATCH_SIZE = 200

    def _highlight_original_values(self) -> None:
        """Подсвечивает в Input вхождения ИСХОДНЫХ значений, которые были
        заменены при анонимизации — тем же цветом по типу данных, что и
        их псевдонимы в Output (см. _apply_type_highlighting). Это и есть
        "diff" по сути: не отдельная вкладка с +/- строками, а прямая
        подсветка того, что именно поменялось, прямо в паре Input/Output,
        видная сразу после нажатия "Анонимизировать" без каких-либо
        дополнительных действий.

        Работает так же, как _apply_type_highlighting, только ищет по
        ключам mapping_table (оригинал -> псевдоним), а не по ключам
        reverse_mapping (псевдоним -> оригинал) — то есть по буквально
        тому же тексту, что виден в самом Input, без реконструкции.

        Обработка идёт пакетами через root.after (см.
        _highlight_original_values_step) — mapping_table на большом логе
        может содержать тысячи уникальных значений, и последовательные
        widget.search() по всем сразу в один вызов ощутимо подвесили бы
        GUI-поток сразу после успешного завершения (уже асинхронной!)
        анонимизации — обидная потеря отзывчивости прямо там, где
        асинхронность уже была сделана ради неё."""
        widget = self.txt_input
        for tag in HIGHLIGHT_TAG_NAMES:
            widget.tag_remove(tag, "1.0", tk.END)
        if not self.anonymizer or not self.anonymizer.mapping_table:
            return
        # Длинные значения — первыми: если одно значение является
        # подстрокой другого (например IP "10.0.0.5" внутри "10.0.0.50"),
        # то без сортировки короткое значение "случайно" подсветило бы
        # начало длинного при независимом проходе. Не критично (оба и так
        # получили бы верный тег по своему типу), но так результат чище.
        items = sorted(
            ((original, pseudo) for original, pseudo in self.anonymizer.mapping_table.items() if original),
            key=lambda kv: -len(kv[0]),
        )
        self._highlight_original_values_step(iter(items))

    def _highlight_original_values_step(self, items_iter) -> None:
        widget = self.txt_input
        for _ in range(self._HIGHLIGHT_BATCH_SIZE):
            try:
                original, pseudo = next(items_iter)
            except StopIteration:
                return
            tag = f"hl_{_pseudonym_type(pseudo)}"
            start_pos = "1.0"
            while True:
                start_pos = widget.search(original, start_pos, stopindex=tk.END)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(original)}c"
                widget.tag_add(tag, start_pos, end_pos)
                start_pos = end_pos
        # Батч исчерпал лимит, но значения ещё остались — планируем
        # продолжение отдельным проходом event loop, а не рекурсивным
        # вызовом внутри текущего, чтобы GUI успевал перерисовываться и
        # реагировать на ввод между пачками.
        self.root.after(0, self._highlight_original_values_step, items_iter)

    def _apply_type_highlighting(self, widget: tk.Text) -> None:
        """Подсвечивает вхождения псевдонимов в widget цветом, зависящим
        от ТИПА данных (IP/EMAIL/USER/SECRET/...), а не одним общим
        цветом, как раньше — тип разбирается из самого текста псевдонима
        (см. _pseudonym_type). Используется для окна результата
        (см. _highlight_pseudonyms); симметричный метод для окна с
        исходным текстом — _highlight_original_values."""
        for tag in HIGHLIGHT_TAG_NAMES:
            widget.tag_remove(tag, "1.0", tk.END)
        if not self.anonymizer or not self.anonymizer.reverse_mapping:
            return
        for pseudo in self.anonymizer.reverse_mapping.keys():
            tag = f"hl_{_pseudonym_type(pseudo)}"
            start_pos = "1.0"
            while True:
                start_pos = widget.search(pseudo, start_pos, stopindex=tk.END)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(pseudo)}c"
                widget.tag_add(tag, start_pos, end_pos)
                start_pos = end_pos

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
        self._reset_session_timer()
        self._set_status("Де-анонимизировано", "Purple")
        log_audit_event(self.anonymizer.config.audit_log_path, {
            "action": "deanonymize",
            "source": "gui",
            "unique_values_available": len(self.anonymizer.reverse_mapping),
        }, max_bytes=self.anonymizer.config.audit_log_max_bytes, backup_count=self.anonymizer.config.audit_log_backup_count)

    # ------------------------------------------------------------------
    # Таблица соответствия
    # ------------------------------------------------------------------

    def refresh_mapping_table(self):
        for item in self.map_tree.get_children():
            self.map_tree.delete(item)
        if self.anonymizer and self.anonymizer.mapping_table:
            for orig, pseudo in self.anonymizer.mapping_table.items():
                self.map_tree.insert("", tk.END, values=(orig, pseudo))

    def filter_mapping_table(self, event=None):
        query = self.entry_search.get().strip().lower()
        for item in self.map_tree.get_children():
            self.map_tree.delete(item)
        if self.anonymizer and self.anonymizer.mapping_table:
            for orig, pseudo in self.anonymizer.mapping_table.items():
                if query in orig.lower() or query in pseudo.lower():
                    self.map_tree.insert("", tk.END, values=(orig, pseudo))

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
        result_text = self.txt_output.get("1.0", tk.END).strip()
        if result_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(result_text)
            messagebox.showinfo("Успех", "Скопировано в буфер обмена!")
        else:
            messagebox.showwarning("Предупреждение", "Нет данных для копирования!")

    # ------------------------------------------------------------------
    # Diff и статистика
    # ------------------------------------------------------------------

    def export_diff_html(self):
        """Экспорт diff'а в отдельный HTML-файл — для тех случаев, когда
        его нужно отправить коллеге или распечатать, а не просто
        посмотреть во встроенной вкладке. Файл содержит исходные
        чувствительные данные наравне с анонимизированными — обращайтесь
        с ним так же, как с исходным логом."""
        original = self._text_value(self.txt_input)
        cleaned = self.txt_output.get("1.0", tk.END)
        if not original.strip() or not cleaned.strip():
            messagebox.showwarning("Предупреждение", "Нужны и исходный текст, и результат анонимизации!")
            return
        if not self._confirm_sensitive_export():
            return

        html_diff = difflib.HtmlDiff(wrapcolumn=100)
        html = html_diff.make_file(
            original.splitlines(), cleaned.splitlines(),
            fromdesc="Исходный текст", todesc="После анонимизации", context=True, numlines=3
        )
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
                os.chmod(f.name, 0o600)
                f.write(html)
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
