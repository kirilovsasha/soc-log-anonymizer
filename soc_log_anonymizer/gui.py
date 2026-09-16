import atexit
import logging
import sys
import threading
import tkinter as tk
from collections import deque
from typing import List, Optional, Tuple

from .anonymizer import SOCLogAnonymizer
from .config import AnonymizerConfig, find_default_config_path
from .crash import configure_file_logging, install_crash_handler
from .dpi import enable_dpi_awareness
from .gui_chrome_mixin import GuiChromeMixin
from .gui_config_mixin import GuiConfigMixin
from .gui_constants import DEFAULT_FONT_SIZE, UNDO_HISTORY_SIZE
from .gui_diff_mixin import GuiDiffMixin
from .gui_files_mixin import GuiFilesMixin
from .gui_layout import build_main_ui
from .gui_mapping_mixin import GuiMappingMixin
from .gui_process_mixin import GuiProcessMixin
from .gui_state_mixin import GuiStateMixin
from .paths import draft_path_for_pid, gui_state_path, is_portable_mode

logger = logging.getLogger("soc_log_anonymizer")


class AnonymizerGUI(
    GuiStateMixin,
    GuiChromeMixin,
    GuiConfigMixin,
    GuiFilesMixin,
    GuiProcessMixin,
    GuiDiffMixin,
    GuiMappingMixin,
):
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOC Log Anonymizer")
        self.root.geometry("1440x960")
        self.root.minsize(1000, 700)
        self._portable = is_portable_mode()
        self._gui_state_path = gui_state_path(self._portable)
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
        # Large-file mode: keep full text off-widget; write *.anon.log on finish.
        self._prefer_sidecar = False
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

        # Тема и размер шрифта (сохраняются в gui_state)
        self.dark_mode = tk.BooleanVar(value=False)
        self.font_size = tk.IntVar(value=DEFAULT_FONT_SIZE)
        self.sync_scroll_var = tk.BooleanVar(value=True)
        self.result_format = tk.StringVar(value="text")
        self.autosave_drafts = tk.BooleanVar(
            value=bool(self._gui_state.get("autosave_drafts", True))
        )
        self.portable_mode_var = tk.BooleanVar(value=self._portable)
        self.auto_sidecar_large = tk.BooleanVar(
            value=bool(self._gui_state.get("auto_sidecar_large", True))
        )

        # Путь автосохранения черновика ввода (см. _schedule_autosave) —
        # уникален для процесса; каталог — Local AppData (или portable data/).
        self._autosave_path = draft_path_for_pid(portable=self._portable)
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

        self._add_placeholder(self.entry_salt, "случайная строка…")
        self._add_placeholder(self.txt_input, "Вставьте лог сюда или нажмите «Открыть» (Ctrl+O)…")

        self._bind_hotkeys()
        self._reset_session_timer()
        self._offer_draft_recovery()
        self._schedule_autosave()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        build_main_ui(self)


def main():
    enable_dpi_awareness()
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=None,
    )
    logging.getLogger("soc_log_anonymizer").setLevel(logging.INFO)
    log_path = configure_file_logging()
    install_crash_handler()
    logger.info("GUI starting; crash/error log: %s", log_path)

    root = tk.Tk()
    app = AnonymizerGUI(root)
    # Дополнительная страховка поверх WM_DELETE_WINDOW/_on_close — на
    # случай аварийного завершения процесса, не прошедшего через штатный
    # обработчик закрытия окна.
    atexit.register(lambda: app.anonymizer and app.anonymizer.clear_sensitive_data())
    root.mainloop()


if __name__ == "__main__":
    main()
