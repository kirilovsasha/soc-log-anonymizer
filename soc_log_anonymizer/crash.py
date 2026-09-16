"""Глобальный обработчик необработанных исключений для windowed GUI (без консоли)."""

from __future__ import annotations

import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Callable, Optional

from .paths import crash_log_path, ensure_dir, user_data_dir

logger = logging.getLogger("soc_log_anonymizer")


def show_native_error(title: str, message: str) -> None:
    """Показывает ошибку без зависимости от живого Tk mainloop."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
            return
        except Exception:
            pass
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        sys.stderr.write(f"{title}\n{message}\n")


def install_crash_handler(
    *,
    show_message: Optional[Callable[[str, str], None]] = None,
) -> str:
    """Ставит sys.excepthook: пишет traceback в crash-лог и показывает путь.

    Возвращает путь к файлу лога. Безопасно вызывать до создания Tk.
    """
    log_path = crash_log_path()
    ensure_dir(user_data_dir())
    notifier = show_message or show_native_error

    def _hook(exc_type, exc, tb):
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            ensure_dir(user_data_dir())
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"\n===== {stamp} =====\n")
                handle.write(text)
        except OSError as write_err:
            logger.error("Could not write crash log %s: %s", log_path, write_err)
        logger.critical("Unhandled exception:\n%s", text)
        try:
            notifier(
                "Критическая ошибка",
                f"Приложение завершилось с ошибкой.\n\n"
                f"Подробности записаны в:\n{log_path}\n\n"
                f"{exc_type.__name__}: {exc}",
            )
        except Exception:
            pass
        # Keep default stderr behaviour when a console exists.
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook
    return log_path


def configure_file_logging(log_path: Optional[str] = None) -> str:
    """Добавляет FileHandler в логгер приложения (для windowed exe)."""
    path = log_path or crash_log_path()
    ensure_dir(user_data_dir())
    abs_path = os.path.abspath(path)
    root = logging.getLogger("soc_log_anonymizer")
    for existing in root.handlers:
        if getattr(existing, "baseFilename", None) == abs_path:
            return path
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.setLevel(logging.INFO)
    root.addHandler(handler)
    return path
