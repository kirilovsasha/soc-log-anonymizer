"""Пути данных приложения: portable (рядом с exe) vs installed (AppData).

Только стандартная библиотека. Используется GUI, crash-логом и (опционально)
CLI при frozen-сборке.
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Optional

APP_DIR_NAME = "SOC Log Anonymizer"
PORTABLE_MARKER = "portable.flag"
CRASH_LOG_NAME = "gui_error.log"
GUI_STATE_NAME = "soc_log_anonymizer_gui_state.json"
DRAFTS_SUBDIR = "drafts"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_dir() -> str:
    """Каталог, где лежит запущенное приложение (exe или пакет)."""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def portable_marker_path(base: Optional[str] = None) -> str:
    return os.path.join(base or app_dir(), PORTABLE_MARKER)


def is_portable_mode(base: Optional[str] = None) -> bool:
    """Portable: рядом с приложением есть portable.flag, либо env SOC_ANON_PORTABLE=1."""
    env = os.environ.get("SOC_ANON_PORTABLE", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    if env in {"0", "false", "no", "off"}:
        return False
    return os.path.isfile(portable_marker_path(base))


def set_portable_mode(enabled: bool, base: Optional[str] = None) -> str:
    """Создаёт или удаляет portable.flag рядом с приложением. Возвращает путь маркера."""
    path = portable_marker_path(base)
    if enabled:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "SOC Log Anonymizer portable mode\n"
                "State, drafts and crash log are stored next to this executable.\n"
            )
    elif os.path.isfile(path):
        os.remove(path)
    return path


def _roaming_appdata() -> str:
    if sys.platform == "win32":
        root = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        root = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
            os.path.expanduser("~"), ".config"
        )
    return os.path.join(root, APP_DIR_NAME)


def _local_appdata() -> str:
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        root = os.environ.get("XDG_STATE_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "state"
        )
    return os.path.join(root, APP_DIR_NAME)


def user_data_dir(portable: Optional[bool] = None) -> str:
    """Каталог настроек/состояния (Roaming AppData или рядом с exe)."""
    if portable is None:
        portable = is_portable_mode()
    if portable:
        return app_dir()
    return _roaming_appdata()


def user_cache_dir(portable: Optional[bool] = None) -> str:
    """Каталог черновиков/кэша (Local AppData или рядом с exe)."""
    if portable is None:
        portable = is_portable_mode()
    if portable:
        return os.path.join(app_dir(), "data")
    return _local_appdata()


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def gui_state_path(portable: Optional[bool] = None) -> str:
    return os.path.join(user_data_dir(portable), GUI_STATE_NAME)


def crash_log_path(portable: Optional[bool] = None) -> str:
    return os.path.join(user_data_dir(portable), CRASH_LOG_NAME)


def drafts_dir(portable: Optional[bool] = None) -> str:
    return os.path.join(user_cache_dir(portable), DRAFTS_SUBDIR)


def draft_path_for_pid(pid: Optional[int] = None, portable: Optional[bool] = None) -> str:
    ensure_dir(drafts_dir(portable))
    return os.path.join(drafts_dir(portable), f"soc_log_anonymizer_draft_{pid or os.getpid()}.txt")


def open_in_file_manager(path: str) -> None:
    """Открывает файл или каталог в проводнике ОС."""
    target = path if os.path.exists(path) else os.path.dirname(path) or path
    if not os.path.exists(target):
        ensure_dir(target)
    if sys.platform == "win32":
        os.startfile(target)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        os.system(f'open "{target}"')
    else:
        os.system(f'xdg-open "{target}"')


def temp_fallback_dir() -> str:
    return tempfile.gettempdir()
