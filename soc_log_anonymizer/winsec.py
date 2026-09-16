"""Ограничение доступа к чувствительным файлам на Windows (ACL) и POSIX (0600).

Только стандартная библиотека: subprocess + icacls на Windows.
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess
from typing import Optional

logger = logging.getLogger("soc_log_anonymizer")


def restrict_sensitive_file(path: str) -> Optional[str]:
    """Ограничивает чтение файла текущим пользователем.

    На POSIX: chmod 0600.
    На Windows: icacls /inheritance:r + grant (R) только текущему пользователю.

    Возвращает текст предупреждения при частичном/неудачном ограничении,
    иначе None. Не бросает исключений при сбое ACL (файл уже записан).
    """
    if not path or not os.path.isfile(path):
        return None
    if os.name == "nt":
        return _restrict_windows_acl(path)
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        return f"Не удалось выставить chmod 600 для {path}: {exc}"
    return None


def _restrict_windows_acl(path: str) -> Optional[str]:
    """Сбрасывает наследование и даёт доступ только текущему пользователю."""
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if not user:
        return (
            f"Не удалось ограничить ACL для {path}: неизвестен USERNAME. "
            "Не храните salt/mapping на общем диске без шифрования."
        )
    # icacls принимает пути с пробелами в кавычках; grant для DOMAIN\\user
    # на рабочих станциях обычно достаточно имени пользователя.
    commands = [
        ["icacls", path, "/inheritance:r"],
        ["icacls", path, "/grant:r", f"{user}:(R,W)"],
    ]
    for cmd in commands:
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return (
                f"Не удалось ограничить ACL для {path} ({exc}). "
                "Не кладите salt/mapping на общий диск / в OneDrive без шифрования."
            )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            return (
                f"icacls не смог ограничить {path}"
                + (f": {detail}" if detail else "")
                + ". Не кладите salt/mapping на общий диск без шифрования."
            )
    return None


def check_world_readable(file_path: str) -> Optional[str]:
    """Предупреждение, если чувствительный файл доступен шире, чем нужно."""
    if not file_path or not os.path.isfile(file_path):
        return None
    if os.name == "nt":
        return _check_windows_acl_hint(file_path)
    try:
        mode = os.stat(file_path).st_mode
    except OSError:
        return None
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        return (
            f"Файл {file_path} доступен на чтение другим пользователям системы "
            f"(рекомендуется chmod 600 {file_path}) — он может содержать соль "
            f"или таблицу деанонимизации."
        )
    return None


def _check_windows_acl_hint(file_path: str) -> Optional[str]:
    """Грубая проверка через icacls: если в выводе есть Everyone/Users с (R) — предупреждаем."""
    try:
        completed = subprocess.run(
            ["icacls", file_path],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    text = (completed.stdout or "").lower()
    risky_tokens = (
        "everyone:(",
        "everyone:(r",
        "\\users:(",
        "authenticated users:(",
        "builtin\\users:(",
    )
    if any(token in text for token in risky_tokens):
        return (
            f"Файл {file_path} может быть доступен другим пользователям Windows "
            "(ACL). Рекомендуется хранить salt/mapping только в профиле "
            "пользователя и не синхронизировать их в OneDrive/общий диск без шифрования."
        )
    return None
