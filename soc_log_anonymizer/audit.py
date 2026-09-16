"""Структурированный аудиторский журнал операций.

Не путать с обычным логом приложения через `logging` (который пишет
человекочитаемые сообщения о ходе работы и предупреждения, с ротацией
через `--log-file`, см. cli.py). Этот модуль фиксирует сам ФАКТ и
МЕТРИКИ каждой операции анонимизации/деанонимизации — кто, когда,
сколько значений какого типа заменил, был ли недоволен gatekeeper
(`verify()`) — в машиночитаемом виде (JSON Lines), без единого исходного
значения или псевдонима. Предназначение — комплаенс/аудит использования
самого инструмента ("кто и когда анонимизировал логи инцидента X"), а не
разбор происходящего ВНУТРИ анонимизируемых логов.

Ротация — тем же механизмом, что и `--log-file` (`RotatingFileHandler`
из стандартной библиотеки), чтобы файл не рос неограниченно на
долгоживущем развёртывании; лимиты задаются в конфигурации
(`audit_log_max_bytes`/`audit_log_backup_count`).

Запись аудита не должна ронять основную операцию: любая ошибка записи
(нет прав, диск полон, путь не существует) только логируется через
обычный `logging` и тихо пропускается.
"""
from __future__ import annotations

import getpass
import json
import logging
import logging.handlers
import os
import socket
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from . import __version__

logger = logging.getLogger("soc_log_anonymizer")

# Кэш уже настроенных аудиторских логгеров, по одному на уникальную
# комбинацию (путь, лимиты ротации) — чтобы не создавать новый
# RotatingFileHandler (а значит и не открывать новый файловый дескриптор)
# на каждый вызов log_audit_event. В типичном процессе будет ровно один
# ключ (один audit_log_path на весь запуск), но кэш по ключу — на случай
# смены конфигурации в рамках одного процесса (например, GUI, где конфиг
# можно перезагрузить через "⚙ Конфиг" не перезапуская приложение).
_audit_loggers: Dict[Tuple[str, int, int], logging.Logger] = {}
_audit_loggers_lock = threading.Lock()


def log_audit_event(
    audit_log_path: Optional[str],
    event: Dict[str, Any],
    max_bytes: int = 5_000_000,
    backup_count: int = 5,
) -> None:
    """Дописывает одну JSON-строку в audit_log_path (JSON Lines: один
    объект на строку, удобно для последующего парсинга построчно даже из
    очень большого файла без загрузки его целиком в память).

    Параметры:
        audit_log_path: путь к файлу журнала. None или пустая строка —
            аудит отключён (значение по умолчанию в конфигурации), функция
            в этом случае ничего не делает — это осознанный opt-in, не
            все развёртывания хотят вести такой журнал.
        event: словарь с полями конкретного события (action, org_name,
            stats_by_type и т.п. — см. вызовы в cli.py/gui.py). НЕ должен
            содержать исходные значения, псевдонимы или соль — это
            ответственность вызывающего кода, модуль этого не проверяет.
        max_bytes/backup_count: параметры ротации (см. config.py,
            audit_log_max_bytes/audit_log_backup_count).

    Файл (и файлы ротации audit.log.1, audit.log.2, ...) — с правами
    0600, независимо от umask процесса: `RotatingFileHandler` создаёт
    файлы через обычный `open()`, права которого зависят от umask, в
    отличие от `save_mapping()`/`save_salt()` (которые используют
    `os.open` с явным режимом) — поэтому здесь права фиксируются явным
    `os.chmod` сразу после создания/после каждой ротации."""
    if not audit_log_path:
        return
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_version": __version__,
        "user": _safe_user(),
        "host": _safe_hostname(),
        **event,
    }
    try:
        audit_logger = _get_audit_logger(audit_log_path, max_bytes, backup_count)
        audit_logger.info(json.dumps(record, ensure_ascii=False, sort_keys=True))
        # Могла произойти ротация внутри вызова выше (RotatingFileHandler
        # сам решает, когда) — новый текущий файл создан через open(),
        # чьи права зависят от umask. Фиксируем 0600 после КАЖДОЙ записи:
        # это один дешёвый syscall, зато инвариант "файл всегда 0600"
        # держится независимо от того, произошла ротация именно сейчас.
        _chmod_quiet(audit_log_path)
    except OSError as e:
        logger.warning("Не удалось записать аудиторский журнал %s: %s", audit_log_path, e)


def _get_audit_logger(path: str, max_bytes: int, backup_count: int) -> logging.Logger:
    key = (path, max_bytes, backup_count)
    with _audit_loggers_lock:
        cached = _audit_loggers.get(key)
        if cached is not None:
            return cached

        # Отдельное, специфичное для (пути, лимитов) имя логгера — иначе
        # переиспользование одного и того же имени с РАЗНЫМИ лимитами
        # ротации (гипотетическая смена конфигурации в рамках процесса)
        # привело бы к повторному addHandler на тот же логгер и задвоенным
        # записям. propagate=False — не смешивать с человекочитаемым логом
        # приложения ("soc_log_anonymizer"), это независимый машиночитаемый
        # поток.
        audit_logger = logging.getLogger(f"soc_log_anonymizer.audit.{len(_audit_loggers)}")
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False

        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
        )
        # Только сырой JSON, без стандартных префиксов logging (уровень,
        # имя логгера, время) — timestamp и так есть внутри самой записи.
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(handler)

        _chmod_quiet(path)
        _audit_loggers[key] = audit_logger
        return audit_logger


def _chmod_quiet(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _safe_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"
