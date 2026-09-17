"""Чтение Windows Event Log (.evtx) через штатный wevtutil.

Только стандартная библиотека. На не-Windows .evtx открыть нельзя — нет
wevtutil. GUI не мигает консолью (CREATE_NO_WINDOW), как и icacls.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from typing import List, Optional

from .winsec import windows_hidden_run_kwargs

logger = logging.getLogger("soc_log_anonymizer")

# ELF/EVTX container signature (not Unix ELF).
EVTX_MAGIC = b"ElfFile\x00"
EVTX_QUERY_TIMEOUT_SECONDS = 240


class EvtxError(ValueError):
    """Не удалось превратить .evtx в текст через wevtutil."""


def is_evtx_file(path: str) -> bool:
    """True, если файл существует и это EVTX (магические байты или .evtx)."""
    if not path or not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as handle:
            magic = handle.read(len(EVTX_MAGIC))
    except OSError:
        return False
    if magic == EVTX_MAGIC:
        return True
    return os.path.splitext(path)[1].lower() == ".evtx"


def find_wevtutil() -> Optional[str]:
    found = shutil.which("wevtutil")
    if found:
        return found
    if os.name == "nt":
        windir = os.environ.get("WINDIR", r"C:\Windows")
        candidate = os.path.join(windir, "System32", "wevtutil.exe")
        if os.path.isfile(candidate):
            return candidate
    return None


def wevtutil_argv(file_path: str, wevtutil: str = "wevtutil") -> List[str]:
    """wevtutil qe <file> как logfile, текст, Unicode — удобно для SOC regex."""
    return [
        wevtutil,
        "qe",
        os.path.abspath(file_path),
        "/lf:true",
        "/f:text",
        "/uni:true",
    ]


def decode_wevtutil_output(raw: bytes) -> str:
    """Декодирует stdout wevtutil (/uni:true часто UTF-16, иногда UTF-8)."""
    from .io_utils import _decode_bytes_auto, _normalize_newlines

    if not raw:
        return ""
    text: Optional[str] = None
    if raw.startswith(b"\xff\xfe"):
        text = raw.decode("utf-16-le", errors="replace")
    elif raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16-be", errors="replace")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw.decode("utf-8-sig", errors="replace")
    elif len(raw) >= 4 and len(raw) % 2 == 0 and raw[1::2].count(0) > len(raw) // 4:
        try:
            text = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            text = None
    if text is None:
        text = _decode_bytes_auto(raw)
    return _normalize_newlines(text)


def read_evtx_text(
    file_path: str,
    *,
    timeout: int = EVTX_QUERY_TIMEOUT_SECONDS,
    runner=None,
) -> str:
    """Экспортирует .evtx в текст через ``wevtutil qe``.

    Raises:
        EvtxError: нет Windows, нет wevtutil, таймаут или ненулевой код.
    """
    if sys.platform != "win32":
        raise EvtxError(
            "Файл Windows Event Log (.evtx) открывается только на Windows "
            "(нужен штатный wevtutil). Сохраните журнал как XML/текст в Event Viewer."
        )
    wevtutil = find_wevtutil()
    if not wevtutil:
        raise EvtxError(
            "wevtutil не найден. Сохраните журнал в Event Viewer как XML или текст."
        )
    argv = wevtutil_argv(file_path, wevtutil=wevtutil)
    logger.info("Конвертация EVTX через wevtutil: %s", file_path)
    run = subprocess.run if runner is None else runner
    try:
        completed = run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            **windows_hidden_run_kwargs(),
        )
    except subprocess.TimeoutExpired as exc:
        raise EvtxError(
            f"wevtutil не успел прочитать {os.path.basename(file_path)} "
            f"за {timeout} с. Экспортируйте XML/текст из Event Viewer "
            "или обработайте меньший фрагмент журнала."
        ) from exc
    except OSError as exc:
        raise EvtxError(f"Не удалось запустить wevtutil: {exc}") from exc

    stdout = completed.stdout or b""
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8", errors="replace")
    stderr = completed.stderr or b""
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", errors="replace")

    if completed.returncode != 0:
        detail = decode_wevtutil_output(stderr).strip() or decode_wevtutil_output(stdout).strip()
        raise EvtxError(
            f"wevtutil не смог прочитать {os.path.basename(file_path)}"
            + (f": {detail}" if detail else "")
        )
    text = decode_wevtutil_output(stdout)
    logger.info("EVTX преобразован в текст (%d символов)", len(text))
    return text
