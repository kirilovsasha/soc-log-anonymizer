"""Windows DPI awareness for sharper tkinter on HiDPI displays."""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger("soc_log_anonymizer")


def enable_dpi_awareness() -> None:
    """Best-effort SetProcessDpiAwareness / SetProcessDPIAware before Tk starts."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # Per-monitor V2 (Windows 10 1703+); fall back to system DPI aware.
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
            return
        except (AttributeError, OSError):
            pass
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError) as exc:
            logger.debug("DPI awareness not set: %s", exc)
    except Exception as exc:
        logger.debug("DPI awareness failed: %s", exc)
