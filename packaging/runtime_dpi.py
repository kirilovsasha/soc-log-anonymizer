"""Runtime hook: enable DPI awareness before tkinter starts (Windows)."""

try:
    from soc_log_anonymizer.dpi import enable_dpi_awareness
    enable_dpi_awareness()
except Exception:
    pass
