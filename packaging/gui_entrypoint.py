"""Точка входа для автономной PyInstaller-сборки GUI."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soc_log_anonymizer.dpi import enable_dpi_awareness  # noqa: E402
from soc_log_anonymizer.crash import install_crash_handler  # noqa: E402

enable_dpi_awareness()
install_crash_handler()

from soc_log_anonymizer.gui import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main() or 0)
