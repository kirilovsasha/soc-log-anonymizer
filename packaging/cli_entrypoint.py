"""Точка входа для автономной PyInstaller-сборки CLI (console)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soc_log_anonymizer.__main__ import main  # noqa: E402

if __name__ == "__main__":
    # When launched as bare exe without args, print help instead of opening GUI
    # (GUI has its own binary). Mimic `soc-log-anonymizer --help` for empty argv.
    if len(sys.argv) <= 1:
        sys.argv.append("--help")
    raise SystemExit(main())
