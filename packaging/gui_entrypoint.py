"""Точка входа для автономной PyInstaller-сборки GUI.

Не часть публичного API пакета — используется только как `--onefile`
скрипт для `pyinstaller` (см. `packaging/soc_log_anonymizer_gui.spec`).
Обычный запуск (`python -m soc_log_anonymizer`, `pip install -e .`)
использует `soc_log_anonymizer/__main__.py` и `soc_log_anonymizer/gui.py`
напрямую — этот файл их не заменяет и не дублирует логику, только
вызывает существующую точку входа.
"""
import sys
from pathlib import Path

# Позволяет запускать `pyinstaller packaging/soc_log_anonymizer_gui.spec`
# из корня репозитория без предварительной установки пакета (добавляет
# корень репозитория в sys.path, чтобы `import soc_log_anonymizer` нашёл
# исходники рядом, а не требовал `pip install`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soc_log_anonymizer.gui import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main() or 0)
