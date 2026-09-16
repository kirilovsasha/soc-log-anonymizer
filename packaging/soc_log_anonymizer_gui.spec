# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller-спека для автономной сборки GUI (см. README, раздел
"Установка" -> "Вариант 4"). Собирает --onefile бинарник, не требующий
установленного Python у получателя.

Использование (из корня репозитория):

    pip install pyinstaller
    pyinstaller packaging/soc_log_anonymizer_gui.spec

Результат: dist/soc-log-anonymizer-gui (Linux/macOS) или
dist/soc-log-anonymizer-gui.exe (Windows).

Собирать нужно отдельно на каждой целевой ОС — PyInstaller не
кросс-компилирует (сборка на Linux даёт Linux-бинарник и т.д.).

Пакет не имеет внешних зависимостей (только стандартная библиотека
Python, включая tkinter), поэтому спека намеренно простая — никаких
hiddenimports для сторонних библиотек не требуется. `tkinter` и его
данные (Tcl/Tk) PyInstaller подхватывает автоматически при наличии
рабочей установки Python с tkinter на машине сборки (см. README:
`sudo apt install python3-tk` и т.п. на Linux, если ещё не установлен).
"""

import sys
from pathlib import Path

block_cipher = None

# Корень репозитория — эта спека лежит в packaging/, репозиторий на
# уровень выше.
REPO_ROOT = Path(SPECPATH).resolve().parent

a = Analysis(
    [str(REPO_ROOT / "packaging" / "gui_entrypoint.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[
        # tkinter.ttk импортируется через `from tkinter import ttk` в
        # gui.py — обычно PyInstaller находит его сам через анализ
        # байткода, но перечисление явно чуть надёжнее на некоторых
        # платформах/сборках Python, где неявный анализ импортов ttk
        # исторически иногда промахивался.
        "tkinter",
        "tkinter.ttk",
        "tkinter.filedialog",
        "tkinter.messagebox",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Пакет не использует эти модули; явное исключение немного
        # уменьшает размер бинарника, если они случайно затянутся как
        # транзитивные зависимости самого PyInstaller/Python на машине
        # сборки.
        "test",
        "unittest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="soc-log-anonymizer-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-сжатие иногда триггерит антивирусы ложными срабатываниями на Windows
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI-приложение — без консольного окна на Windows/macOS
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
