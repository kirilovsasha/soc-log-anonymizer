# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller --onedir GUI build (default for Windows distribution).

Faster cold start than onefile: no extract-to-%TEMP% on every launch.

Usage (repo root):

    packaging\\build_windows.bat
    # or: pyinstaller packaging/soc_log_anonymizer_gui.spec

Result: dist/soc-log-anonymizer-gui/soc-log-anonymizer-gui.exe
"""

from pathlib import Path

block_cipher = None
REPO_ROOT = Path(SPECPATH).resolve().parent
ICON = REPO_ROOT / "packaging" / "icon.ico"
VERSION = REPO_ROOT / "packaging" / "version_info.txt"

a = Analysis(
    [str(REPO_ROOT / "packaging" / "gui_entrypoint.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[
        (str(REPO_ROOT / "packaging" / "default_config.json"), "."),
    ],
    hiddenimports=[
        "tkinter",
        "tkinter.ttk",
        "tkinter.filedialog",
        "tkinter.messagebox",
        "soc_log_anonymizer.gui_theme",
        "soc_log_anonymizer.detectors",
        "soc_log_anonymizer.result",
        "soc_log_anonymizer.structured",
        "soc_log_anonymizer.paths",
        "soc_log_anonymizer.winsec",
        "soc_log_anonymizer.crash",
        "soc_log_anonymizer.dpi",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(REPO_ROOT / "packaging" / "runtime_dpi.py")],
    excludes=["test", "unittest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="soc-log-anonymizer-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON) if ICON.is_file() else None,
    version=str(VERSION) if VERSION.is_file() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="soc-log-anonymizer-gui",
)
