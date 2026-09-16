# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller --onedir CLI build (console=True) for pipelines without Python."""

from pathlib import Path

block_cipher = None
REPO_ROOT = Path(SPECPATH).resolve().parent
ICON = REPO_ROOT / "packaging" / "icon.ico"
VERSION = REPO_ROOT / "packaging" / "version_info_cli.txt"

a = Analysis(
    [str(REPO_ROOT / "packaging" / "cli_entrypoint.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=[
        (str(REPO_ROOT / "packaging" / "default_config.json"), "."),
    ],
    hiddenimports=[
        "soc_log_anonymizer.detectors",
        "soc_log_anonymizer.result",
        "soc_log_anonymizer.structured",
        "soc_log_anonymizer.paths",
        "soc_log_anonymizer.winsec",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["test", "unittest", "tkinter"],
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
    name="soc-log-anonymizer-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
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
    name="soc-log-anonymizer-cli",
)
