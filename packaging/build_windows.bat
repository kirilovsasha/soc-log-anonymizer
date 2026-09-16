@echo off
setlocal EnableExtensions
rem Build standalone Windows onefile EXE (GUI + CLI).
rem One autonomous .exe each — no Python required on the target PC.
rem Run from repository root. Requires: pip install pyinstaller

cd /d "%~dp0\.."

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] python not found in PATH
  exit /b 1
)

python -m pip install -U pip pyinstaller
if errorlevel 1 exit /b 1

echo === Building GUI (onefile) ===
python -m PyInstaller --noconfirm --clean packaging\soc_log_anonymizer_gui_onefile.spec
if errorlevel 1 exit /b 1

echo === Building CLI (onefile) ===
python -m PyInstaller --noconfirm --clean packaging\soc_log_anonymizer_cli_onefile.spec
if errorlevel 1 exit /b 1

rem Sample config next to the exe (auto-discovered as soc_log_anonymizer.json).
if exist "packaging\default_config.json" (
  copy /Y "packaging\default_config.json" "dist\soc_log_anonymizer.json" >nul
)

echo.
echo Done. Autonomous single-file builds:
echo   GUI: dist\soc-log-anonymizer-gui.exe
echo   CLI: dist\soc-log-anonymizer-cli.exe
echo   Config sample: dist\soc_log_anonymizer.json  ^(put next to the exe^)
echo.
echo Tip: create portable.flag next to the exe for USB/portable data layout.
echo Tip: for SmartScreen, Authenticode-sign the exe (see docs\WINDOWS_EXE.md).
echo.
echo Optional onedir folder builds still available via:
echo   packaging\soc_log_anonymizer_gui.spec
echo   packaging\soc_log_anonymizer_cli.spec
exit /b 0
