@echo off
setlocal EnableExtensions
rem Build standalone Windows EXE (GUI + CLI). No Python on the target PC.
rem Run from repository root.
rem
rem Default: --onedir (folder). Starts fast — no extract-to-temp on every launch.
rem
rem Options (any order):
rem   /onefile   single .exe each (convenient to copy, slow cold start + Defender)
rem   /clean     wipe PyInstaller cache before each build
rem   /gui       build GUI only
rem   /cli       build CLI only
rem   /upgrade   force pip upgrade of pyinstaller

cd /d "%~dp0\.."

set "DO_CLEAN="
set "DO_GUI=1"
set "DO_CLI=1"
set "DO_UPGRADE="
set "ONEFILE="
set "ONLY_SET="

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="/clean"   set "DO_CLEAN=1" & shift & goto parse_args
if /I "%~1"=="--clean"  set "DO_CLEAN=1" & shift & goto parse_args
if /I "%~1"=="/onefile" set "ONEFILE=1" & shift & goto parse_args
if /I "%~1"=="/upgrade" set "DO_UPGRADE=1" & shift & goto parse_args
if /I "%~1"=="/gui" (
  if not defined ONLY_SET set "DO_CLI="
  set "ONLY_SET=1"
  set "DO_GUI=1"
  shift & goto parse_args
)
if /I "%~1"=="/cli" (
  if not defined ONLY_SET set "DO_GUI="
  set "ONLY_SET=1"
  set "DO_CLI=1"
  shift & goto parse_args
)
echo [ERROR] Unknown option: %~1
echo Usage: packaging\build_windows.bat [/onefile] [/clean] [/upgrade] [/gui] [/cli]
exit /b 1

:args_done

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] python not found in PATH
  exit /b 1
)

if defined DO_UPGRADE (
  echo === Upgrading pip + PyInstaller ===
  python -m pip install -U pip pyinstaller
  if errorlevel 1 exit /b 1
) else (
  python -c "import PyInstaller" >nul 2>nul
  if errorlevel 1 (
    echo === Installing PyInstaller ===
    python -m pip install pyinstaller
    if errorlevel 1 exit /b 1
  )
)

set "PI_FLAGS=--noconfirm"
if defined DO_CLEAN (
  set "PI_FLAGS=%PI_FLAGS% --clean"
  echo [info] --clean enabled
)

if defined ONEFILE (
  set "GUI_SPEC=packaging\soc_log_anonymizer_gui_onefile.spec"
  set "CLI_SPEC=packaging\soc_log_anonymizer_cli_onefile.spec"
  echo [info] mode: onefile ^(slow cold start under Defender^)
) else (
  set "GUI_SPEC=packaging\soc_log_anonymizer_gui.spec"
  set "CLI_SPEC=packaging\soc_log_anonymizer_cli.spec"
  echo [info] mode: onedir ^(recommended — fast start^)
)

if defined DO_GUI (
  echo === Building GUI ===
  python -m PyInstaller %PI_FLAGS% %GUI_SPEC%
  if errorlevel 1 exit /b 1
)

if defined DO_CLI (
  echo === Building CLI ===
  python -m PyInstaller %PI_FLAGS% %CLI_SPEC%
  if errorlevel 1 exit /b 1
)

rem Sample config next to the exe (auto-discovered as soc_log_anonymizer.json).
if exist "packaging\default_config.json" (
  copy /Y "packaging\default_config.json" "dist\soc_log_anonymizer.json" >nul
  if not defined ONEFILE (
    if exist "dist\soc-log-anonymizer-gui\" copy /Y "packaging\default_config.json" "dist\soc-log-anonymizer-gui\soc_log_anonymizer.json" >nul
    if exist "dist\soc-log-anonymizer-cli\" copy /Y "packaging\default_config.json" "dist\soc-log-anonymizer-cli\soc_log_anonymizer.json" >nul
  )
)

echo.
echo Done.
if defined ONEFILE (
  if defined DO_GUI echo   GUI: dist\soc-log-anonymizer-gui.exe
  if defined DO_CLI echo   CLI: dist\soc-log-anonymizer-cli.exe
) else (
  if defined DO_GUI echo   GUI: dist\soc-log-anonymizer-gui\soc-log-anonymizer-gui.exe
  if defined DO_CLI echo   CLI: dist\soc-log-anonymizer-cli\soc-log-anonymizer-cli.exe
  echo   Distribute the whole folder ^(or zip it^), not only the .exe.
)
echo   Config sample: dist\soc_log_anonymizer.json
echo.
echo Tip: create portable.flag next to the exe for USB/portable data layout.
echo Tip: for SmartScreen, Authenticode-sign the exe (see docs\WINDOWS_EXE.md).
echo Tip: packaging\build_windows.bat /onefile  — single-file build if needed.
exit /b 0
