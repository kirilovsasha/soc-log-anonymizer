@echo off
chcp 65001 >nul
rem =====================================================================
rem  SOC Log Anonymizer - запуск GUI БЕЗ окна консоли.
rem
rem  Используйте этот файл только после того, как убедились, что
rem  run_gui.bat (с видимой консолью) запускается без ошибок. Если GUI
rem  всё же не появится, ошибка будет записана в gui_error.log рядом
rem  с этим файлом — откройте его для диагностики.
rem =====================================================================
setlocal
cd /d "%~dp0"

set "PYEXE="
where pythonw >nul 2>nul
if %errorlevel%==0 set "PYEXE=pythonw"

if not defined PYEXE (
    echo [ОШИБКА] pythonw не найден в PATH. Используйте run_gui.bat.
    pause
    exit /b 1
)

del /q gui_error.log >nul 2>nul
start "" /wait %PYEXE% -m soc_log_anonymizer gui 2>gui_error.log
if errorlevel 1 (
    echo [ОШИБКА] Программа завершилась с ошибкой. Подробности в gui_error.log.
    notepad gui_error.log
)
