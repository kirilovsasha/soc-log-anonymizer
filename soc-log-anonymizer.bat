@echo off
chcp 65001 >nul
rem =====================================================================
rem  SOC Log Anonymizer - CLI-обёртка для Windows
rem
rem  Использование (из cmd.exe или PowerShell), например:
rem    soc-log-anonymizer.bat anonymize -i raw.log -o clean.log --salt-file salt.txt
rem    soc-log-anonymizer.bat deanonymize -i response.txt --mapping mapping.json
rem    soc-log-anonymizer.bat batch --input-dir logs --output-dir clean_logs
rem    soc-log-anonymizer.bat validate-config myconfig.json
rem    soc-log-anonymizer.bat            (без аргументов -> запуск GUI)
rem
rem  Совет: добавьте каталог проекта в PATH, чтобы вызывать команду
rem  soc-log-anonymizer из любого места, либо создайте ярлык на этот файл.
rem =====================================================================
setlocal
cd /d "%~dp0"

set "PYEXE="
where python >nul 2>nul && set "PYEXE=python"
if not defined PYEXE (
    where py >nul 2>nul && set "PYEXE=py -3"
)

if not defined PYEXE (
    echo.
    echo [ОШИБКА] Python не найден в PATH.
    echo Установите Python 3.8+ с https://www.python.org/downloads/
    echo При установке обязательно отметьте галочку "Add python.exe to PATH".
    echo.
    exit /b 1
)

%PYEXE% -m soc_log_anonymizer %*
exit /b %errorlevel%
