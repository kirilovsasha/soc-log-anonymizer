@echo off
chcp 65001 >nul
rem =====================================================================
rem  SOC Log Anonymizer - первичная установка на Windows (опционально)
rem
rem  Создаёт виртуальное окружение .venv в каталоге проекта и
rem  устанавливает пакет в него через "pip install -e .". Это НЕ
rem  обязательный шаг: run_gui.bat и soc-log-anonymizer.bat работают и
rem  без установки, напрямую через системный python. Используйте этот
rem  скрипт, если хотите изолированное окружение или команду
rem  soc-log-anonymizer в PATH venv'а.
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
    pause
    exit /b 1
)

echo Создаю виртуальное окружение .venv ...
%PYEXE% -m venv .venv
if errorlevel 1 (
    echo [ОШИБКА] Не удалось создать виртуальное окружение.
    pause
    exit /b 1
)

echo Устанавливаю пакет (только стандартная библиотека, зависимостей нет) ...
call ".venv\Scripts\python.exe" -m pip install --upgrade pip
call ".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 (
    echo [ОШИБКА] Установка пакета не удалась.
    pause
    exit /b 1
)

echo.
echo Готово. Запуск:
echo   .venv\Scripts\soc-log-anonymizer.exe            (GUI)
echo   .venv\Scripts\soc-log-anonymizer.exe anonymize ... (CLI)
echo.
pause
