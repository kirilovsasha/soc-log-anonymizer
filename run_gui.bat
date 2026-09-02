@echo off
chcp 65001 >nul
rem =====================================================================
rem  SOC Log Anonymizer - запуск GUI (двойной клик)
rem
rem  Эта версия ВСЕГДА показывает консоль с диагностикой, чтобы в
rem  случае ошибки вы видели сообщение, а не просто "ничего не
rem  происходит". Если Python в PATH указывает на заглушку Microsoft
rem  Store (частая проблема на новых установках Windows), скрипт это
rem  обнаружит и подскажет, что делать.
rem =====================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo Поиск Python...
set "PYEXE="

where python >nul 2>nul
if %errorlevel%==0 (
    for /f "delims=" %%P in ('where python 2^>nul') do (
        echo %%P | findstr /i "WindowsApps" >nul
        if errorlevel 1 (
            if not defined PYEXE set "PYEXE=python"
        )
    )
)

if not defined PYEXE (
    where py >nul 2>nul
    if %errorlevel%==0 set "PYEXE=py -3"
)

if not defined PYEXE (
    echo.
    echo [ОШИБКА] Подходящий Python не найден в PATH.
    echo.
    echo Если команда "python" в PowerShell/cmd открывает Microsoft Store —
    echo значит в PATH только заглушка Store, а не настоящий Python.
    echo Отключить её: Параметры -^> Приложения -^> Дополнительные параметры
    echo приложений -^> Псевдонимы выполнения приложений -^> выключить python.exe/python3.exe.
    echo.
    echo Установите Python 3.8+ с https://www.python.org/downloads/
    echo и обязательно отметьте галочку "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)

echo Использую интерпретатор: %PYEXE%
echo.
echo --- Проверка версии Python ---
%PYEXE% --version
if errorlevel 1 (
    echo [ОШИБКА] Не удалось запустить %PYEXE%. См. сообщение выше.
    pause
    exit /b 1
)

echo.
echo --- Проверка наличия модуля tkinter ---
%PYEXE% -c "import tkinter" 2>nul
if errorlevel 1 (
    echo [ОШИБКА] В этой установке Python отсутствует модуль tkinter.
    echo Переустановите Python с сайта python.org, ничего не снимая
    echo с выбором компонентов по умолчанию ^(tkinter ставится вместе
    echo с обычным установщиком^).
    pause
    exit /b 1
)

echo OK
echo.
echo --- Запуск GUI ---
%PYEXE% -m soc_log_anonymizer gui
set "EXITCODE=%errorlevel%"

if not "%EXITCODE%"=="0" (
    echo.
    echo [ОШИБКА] Программа завершилась с кодом %EXITCODE%.
    echo Сообщение об ошибке должно быть выведено выше.
    pause
)

exit /b %EXITCODE%
