@echo off
:: =============================================================
::  Akatsuki Clan -- PS4 14.00 / 14.02 exploit host
::
::  Usage:
::    serve.bat            (port 8000)
::    serve.bat 8080       (custom port)
::
::  Requirements: Python 3 on PATH
:: =============================================================

setlocal enabledelayedexpansion

set PORT=8000
if not "%~1"=="" set PORT=%~1

cd /d "%~dp0"

echo.
echo  Akatsuki Clan -- PS4 Exploit Host
echo  ------------------------------------

:: Detect python
set PYCMD=
where python >nul 2>&1 && set PYCMD=python
if "!PYCMD!"=="" where python3 >nul 2>&1 && set PYCMD=python3

if "!PYCMD!"=="" (
    echo.
    echo  ERROR: Python 3 not found on PATH.
    echo.
    echo  Fix:
    echo    1. Download Python 3 from https://python.org/downloads
    echo    2. Tick "Add Python to PATH" during install
    echo    3. Reopen this window and try again.
    echo.
    pause
    exit /b 1
)

:: Confirm real Python, not the Store stub
!PYCMD! --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: ^'python^' found but won^'t run. Install Python 3 from python.org
    echo  and tick "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

:: Confirm server.py is here
if not exist "%~dp0server.py" (
    echo.
    echo  ERROR: server.py not found next to serve.bat.
    echo  Make sure both files are in the same folder.
    echo.
    pause
    exit /b 1
)

echo  Using: !PYCMD!
echo.

!PYCMD! "%~dp0server.py" %PORT%

echo.
if %errorlevel% neq 0 (
    echo  Server stopped with error code %errorlevel%.
    echo  Check above for the Python error message.
) else (
    echo  Server stopped.
)
echo.
pause
endlocal
