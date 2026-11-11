@echo off
:: ============================================================
::  NanospeedGamer -- PS4 14.00 / 14.02 exploit host
::
::  Usage:
::    serve.bat            (port 8000)
::    serve.bat 8080       (custom port)
::
::  Requirements: Python 3 installed and on PATH
::  Admin panel:  URL printed on startup (new key every restart)
:: ============================================================

setlocal enabledelayedexpansion

set PORT=8000
if not "%~1"=="" set PORT=%~1

cd /d "%~dp0"

echo.
echo  NanospeedGamer exploit host
echo  ----------------------------

:: ── Detect Python ─────────────────────────────────────────────────────────
set PYCMD=
where python >nul 2>&1
if %errorlevel%==0 set PYCMD=python

if "!PYCMD!"=="" (
    where python3 >nul 2>&1
    if %errorlevel%==0 set PYCMD=python3
)

if "!PYCMD!"=="" (
    echo.
    echo  ERROR: Python 3 was not found on PATH.
    echo.
    echo  Fix:
    echo    1. Download Python 3 from  https://python.org/downloads
    echo    2. During install, tick "Add Python to PATH"  ^<-- important
    echo    3. Close this window and double-click serve.bat again.
    echo.
    pause
    exit /b 1
)

echo  Using: !PYCMD!
echo.

:: ── Run server ────────────────────────────────────────────────────────────
!PYCMD! "%~dp0server.py" %PORT%

echo.
if %errorlevel% neq 0 (
    echo  ERROR: Server exited with code %errorlevel%.
    echo  Make sure port %PORT% is not already in use and try again.
) else (
    echo  Server stopped.
)
echo.
pause
endlocal
