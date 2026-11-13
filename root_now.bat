@echo off
rem ASCII-ONLY on purpose (cmd + UTF-8 codepage + batch = read-block mis-seek bug).
rem One-shot deterministic root for FNE-AN00 8.0.0.202 (see root_now.sh).
setlocal enabledelayedexpansion
title GhostLock-HonorFne root_now (one shot)
cd /d "%~dp0"

set "BASH="
for %%B in ("%ProgramFiles%\Git\bin\bash.exe" "D:\Git\bin\bash.exe" "%ProgramFiles(x86)%\Git\bin\bash.exe") do (
    if not defined BASH if exist "%%~B" set "BASH=%%~B"
)
if not defined BASH goto :no_bash

set "ADBDIR="
where adb >nul 2>nul
if not errorlevel 1 (
    for /f "delims=" %%A in ('where adb') do if not defined ADBDIR set "ADBDIR=%%~dpA"
)
if not defined ADBDIR if exist "D:\MiniApp\platform-tools\adb.exe" set "ADBDIR=D:\MiniApp\platform-tools\"
if not defined ADBDIR goto :no_adb

set "PATH=%ADBDIR%;%PATH%"
echo ==================================================
echo    GhostLock-HonorFne  root_now  (one shot)
echo    adb  = %ADBDIR%adb.exe
echo    bash = %BASH%
echo ==================================================
echo.
echo [1/2] Waiting for device ...
adb wait-for-device
adb devices
echo.
echo [2/2] Running root_now.sh (W1 -> Permissive -> 20s -> W2 -> KSU -> su check)
echo       This takes ~5-8 minutes. Do not unplug USB.
echo.
"%BASH%" "root/host-scripts/root_now.sh"
set "RC=%errorlevel%"
echo.
if "%RC%"=="0" (
    echo [OK] root achieved - verifying:
    adb shell "su -c id"
) else (
    echo [FAIL] rc=%RC%  - see messages above; device may need one more run.
)
echo.
pause
exit /b %RC%

:no_bash
echo [ERROR] Git Bash not found (looked in Program Files\Git\bin and D:\Git\bin).
echo         Install Git for Windows, or run: bash root/host-scripts/root_now.sh
echo         from any bash with adb on PATH. Do NOT use C:\Windows\System32\bash.exe (WSL).
echo.
pause
exit /b 1

:no_adb
echo [ERROR] adb not found on PATH and D:\MiniApp\platform-tools\adb.exe missing.
echo.
pause
exit /b 1
