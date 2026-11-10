@echo off
title GhostLock-HonorFne One-Click Temporary Root
cd /d "%~dp0"

rem ASCII-ONLY on purpose. Do NOT add "chcp 65001" or non-ASCII text:
rem cmd + UTF-8 codepage + batch file has a read-block mis-seek bug that
rem aborts the batch mid-run (= window flash close). Hit after [2/5] on
rem 2026-10-23.

echo ==================================================
echo    GhostLock-HonorFne  One-Click Temporary Root (Windows)
echo    Target: HONOR 70 FNE-AN00 (Bootloader Locked)
echo ==================================================
echo.

rem ---------- Mode selection: deploy / uninstall ----------
echo Please select mode:
echo   [1] Deploy / One-click temporary root (default)
echo   [2] Uninstall (clean device-side files and module staging; does not uninstall manager/app)
set "MODE=1"
set /p "MODE=Enter 1 or 2 and press Enter: "
if "%MODE%"=="2" goto :undo
goto :deploy

:undo
where adb >nul 2>nul || goto :no_adb
call :prepend_adb
set "BASH="
call :resolve_bash
if not defined BASH goto :no_bash
"%BASH%" "root/host-scripts/uninstall.sh"
echo.
pause
exit /b 0

:deploy
rem ---------- 1/5 Dependency check ----------
echo [1/5] Checking dependencies...
where adb >nul 2>nul
if errorlevel 1 goto :no_adb
call :prepend_adb
set "BASH="
call :resolve_bash
if not defined BASH goto :no_bash
echo       OK: adb  = %GHOSTLOCK_ADB_DIR%\adb.exe
echo       OK: bash = %BASH%
echo.

rem ---------- 2/5 Connect device ----------
echo [2/5] Connecting device (USB)
:devcheck
adb get-state >nul 2>nul
if errorlevel 1 (
    echo       Waiting for device - connect USB and allow USB debugging authorization
    adb wait-for-device
)
echo       Connected:
adb devices
echo.

rem ---------- 3/5 Root status check ----------
echo [3/5] Checking KernelSU status...
rem Wireless adb single-shell transient disconnect (empty response) may falsely
rem report "not loaded" and trigger a full exploit run; repeating W2 within the
rem same boot causes a slab_drain fork storm that may trigger a protective reboot.
rem Max 2 checks to resist transient disconnect (same rule as run_root.command / run_w2.sh).
rem Use goto loop instead of for block: %errorlevel%/%VAR% inside blocks has delayed expansion pitfalls.
set "KSU_TRIES=0"
set "KSU_LOADED=0"
:ksu_chk
adb shell "grep -q kernelsu /proc/modules" >nul 2>nul
if not errorlevel 1 (
    set "KSU_LOADED=1"
    goto :ksu_done
)
set /a KSU_TRIES+=1
if %KSU_TRIES% LSS 2 (
    echo       No response, retrying - try %KSU_TRIES% of 2
    ping -n 6 127.0.0.1 >nul
    goto :ksu_chk
)
:ksu_done
if "%KSU_LOADED%"=="1" (
    echo       KernelSU is already running, no need to re-root.
    call :ensure_module
    rem Previous run may have timed out and falsely reported "not landed" - module loaded but su not ready. Complete installation/activation, rerun to fix.
    echo       --- Completing KSU / LSP manager installation and Zygisk activation ---
    "%BASH%" "root/host-scripts/install_managers.sh"
    "%BASH%" "root/host-scripts/activate_zygisk.sh"
    echo.
    pause
    exit /b 0
)
echo       KernelSU not loaded, continuing.
echo.

rem ---------- 4/5 Deploy (unconditional overwrite) ----------
rem Overwrite instead of skip-if-exists: chain_hook.sh / ko / syms iterate frequently; existence check would prevent already-deployed devices from getting new versions (LSA merge fix was stuck on old chain_hook).
if not exist "root\exploit\ghostlock" (
    echo [ERROR] Missing root\exploit\ghostlock - exploit binary.
    echo         This repo should ship prebuilt artifacts; if you cloned via git and it's missing,
    echo         please update to the latest version; or refer to README "Rebuild" section with
    echo         Android NDK r27c:  cd root\exploit ^&^& ANDROID_NDK_HOME=.. make
    timeout /t 30 /nobreak >nul
    pause
    exit /b 1
)
for %%F in (chain_hook.sh kernelsu.ko ksud magiskpolicy ksu_rules load_ko kmsg_dumper fne_syms.txt) do (
    if not exist "root\ksu-late-load\%%F" (
        echo [ERROR] Missing root\ksu-late-load\%%F
        timeout /t 30 /nobreak >nul
        pause
        exit /b 1
    )
)
echo [4/5] Deploying device-side files (~20MB, overwrite sync, please wait)...

rem ---- pick the exploit binary that matches the running kernel ----
rem 8.0.0.202 (5.4.289-qgki-gc5b795a0f72f) needs its own offset table, shipped
rem as ghostlock.fne202; all other supported kernels use the stock binary.
set "EXPLOIT_BIN=root/exploit/ghostlock"
set "KREL="
for /f "usebackq delims=" %%K in (`adb shell uname -r 2^>nul`) do if not defined KREL set "KREL=%%K"
if defined KREL echo       kernel: %KREL%
set "KREL202="
if defined KREL echo %KREL%|findstr /c:"gc5b795a0f72f" >nul && set "KREL202=1"
if defined KREL202 if exist "root\exploit\ghostlock.fne202" set "EXPLOIT_BIN=root/exploit/ghostlock.fne202"
if defined KREL202 if not exist "root\exploit\ghostlock.fne202" echo [WARN] 8.0.0.202 kernel but root\exploit\ghostlock.fne202 is missing - offsets will not match.
if defined KREL202 echo       8.0.0.202 kernel - using ghostlock.fne202

adb shell "mkdir -p /data/local/tmp/ksu_fne"
adb push "%EXPLOIT_BIN%" /data/local/tmp/e
if errorlevel 1 goto :push_fail
adb shell "chmod 755 /data/local/tmp/e"
for %%F in (chain_hook.sh kernelsu.ko ksud magiskpolicy ksu_rules load_ko kmsg_dumper fne_syms.txt) do (
    adb push "root/ksu-late-load/%%F" /data/local/tmp/ksu_fne/ || goto :push_fail
)
adb shell "chmod 755 /data/local/tmp/ksu_fne/chain_hook.sh /data/local/tmp/ksu_fne/magiskpolicy /data/local/tmp/ksu_fne/ksud /data/local/tmp/ksu_fne/load_ko /data/local/tmp/ksu_fne/kmsg_dumper"
echo       Deployment complete.
echo.

rem netfix_packet module is small and iterates quickly: always re-transfer to ensure module fixes (sepolicy rules / LSPosed tmpfs patch) are synced to device.
:sync_module
echo       Syncing netfix_packet module...
adb shell "rm -rf /data/local/tmp/netfix_packet" >nul 2>nul
adb push "root/ksu-modules/netfix_packet" /data/local/tmp/
if errorlevel 1 goto :push_fail
echo.

:grind
rem ---------- 5/5 Run ----------
rem Preflight: run_w2.sh calls bare `adb` inside bash. If the bash we picked
rem cannot see adb (WSL's System32\bash.exe, or platform-tools missing from
rem PATH) every call fails with rc=127, settle() burns ~10 minutes of silent
rem retries, W1 "fails" in milliseconds, and run_forever.sh relaunches it
rem forever -- which looks exactly like a hang/timeout. Fail loudly here.
"%BASH%" -c "command -v adb >/dev/null 2>&1"
if errorlevel 1 goto :no_adb_in_bash
"%BASH%" -c "command -v timeout >/dev/null 2>&1"
if errorlevel 1 echo       * WARN: GNU timeout not visible in bash - watchdogs disabled
echo [5/5] Starting per-boot root (W1 - W2 - KSU late-load)
echo       * Fully automatic, includes multiple device reboots, may take a long time
echo       * Do not close this window; do not run other grinds simultaneously
echo       * Script stops automatically on success
echo.
"%BASH%" "root/host-scripts/run_forever.sh"
echo.

rem After root lands, detached chain_hook still needs tens of seconds to complete KSU late-load; checking /proc/modules immediately may falsely report failure. Poll and wait (max 180s), showing device-side chain_status / chain.log incrementally (wait_ksu.sh).
"%BASH%" "root/host-scripts/wait_ksu.sh"
if not errorlevel 1 goto :ksu_ok
goto :ksu_fail

:ksu_fail
call :ensure_module
echo ==================================================
echo    [FAILED] This grind did not land, you can rerun and try again.
echo ==================================================
goto :done_root

:ksu_ok
call :ensure_module
echo ==================================================
echo    [SUCCESS] KernelSU loaded, temporary root ready!
echo ==================================================
echo       --- Auto-installing KSU / LSP managers ---
"%BASH%" "root/host-scripts/install_managers.sh"
rem Zygisk/LSPosed injection activation (post-chain timing, verified recipe at 12:40; running inside chain would break modules)
"%BASH%" "root/host-scripts/activate_zygisk.sh"
call :install_launcher_mods
goto :done_root

:done_root
echo.
pause
exit /b 0

:no_adb
echo [ERROR] adb not found.
echo         Please install Android platform-tools and add adb directory to PATH.
timeout /t 30 /nobreak >nul
pause
exit /b 1

:no_bash
echo [ERROR] Git Bash not found.
echo         NOTE: C:\Windows\System32\bash.exe is WSL, NOT Git Bash - this tool
echo               cannot run under WSL (the scripts call Windows adb.exe).
echo         Install Git for Windows (https://git-scm.com/download/win) anywhere you
echo         like, or point GHOSTLOCK_BASH at an existing bash.exe, e.g.
echo             set GHOSTLOCK_BASH=D:\Git\bin\bash.exe
timeout /t 30 /nobreak >nul
pause
exit /b 1

:no_adb_in_bash
echo [ERROR] adb is not visible inside bash.
echo         cmd found: %GHOSTLOCK_ADB_DIR%\adb.exe
echo         but "%BASH%" cannot resolve `adb` - every adb call would fail rc=127.
echo         Make sure the platform-tools directory is on PATH, then rerun.
timeout /t 30 /nobreak >nul
pause
exit /b 1

:push_fail
echo [ERROR] File push failed. Check connection and USB debugging authorization and retry.
timeout /t 30 /nobreak >nul
pause
exit /b 1

rem ---------- Optional: install launcher mods (Launcher/SystemUI hooks) ----------
rem Called after KSU/LSPosed success. Default skip, choose Y to install:
rem   HnLauncherPort.apk (LSPosed module: launcher layout + control center animation optimization)
:install_launcher_mods
echo.
choice /c YN /n /m "Install launcher mods (HnLauncherPort)? [Y=Install N=Skip]: "
if errorlevel 2 (
    echo       Skipped launcher mods installation.
    goto :eof
)
if not exist "hooks\launcher\out\HnLauncherPort.apk" (
    echo       [ERROR] Missing hooks\launcher\out\HnLauncherPort.apk
    goto :eof
)
echo       Installing HnLauncherPort.apk ...
adb install -r "hooks\launcher\out\HnLauncherPort.apk" >nul 2>nul
if errorlevel 1 (
    echo       [ERROR] APK installation failed
    goto :eof
)
echo       APK installed successfully.
echo       Note: First time you need to enable the module in LSPosed Manager and check
echo             scope (HONOR Launcher + SystemUI), then restart the app to take effect.
goto :eof

rem ---------- netfix_packet module installation (called after KSU ready) ----------
rem /data/adb is a root directory, adb direct push won't work: stage via /data/local/tmp, then su 0 merge-sync install.
rem Unconditional sync (cp -rf merge, preserve runtime netfix.log): ensure module fixes/updates always take effect.
rem Rules are read and injected during ksud late-load, so updates activate automatically from next root/reboot.
:ensure_module
adb shell "su 0 sh -c 'mkdir -p /data/adb/modules/netfix_packet && cp -rf /data/local/tmp/netfix_packet/. /data/adb/modules/netfix_packet/'" >nul 2>nul
adb shell "su 0 sh -c '[ -f /data/adb/modules/netfix_packet/sepolicy.rule ]'" >nul 2>nul && (
    echo       netfix_packet module synced - network/RRO/status bar/nav bar/AOD fix
) || (
    echo       [WARN] netfix_packet module sync failed
)
goto :eof

rem ==================== helpers ====================
rem :resolve_bash  - set BASH to a Git for Windows bash.exe, or leave it unset.
rem   Git Bash is REQUIRED: every host script is POSIX shell that calls the
rem   Windows adb.exe and relies on MSYS path/adb.exe translation. WSL's bash
rem   (C:\Windows\System32\bash.exe) has no adb on PATH -> rc=127 on every
rem   call, which previously turned into a silent infinite grind.
:resolve_bash
set "BASH="
rem 1) explicit override
if defined GHOSTLOCK_BASH if exist "%GHOSTLOCK_BASH%" set "BASH=%GHOSTLOCK_BASH%"
if defined BASH goto :eof
rem 2) standard install locations (Program Files / per-user / common D:\ form)
for %%P in (
    "%ProgramFiles%\Git\bin\bash.exe"
    "%ProgramW6432%\Git\bin\bash.exe"
    "%LocalAppData%\Programs\Git\bin\bash.exe"
    "D:\Git\bin\bash.exe"
    "C:\Git\bin\bash.exe"
) do if not defined BASH if exist "%%~P" set "BASH=%%~P"
if defined BASH goto :eof
rem 3) derive from git.exe on PATH: <Git>\cmd\git.exe -> <Git>\bin\bash.exe
for /f "delims=" %%G in ('where git.exe 2^>nul') do (
    if not defined BASH (
        for %%H in ("%%~dpG..\bin\bash.exe") do if exist "%%~fH" set "BASH=%%~fH"
    )
)
if defined BASH goto :eof
rem 4) any non-WSL bash on PATH (MSYS2 / scoop / custom)
for /f "delims=" %%B in ('where bash.exe 2^>nul') do (
    if not defined BASH if /i not "%%~dpB"=="%SystemRoot%\System32\" set "BASH=%%~B"
)
goto :eof

rem :prepend_adb  - put the real adb directory at the FRONT of PATH so the bash
rem   child resolves the exact adb.exe cmd just used (usually
rem   D:\MiniApp\platform-tools). Harmless when adb is not found.
:prepend_adb
set "GHOSTLOCK_ADB_DIR="
for /f "delims=" %%A in ('where adb.exe 2^>nul') do if not defined GHOSTLOCK_ADB_DIR set "GHOSTLOCK_ADB_DIR=%%~dpA"
if not defined GHOSTLOCK_ADB_DIR goto :eof
set "GHOSTLOCK_ADB_DIR=%GHOSTLOCK_ADB_DIR:~0,-1%"
set "PATH=%GHOSTLOCK_ADB_DIR%;%PATH%"
goto :eof

