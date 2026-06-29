@echo off
REM ============================================================
REM   SOUN RUNNER - One-click launcher (Windows)
REM   Soun Al Hosn Cybersecurity LLC
REM
REM   Double-click this file to start Soun Runner.
REM   It finds a REAL Python (ignoring Windows' fake Microsoft
REM   Store stub), installs Python packages, checks Nmap, then
REM   opens the tool in your browser.
REM
REM   First time on a fresh machine? Run SETUP.bat instead -
REM   it installs Python/Git/Nmap automatically.
REM ============================================================
setlocal enableextensions
cd /d "%~dp0"
title Soun Runner - Soun Al Hosn Cybersecurity

REM ---- Advanced console password (CHANGE THIS for your deployment) ----
set SOUN_ADVANCED_PASSWORD=Tmppassword

REM ---- Email reports to Soun ("Email to Soun" button) ----
REM cPanel mailbox reports@sounalhosn.ae - SSL on port 465.
REM >>> Put the mailbox password after PASSWORD= (no quotes). <<<
set SOUN_SMTP_HOST=sounalhosn.ae
set SOUN_SMTP_PORT=465
set SOUN_SMTP_USER=reports@sounalhosn.ae
set SOUN_SMTP_PASSWORD=
set SOUN_REPORT_TO=Mohamed@sounalhosn.ae

echo.
echo  ===============================================
echo    SOUN RUNNER  -  Soun Al Hosn Cybersecurity
echo  ===============================================
echo.

REM ---- 1. Find a REAL Python --------------------------------
REM Windows 10/11 ships a fake "python.exe" that just opens the
REM Microsoft Store. It prints NOTHING to stdout, so asking Python
REM to print its own path filters the fake out automatically.
set "PY="

REM Portable Python installed by SETUP-AND-RUN.ps1 (sits next to the repo)
if exist "%~dp0..\_sr_python\python.exe" (
    "%~dp0..\_sr_python\python.exe" -c "import sys" >nul 2>&1 && set "PY=%~dp0..\_sr_python\python.exe"
)

REM Normal PATH python - accepted only if it runs AND is 3.10+
if not defined PY for /f "delims=" %%i in ('python -c "import sys;v=sys.version_info;v[0]==3 and v[1] in range(10,100) and print(sys.executable)" 2^>nul') do set "PY=%%i"

REM The py launcher knows about real installs even when PATH is stale
if not defined PY for /f "delims=" %%i in ('py -3 -c "import sys;v=sys.version_info;v[0]==3 and v[1] in range(10,100) and print(sys.executable)" 2^>nul') do set "PY=%%i"

if not defined PY (
    echo  [!] No working Python 3.10+ found on this machine.
    echo.
    echo      NOTE: the "python" that opens the Microsoft Store does NOT
    echo      count - that is a Windows placeholder, not a real Python.
    echo.
    echo      EASIEST FIX: run SETUP.bat ^(next to this file^) - it installs
    echo      everything automatically. Or install Python manually from
    echo      https://www.python.org/downloads/ and tick "Add Python to PATH".
    echo.
    pause
    exit /b 1
)
echo  [ok] Python found: %PY%

REM ---- 2. Check / install Python packages -------------------
echo  [..] Checking required Python packages...
"%PY%" -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo  [!] pip reported errors - verifying what actually installed...
)
"%PY%" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo  [!] Core packages are missing ^(Flask did not import^).
    echo      Check the internet connection and try again, or run SETUP.bat.
    pause
    exit /b 1
)
echo  [ok] Python packages ready.

REM ---- 3. Check Nmap ---------------------------------------
where nmap >nul 2>&1
if errorlevel 1 (
    if exist "C:\Program Files (x86)\Nmap\nmap.exe" goto nmap_ok
    if exist "C:\Program Files\Nmap\nmap.exe" goto nmap_ok
    echo.
    echo  [!] Nmap is not installed - scanning will not work without it.
    echo.
    echo      Install it once from:  https://nmap.org/download
    echo      ^(or run:  winget install Insecure.Nmap^)
    echo.
    echo      You can still open the tool, but scans need Nmap.
    echo.
    pause
)
:nmap_ok
echo  [ok] Nmap found.

REM ---- 4. Launch -------------------------------------------
echo.
echo  Starting Soun Runner...
echo  A browser window will open at http://127.0.0.1:5757
echo.
echo  Keep this window open while you work.
echo  Close this window (or press Ctrl+C) to stop the tool.
echo.
REM Clear any stale wipe sentinel from a previous run before launching.
del /f /q "%TEMP%\_sr_wiped" >nul 2>&1

"%PY%" main.py

REM If a Finish & Wipe ran, the app dropped a sentinel in TEMP. In that case the
REM project folder is being removed by a detached cleaner — close this window
REM instead of pausing (and don't leave a "press any key" on a half-gone app).
if exist "%TEMP%\_sr_wiped" (
    del /f /q "%TEMP%\_sr_wiped" >nul 2>&1
    echo.
    echo  SounRunner has finished and is removing itself and its setup files
    echo  from this machine. Your reports were saved to a folder on the Desktop.
    timeout /t 4 /nobreak >nul
    exit
)

pause
