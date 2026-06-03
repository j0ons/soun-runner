@echo off
REM ============================================================
REM   SOUN RUNNER - One-click launcher (Windows)
REM   Soun Al Hosn Cybersecurity LLC
REM
REM   Double-click this file to start Soun Runner.
REM   It checks for Python + Nmap, installs Python packages
REM   automatically, then opens the tool in your browser.
REM ============================================================
setlocal enableextensions
cd /d "%~dp0"
title Soun Runner - Soun Al Hosn Cybersecurity

REM ---- Advanced console password (CHANGE THIS for your deployment) ----
set SOUN_ADVANCED_PASSWORD=Tmppassword

echo.
echo  ===============================================
echo    SOUN RUNNER  -  Soun Al Hosn Cybersecurity
echo  ===============================================
echo.

REM ---- 1. Check Python --------------------------------------
where python >nul 2>&1
if errorlevel 1 (
    echo  [!] Python is not installed on this machine.
    echo.
    echo      Soun Runner needs Python 3.10 or newer.
    echo      Install it once from:  https://www.python.org/downloads/
    echo      IMPORTANT: tick "Add Python to PATH" during install.
    echo.
    echo      After installing, double-click this file again.
    echo.
    pause
    exit /b 1
)
echo  [ok] Python found.

REM ---- 2. Check / install Python packages -------------------
echo  [..] Checking required Python packages...
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo  [!] Could not install Python packages automatically.
    echo      Check the internet connection and try again.
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
python main.py

pause
