@echo off
REM ============================================================================
REM  SOUN RUNNER - fresh-machine setup (cmd-safe entry point)
REM  Soun Al Hosn Cybersecurity LLC
REM
REM  Works from a normal Command Prompt OR by double-clicking this file.
REM  It launches the PowerShell setup which installs everything (VC++, Python,
REM  Git, Nmap, Chromium), fetches the app, verifies it, and starts it.
REM
REM  This avoids the cmd-vs-PowerShell confusion: you can run it from cmd.
REM ============================================================================
title Soun Runner - Setup
echo.
echo   ========================================================
echo     SOUN RUNNER - Setup ^& Launch
echo     Soun Al Hosn Cybersecurity LLC
echo   ========================================================
echo.
echo   This will install everything needed and start the tool.
echo   Keep this window open. A browser will open when ready.
echo.

REM Prefer the local copy of the setup script when it is next to this file
REM (e.g. inside an already-cloned repo or on a USB stick); otherwise fetch
REM the latest from GitHub.
if exist "%~dp0SETUP-AND-RUN.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SETUP-AND-RUN.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/j0ons/soun-runner/main/SETUP-AND-RUN.ps1 | iex"
)

echo.
echo   (If the tool stopped, this window can be closed.)
pause
