@echo off
REM ============================================================================
REM  build-exe.bat  -  Build SounRunner.exe (Windows, single file, Chromium baked in)
REM
REM  Run this ONCE on a Windows machine that has Python 3.10+ installed.
REM  Produces:  dist\SounRunner.exe   (self-contained PDF engine, no install needed)
REM
REM  Requirements on the BUILD machine only:
REM    - Python 3.10+  (winget install Python.Python.3.12)
REM    - Internet (to download deps + Chromium once)
REM ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo ===========================================================
echo  Soun Runner - Windows EXE builder
echo ===========================================================
echo.

REM --- check python ---
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python is not installed or not on PATH.
  echo         Install it:  winget install Python.Python.3.12
  echo         Then re-open this window and run build-exe.bat again.
  exit /b 1
)

REM --- fresh venv so the build is clean and reproducible ---
echo [1/6] Creating build virtual environment...
if exist build-venv rmdir /s /q build-venv
python -m venv build-venv
call build-venv\Scripts\activate.bat

REM --- CRITICAL: install Chromium INTO the playwright package so PyInstaller bundles it ---
set PLAYWRIGHT_BROWSERS_PATH=0

echo [2/6] Upgrading pip...
python -m pip install --upgrade pip >nul

echo [3/6] Installing dependencies + build tools...
python -m pip install -r requirements.txt
python -m pip install pyinstaller

echo [4/6] Downloading Chromium into the package (one-time, ~120 MB)...
python -m playwright install chromium
if errorlevel 1 (
  echo [ERROR] Chromium download failed. Check your internet connection.
  exit /b 1
)

echo [5/6] Building SounRunner.exe with PyInstaller...
pyinstaller soun-runner.spec --noconfirm
if errorlevel 1 (
  echo [ERROR] PyInstaller build failed. See the output above.
  exit /b 1
)

echo [6/6] Done.
echo.
if exist dist\SounRunner.exe (
  echo ===========================================================
  echo  SUCCESS  ->  dist\SounRunner.exe
  echo ===========================================================
  echo.
  echo  Next: put dist\SounRunner.exe and an nmap installer into your
  echo  client deployment folder. See BUILD-EXE.md for the per-client steps.
) else (
  echo [ERROR] Build finished but dist\SounRunner.exe was not found.
  exit /b 1
)
endlocal
