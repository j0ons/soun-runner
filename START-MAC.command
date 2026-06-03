#!/bin/bash
# ============================================================
#   SOUN RUNNER - One-click launcher (macOS)
#   Soun Al Hosn Cybersecurity LLC
#
#   Double-click this file to start Soun Runner.
# ============================================================
cd "$(dirname "$0")"

# Advanced console password (CHANGE THIS for your deployment)
export SOUN_ADVANCED_PASSWORD="Tmppassword"

echo ""
echo " ==============================================="
echo "   SOUN RUNNER  -  Soun Al Hosn Cybersecurity"
echo " ==============================================="
echo ""

# 1. Python
if ! command -v python3 >/dev/null 2>&1; then
  echo " [!] Python 3 is not installed."
  echo "     Install it from https://www.python.org/downloads/ then re-run."
  read -p "Press Enter to close..."
  exit 1
fi
echo " [ok] Python found."

# 2. WeasyPrint needs Homebrew libs on Mac
if [ -d "/opt/homebrew/lib" ]; then
  export DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH"
fi

# 3. Python packages
echo " [..] Checking Python packages..."
python3 -m pip install --quiet --disable-pip-version-check -r requirements.txt 2>/dev/null
echo " [ok] Packages ready."

# 4. Nmap
if ! command -v nmap >/dev/null 2>&1; then
  echo " [!] Nmap not found. Install with:  brew install nmap"
fi

echo ""
echo " Starting Soun Runner... browser opens at http://127.0.0.1:5757"
echo " Press Ctrl+C in this window to stop."
echo ""
python3 main.py
