"""Soun Runner v2 — Entry point."""

import os
import sys
import threading
import webbrowser
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

# macOS: WeasyPrint needs Homebrew's pango/cairo. Set before any import that
# might trigger the weasyprint C-extension load.
if sys.platform == "darwin":
    _brew_lib = "/opt/homebrew/lib"
    existing = os.environ.get("DYLD_LIBRARY_PATH", "")
    if _brew_lib not in existing:
        os.environ["DYLD_LIBRARY_PATH"] = f"{_brew_lib}:{existing}" if existing else _brew_lib

from app import create_app

HOST = "127.0.0.1"
PORT = 5757


def open_browser():
    import time
    time.sleep(1.2)
    webbrowser.open(f"http://{HOST}:{PORT}")


if __name__ == "__main__":
    app = create_app()

    print("=" * 52)
    print("  Soun Runner v2 — Network Assessment Tool")
    print("  Soun Al Hosn Cybersecurity LLC")
    print("=" * 52)
    print(f"  Open your browser at: http://{HOST}:{PORT}")
    print("  Press Ctrl+C to stop.")
    print("=" * 52)

    threading.Thread(target=open_browser, daemon=True).start()

    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
