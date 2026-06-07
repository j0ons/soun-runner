"""Soun Runner v2 — Entry point."""

import os
import sys
import threading
import webbrowser
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

# PDF engine: Soun Runner renders reports to PDF via headless Chromium
# (Playwright) by default — portable, no system libraries required. WeasyPrint
# is a fallback for setups that already have it. The line below only helps the
# WeasyPrint fallback on macOS, where it needs Homebrew's pango/cairo. It is
# harmless on machines that use Chromium.
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

    from app.modules.pdf import engine_name
    _pdf_engine = engine_name()

    print("=" * 52)
    print("  Soun Runner v2 — Network Assessment Tool")
    print("  Soun Al Hosn Cybersecurity LLC")
    print("=" * 52)
    print(f"  Open your browser at: http://{HOST}:{PORT}")
    print(f"  PDF engine: {_pdf_engine}")
    if _pdf_engine == "none":
        print("  (No PDF engine — reports will be HTML only.)")
        print("  Fix: pip install playwright && playwright install chromium")
    print("  Press Ctrl+C to stop.")
    print("=" * 52)

    threading.Thread(target=open_browser, daemon=True).start()

    # Soun Runner is a local single-operator tool bound to 127.0.0.1, not a
    # public service — silence Flask/Werkzeug's "development server" banner so the
    # console stays clean in front of clients. Our own banner above already shows
    # the URL; request logs stay on. (log_startup prints both the warning and the
    # "Running on" line, so we no-op it entirely.)
    try:
        import flask.cli
        flask.cli.show_server_banner = lambda *a, **k: None
    except Exception:
        pass
    try:
        from werkzeug.serving import BaseWSGIServer
        BaseWSGIServer.log_startup = lambda self: None
    except Exception:
        pass

    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
