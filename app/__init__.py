"""Soun Runner v2 — Flask application factory."""

from __future__ import annotations

from pathlib import Path

from flask import Flask

_LOGO_URI_CACHE: str | None = None


def _logo_data_uri() -> str:
    """Return the Soun logo as a base64 data URI (cached). Used so the logo
    survives in WeasyPrint-generated PDFs without a network/file lookup."""
    global _LOGO_URI_CACHE
    if _LOGO_URI_CACHE is not None:
        return _LOGO_URI_CACHE
    import base64
    logo = Path(__file__).parent / "static" / "logo.png"
    try:
        b64 = base64.b64encode(logo.read_bytes()).decode()
        _LOGO_URI_CACHE = "data:image/png;base64," + b64
    except Exception:
        _LOGO_URI_CACHE = ""
    return _LOGO_URI_CACHE


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = "sounrunner-local-only"

    @app.context_processor
    def inject_logo():
        return {"logo_uri": _logo_data_uri()}

    from app.routes import bp
    app.register_blueprint(bp)

    return app
