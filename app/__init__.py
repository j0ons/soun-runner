"""Soun Runner v2 — Flask application factory."""

from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask

_LOGO_URI_CACHE: str | None = None


def resource_path(*parts: str) -> Path:
    """Resolve a bundled resource path for both source and frozen (.exe) runs.

    PyInstaller unpacks bundled data files into a temp dir exposed as
    ``sys._MEIPASS``. In a normal source checkout we anchor to this file's
    package directory instead. ``parts`` are joined under that base
    (e.g. resource_path("static", "logo.png")).
    """
    base = getattr(sys, "_MEIPASS", None)
    if base:
        # Frozen: data files are bundled under <_MEIPASS>/app/...
        return Path(base) / "app" / Path(*parts)
    return Path(__file__).parent / Path(*parts)


def _logo_data_uri() -> str:
    """Return the Soun logo as a base64 data URI (cached). Used so the logo
    survives in generated PDFs without a network/file lookup."""
    global _LOGO_URI_CACHE
    if _LOGO_URI_CACHE is not None:
        return _LOGO_URI_CACHE
    import base64
    logo = resource_path("static", "logo.png")
    try:
        b64 = base64.b64encode(logo.read_bytes()).decode()
        _LOGO_URI_CACHE = "data:image/png;base64," + b64
    except Exception:
        _LOGO_URI_CACHE = ""
    return _LOGO_URI_CACHE


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(resource_path("templates")),
        static_folder=str(resource_path("static")),
    )
    app.secret_key = "sounrunner-local-only"

    @app.context_processor
    def inject_logo():
        return {"logo_uri": _logo_data_uri()}

    from app.routes import bp
    app.register_blueprint(bp)

    return app
