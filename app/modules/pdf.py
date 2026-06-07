"""Cross-platform HTML→PDF rendering for Soun Runner reports.

Why this module exists
----------------------
Reports are rendered as rich HTML+CSS (flexbox, grid, gradients, SVG). On the
operator's own machine WeasyPrint handled the PDF, but WeasyPrint depends on
native GTK libraries (libgobject-2.0, pango, cairo). On a client Windows
workstation those DLLs are absent and the load fails with:

    cannot load library 'libgobject-2.0-0': error 0x7e

To make the tool portable to machines we do not control, the *primary* engine
is now headless Chromium via Playwright — it renders the report pixel-identically
to a browser and ships its own self-contained browser binary (no system DLLs,
no admin install). WeasyPrint is kept as a fallback so existing setups that
already have it keep working unchanged.

Engine order:
    1. Playwright (headless Chromium)   ← preferred, fully portable
    2. WeasyPrint                       ← fallback, needs GTK
    3. give up gracefully → report stays HTML-only

`render_pdf()` never raises: it returns True on success, False otherwise, so
callers can keep their existing "HTML report still works without a PDF" path.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path


@contextlib.contextmanager
def _quiet_output():
    """Best-effort: silence stdout+stderr (Python streams) for the block.

    A misconfigured WeasyPrint (missing native GTK) prints a multi-line
    "could not import some external libraries" banner to stdout while importing.
    Since that import is only our optional *fallback*, we hide the banner to keep
    the operator's console clean. Best-effort by design: WeasyPrint emits some of
    this from its C layer / at finalization, which Python-level redirection can't
    always catch — that's acceptable, it's purely cosmetic and only appears on a
    machine whose WeasyPrint is broken anyway (the Chromium path is unaffected).
    """
    with open(os.devnull, "w") as devnull:
        with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
            yield

# Cache which engine works so we don't re-probe (and re-log) on every report.
# None = not probed yet; "playwright" / "weasyprint" / "none" once decided.
_ENGINE: str | None = None

# Human-readable reason the most recent render attempt failed (for diagnostics
# surfaced in the UI / logs instead of a silent "PDF not available").
_LAST_ERROR: str = ""


def last_error() -> str:
    """Reason the last render_pdf() call failed, or '' if none/last succeeded."""
    return _LAST_ERROR


def _is_frozen() -> bool:
    """True when running inside a PyInstaller/py2exe bundle."""
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def _bundle_dir() -> Path | None:
    """Directory where a frozen build unpacks its data files, else None."""
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) if base else None


def _prepare_chromium_env() -> None:
    """Point Playwright at a bundled Chromium when frozen.

    During normal `python main.py` use, Playwright finds the browser it
    downloaded via `playwright install chromium` automatically. When packaged
    into an EXE there is no such download on the target machine, so we ship the
    browser inside the bundle (under a `ms-playwright` folder) and tell
    Playwright where it is via PLAYWRIGHT_BROWSERS_PATH.

    Bundling step (done at build time, documented in BUILD-EXE notes):
        1. `playwright install chromium`
        2. copy the resolved browsers dir into the build as `ms-playwright/`
        3. add it to the PyInstaller datas so it lands next to the EXE.
    """
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return  # operator/build already configured it — respect that.

    candidates: list[Path] = []
    bundle = _bundle_dir()
    if bundle:
        candidates.append(bundle / "ms-playwright")
    # Also look next to the executable / project root.
    exe_dir = Path(sys.executable).parent if _is_frozen() else Path(__file__).resolve().parents[2]
    candidates.append(exe_dir / "ms-playwright")

    for path in candidates:
        if path.is_dir():
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(path)
            return


def _render_with_playwright(html: str, out_path: str) -> bool:
    """Render via headless Chromium. Returns True on success."""
    global _LAST_ERROR
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        _LAST_ERROR = ("Playwright is not installed. Run: pip install playwright "
                       "&& playwright install chromium")
        return False

    _prepare_chromium_env()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page()
                # set_content + wait for network idle so data-URI images (the
                # base64 logo) and any web fonts are fully laid out before print.
                page.set_content(html, wait_until="networkidle")
                page.pdf(
                    path=out_path,
                    format="A4",
                    print_background=True,  # keep gradients / coloured panels
                    margin={"top": "14mm", "bottom": "16mm", "left": "12mm", "right": "12mm"},
                )
            finally:
                browser.close()
        return True
    except Exception as exc:
        msg = str(exc)
        if "Executable doesn't exist" in msg or "Looks like Playwright" in msg:
            _LAST_ERROR = ("Chromium browser not installed for Playwright. "
                           "Run: playwright install chromium")
        else:
            _LAST_ERROR = f"Chromium render failed: {msg}"
        return False


def _render_with_weasyprint(html: str, out_path: str) -> bool:
    """Render via WeasyPrint (needs native GTK). Returns True on success."""
    global _LAST_ERROR
    try:
        with _quiet_output():
            from weasyprint import HTML as WP
    except Exception as exc:
        _LAST_ERROR = (f"WeasyPrint unavailable ({exc}). Install the Chromium "
                       "engine instead: pip install playwright && playwright install chromium")
        return False
    try:
        WP(string=html).write_pdf(out_path)
        return True
    except Exception as exc:
        _LAST_ERROR = f"WeasyPrint render failed: {exc}"
        return False


def render_pdf(html: str, out_path: str | os.PathLike) -> bool:
    """Render an HTML string to a PDF file at ``out_path``.

    Tries Chromium (Playwright) first, then WeasyPrint. Never raises — returns
    True on success, False if no engine could produce a PDF (caller should then
    fall back to serving the HTML report).
    """
    global _ENGINE, _LAST_ERROR
    out_path = str(out_path)
    _LAST_ERROR = ""

    # If we've already found a working engine, go straight to it but still allow
    # falling through to the other on a transient failure.
    if _ENGINE == "playwright":
        if _render_with_playwright(html, out_path):
            _LAST_ERROR = ""
            return True
    elif _ENGINE == "weasyprint":
        if _render_with_weasyprint(html, out_path):
            _LAST_ERROR = ""
            return True

    # First run (or the cached engine just failed): probe in priority order.
    if _render_with_playwright(html, out_path):
        _ENGINE = "playwright"
        _LAST_ERROR = ""
        return True
    if _render_with_weasyprint(html, out_path):
        _ENGINE = "weasyprint"
        _LAST_ERROR = ""
        return True

    _ENGINE = "none"
    if not _LAST_ERROR:
        _LAST_ERROR = ("No PDF engine available. Run: pip install playwright "
                       "&& playwright install chromium")
    return False


def engine_name() -> str:
    """Best-effort name of the engine that will be used, for diagnostics.

    Does not render anything; only checks importability (cheap). Returns one of
    'chromium (playwright)', 'weasyprint', or 'none'.
    """
    try:
        import playwright.sync_api  # noqa: F401
        return "chromium (playwright)"
    except Exception:
        pass
    try:
        with _quiet_output():
            import weasyprint  # noqa: F401
        return "weasyprint"
    except Exception:
        pass
    return "none"
