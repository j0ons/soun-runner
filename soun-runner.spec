# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for SounRunner.exe (Windows, single-file).

Bundles:
  - the Flask app code
  - app/templates and app/static (incl. logo.png)  -> resolved via resource_path()
  - the Playwright Chromium browser                  -> for PDF generation, no install on client

IMPORTANT — build with the browser bundled INTO the playwright package:
    set PLAYWRIGHT_BROWSERS_PATH=0
    pip install -r requirements.txt pyinstaller
    playwright install chromium
    pyinstaller soun-runner.spec --noconfirm
(build-exe.bat does all of this for you.)

With PLAYWRIGHT_BROWSERS_PATH=0, Chromium installs under the playwright
package's own folder, and collect_data_files('playwright') below sweeps it into
the bundle automatically. app/modules/pdf.py also sets the same env var at
runtime when frozen, so the bundled browser is found.
"""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# --- data files -------------------------------------------------------------
datas = [
    ("app/templates", "app/templates"),
    ("app/static", "app/static"),
]
# Sweep the entire playwright package, including the bundled Chromium binaries
# (present because we build with PLAYWRIGHT_BROWSERS_PATH=0).
datas += collect_data_files("playwright")

# --- hidden imports ---------------------------------------------------------
# Flask/Jinja and our lazily-imported modules can be missed by static analysis.
hiddenimports = []
hiddenimports += collect_submodules("playwright")
hiddenimports += [
    "app",
    "app.routes",
    "app.modules.pdf",
    "app.modules.scanner",
    "app.modules.free_report",
    "app.modules.report_builder",
    "app.modules.dns_check",
    "app.modules.ssl_check",
    "app.modules.vuln_lookup",
    "app.modules.compliance",
    "app.modules.runbook",
    "app.modules.topology",
    "app.modules.netinfo",
    "app.modules.validation_agent",
    "app.modules.engineer_modules",
    "app.modules.workspace",
    "app.modules.webscan",
    "app.modules.deepprobe",
    "app.modules.credtest",
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["weasyprint"],  # not used in the frozen build; Chromium is the engine
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="SounRunner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # keep the console: shows the local URL + PDF engine line
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="app/static/logo.png" if __import__("os").path.exists("app/static/logo.png") else None,
)
