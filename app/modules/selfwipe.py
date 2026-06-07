"""Self-wipe for the private SounRunner tool.

After an assessment, the operator can remove the tool from a client machine
without leaving traces — while KEEPING the generated reports.

Flow (see ``wipe()``):
  1. Export every report to a safe folder on the Desktop (verified copy) so the
     reports survive the wipe.
  2. Schedule deletion of the app itself:
       - frozen .exe  -> a detached batch waits for the process to exit, then
                         deletes the .exe (a running .exe can't delete itself).
       - source run   -> delete the project working dir.
     The reports folder and the export are NEVER inside the delete target.
  3. The caller then shuts the server down.

Design rules:
  - Export and VERIFY before scheduling any deletion. If export fails, we abort
    and delete nothing.
  - The exported reports live OUTSIDE the app directory (Desktop), so wiping the
    app can never touch them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _is_frozen() -> bool:
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")


def _desktop_dir() -> Path:
    """Best-effort path to the user's Desktop, with safe fallbacks."""
    home = Path.home()
    for candidate in (home / "Desktop", home / "OneDrive" / "Desktop"):
        if candidate.is_dir():
            return candidate
    return home  # fall back to home dir if no Desktop


def _unique_dir(base: Path, name: str) -> Path:
    """Return base/name, appending -1, -2, … if it already exists."""
    target = base / name
    i = 1
    while target.exists():
        target = base / f"{name}-{i}"
        i += 1
    return target


def export_reports(reports_dir: Path, stamp: str) -> tuple[Path | None, int]:
    """Copy all report files to a fresh folder on the Desktop.

    Returns (export_path, file_count). export_path is None if there were no
    reports to export. Raises on copy failure (caller aborts the wipe).
    """
    reports_dir = Path(reports_dir)
    if not reports_dir.is_dir():
        return None, 0

    files = [p for p in reports_dir.iterdir()
             if p.is_file() and p.suffix.lower() in (".pdf", ".html")]
    if not files:
        return None, 0

    dest = _unique_dir(_desktop_dir(), f"SounRunner-Reports-{stamp}")
    dest.mkdir(parents=True, exist_ok=False)

    copied = 0
    for f in files:
        shutil.copy2(f, dest / f.name)
        # verify each copy landed with matching size
        if not (dest / f.name).exists() or (dest / f.name).stat().st_size != f.stat().st_size:
            raise IOError(f"verification failed for {f.name}")
        copied += 1
    return dest, copied


def _schedule_delete_exe(exe_path: Path, keep: Path | None) -> None:
    """Spawn a detached Windows batch that waits, then deletes the .exe.

    A running .exe cannot delete itself, so we hand the job to a short batch
    that loops until the file is unlocked, removes it, then removes itself.
    `keep` (the export folder) is never inside exe_path's dir handling here, but
    we pass it only for clarity; the batch only targets the exe and its folder
    contents that are NOT the keep path.
    """
    exe_path = Path(exe_path)
    bat = exe_path.parent / "_sr_cleanup.bat"
    # Wait for PID to exit, retry-delete the exe, then delete this batch.
    pid = os.getpid()
    script = f"""@echo off
echo Cleaning up SounRunner...
:waitloop
tasklist /FI "PID eq {pid}" 2>NUL | find "{pid}" >NUL
if not errorlevel 1 (
  timeout /t 1 /nobreak >NUL
  goto waitloop
)
:delloop
del /f /q "{exe_path.name}" >NUL 2>&1
if exist "{exe_path.name}" (
  timeout /t 1 /nobreak >NUL
  goto delloop
)
del /f /q "%~f0" >NUL 2>&1
"""
    bat.write_text(script, encoding="utf-8")
    # Detached, no window, runs independently of this process.
    DETACHED = 0x00000008  # DETACHED_PROCESS
    CREATE_NO_WINDOW = 0x08000000
    subprocess.Popen(
        ["cmd", "/c", str(bat)],
        cwd=str(exe_path.parent),
        creationflags=DETACHED | CREATE_NO_WINDOW,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True,
    )


def _delete_source_tree(project_dir: Path, keep: Path | None) -> None:
    """Delete the project working dir (source-run wipe).

    Safety: refuse if the export (keep) is inside project_dir — it must be
    elsewhere (it is: it's on the Desktop) so reports can't be deleted.
    """
    project_dir = Path(project_dir).resolve()
    if keep is not None:
        keep = Path(keep).resolve()
        if keep == project_dir or keep in project_dir.parents or project_dir in keep.parents:
            raise IOError("refusing to wipe: export folder overlaps the app directory")
    # Don't delete obviously-wrong roots.
    if project_dir == Path.home().resolve() or project_dir.parent == project_dir:
        raise IOError("refusing to wipe an unsafe directory")
    shutil.rmtree(project_dir, ignore_errors=True)


def wipe(reports_dir: Path, stamp: str) -> dict:
    """Export reports, then schedule destruction of the app.

    Returns a result dict: {ok, export_path, count, mode, message}.
    Does NOT shut the server down — the caller does that after responding.
    On any failure during export, nothing is deleted.
    """
    try:
        export_path, count = export_reports(Path(reports_dir), stamp)
    except Exception as exc:
        return {"ok": False, "export_path": None, "count": 0,
                "mode": "frozen" if _is_frozen() else "source",
                "message": f"Export failed, nothing deleted: {exc}"}

    try:
        if _is_frozen():
            exe = Path(sys.executable)
            _schedule_delete_exe(exe, export_path)
            mode = "frozen"
        else:
            # Source run: project root is two levels up from this file
            # (app/modules/selfwipe.py -> project/).
            project_dir = Path(__file__).resolve().parents[2]
            _delete_source_tree(project_dir, export_path)
            mode = "source"
    except Exception as exc:
        return {"ok": False, "export_path": str(export_path) if export_path else None,
                "count": count, "mode": "frozen" if _is_frozen() else "source",
                "message": f"Reports saved, but app cleanup failed: {exc}"}

    msg = (f"{count} report file(s) saved to {export_path}. App removed."
           if export_path else "No reports found to save. App removed.")
    return {"ok": True, "export_path": str(export_path) if export_path else None,
            "count": count, "mode": mode, "message": msg}
