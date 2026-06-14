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
    exe_full = str(exe_path)
    exe_name = exe_path.name
    bat = exe_path.parent / "_sr_cleanup.bat"
    pid = os.getpid()
    # Wait (bounded) for OUR pid+image to exit, then delete the exe by full path
    # (bounded retries), then self-delete. Bounded loops avoid spinning forever
    # on PID reuse or an undeletable file. Image-name filter avoids matching the
    # PID digits elsewhere in tasklist output.
    script = f"""@echo off
set /a tries=0
:waitloop
tasklist /FI "PID eq {pid}" /FI "IMAGENAME eq {exe_name}" /NH 2>NUL | findstr /I "{exe_name}" >NUL
if errorlevel 1 goto delloop
set /a tries+=1
if %tries% GEQ 30 goto delloop
timeout /t 1 /nobreak >NUL
goto waitloop
:delloop
set /a dtries=0
:delretry
del /f /q "{exe_full}" >NUL 2>&1
if not exist "{exe_full}" goto done
set /a dtries+=1
if %dtries% GEQ 15 goto done
timeout /t 1 /nobreak >NUL
goto delretry
:done
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
    """Schedule deletion of the project working dir (source-run wipe).

    A running process CANNOT reliably delete its own directory: on Windows the
    interpreter locks the current working directory and every loaded module/DLL,
    so an in-process ``shutil.rmtree`` only partially succeeds (and silently, with
    ignore_errors). So — exactly like the frozen .exe path — we hand the job to a
    DETACHED cleaner that waits for THIS process to exit, then force-removes the
    whole project directory. The export (``keep``) lives on the Desktop, outside
    project_dir, so it is never in the delete target.

    All the safety guards run HERE, before anything is scheduled, so a bad layout
    aborts the wipe before any deletion command is spawned.
    """
    project_dir = Path(project_dir).resolve()
    if keep is not None:
        keep = Path(keep).resolve()
        if keep == project_dir or keep in project_dir.parents or project_dir in keep.parents:
            raise IOError("refusing to wipe: export folder overlaps the app directory")
    # Don't delete obviously-wrong roots.
    if project_dir == Path.home().resolve() or project_dir.parent == project_dir:
        raise IOError("refusing to wipe an unsafe directory")
    # Allowlist guard: only delete something that actually LOOKS like this app,
    # so an unexpected layout can never make us remove the wrong directory.
    signature = ["main.py", "app", "requirements.txt"]
    if not all((project_dir / s).exists() for s in signature):
        raise IOError(
            f"refusing to wipe {project_dir}: it does not look like the SounRunner app "
            f"(missing one of {signature})"
        )
    _schedule_delete_dir(project_dir)


def _schedule_delete_dir(project_dir: Path) -> None:
    """Spawn a detached cleaner that waits for our PID to exit, then removes
    ``project_dir`` in full. Windows uses a batch (cmd); POSIX uses a shell so
    the operator can wipe a source run on a Mac/Linux test box too.
    """
    pid = os.getpid()
    target = str(project_dir)

    if sys.platform == "win32":
        # Drop the cleaner OUTSIDE project_dir (in TEMP) so removing the project
        # can't delete the running script out from under cmd.
        import tempfile
        bat = Path(tempfile.gettempdir()) / f"_sr_wipe_{pid}.bat"
        # The running image for a source run is python.exe (or pythonw.exe);
        # filter on it so the PID digits can't match elsewhere in tasklist output.
        img = Path(sys.executable).name or "python.exe"
        # Wait (bounded) for our PID to exit, then rmdir /s /q with bounded
        # retries (the OS may hold the dir for a moment after we exit), then
        # self-delete the batch. Bounded loops never spin forever.
        script = f"""@echo off
set /a tries=0
:waitloop
tasklist /FI "PID eq {pid}" /FI "IMAGENAME eq {img}" /NH 2>NUL | findstr /I "{img}" >NUL
if errorlevel 1 goto delloop
set /a tries+=1
if %tries% GEQ 30 goto delloop
timeout /t 1 /nobreak >NUL
goto waitloop
:delloop
set /a dtries=0
:delretry
rmdir /s /q "{target}" >NUL 2>&1
if not exist "{target}" goto done
set /a dtries+=1
if %dtries% GEQ 20 goto done
timeout /t 1 /nobreak >NUL
goto delretry
:done
del /f /q "%~f0" >NUL 2>&1
"""
        bat.write_text(script, encoding="utf-8")
        DETACHED = 0x00000008          # DETACHED_PROCESS
        CREATE_NO_WINDOW = 0x08000000
        subprocess.Popen(
            ["cmd", "/c", str(bat)],
            cwd=str(bat.parent),       # NOT inside the dir we're about to delete
            creationflags=DETACHED | CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    else:
        # POSIX (Mac/Linux source-run test machines): a detached shell waits for
        # our PID to exit, then rm -rf the project dir. cwd is /, never the target.
        sh = (
            f"i=0; while kill -0 {pid} 2>/dev/null && [ $i -lt 30 ]; do "
            f"sleep 1; i=$((i+1)); done; rm -rf {_sh_quote(target)}"
        )
        subprocess.Popen(
            ["/bin/sh", "-c", sh],
            cwd="/",
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,    # fully detach from this process group
            close_fds=True,
        )


def _sh_quote(path: str) -> str:
    """Single-quote a path for safe use in a /bin/sh -c command."""
    return "'" + path.replace("'", "'\\''") + "'"


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

    # Both paths now delete via a DETACHED cleaner that fires AFTER this process
    # exits (a running process can't reliably delete its own files on Windows),
    # so removal isn't confirmed at response time — it's scheduled and trusted.
    removed = "App will remove itself once this window closes."
    saved = (f"{count} report file(s) saved to {export_path}."
             if export_path else "No reports found to save.")
    return {"ok": True, "export_path": str(export_path) if export_path else None,
            "count": count, "mode": mode, "message": f"{saved} {removed}"}
