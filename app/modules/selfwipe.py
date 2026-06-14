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


# Sibling folders the setup script (SETUP-AND-RUN.ps1) drops next to the project
# on the Desktop. A full wipe should leave no trace, so these go too — but ONLY
# these exact names, and only when they sit directly beside the project dir.
_SETUP_ARTIFACTS = ("_sr_installers", "_sr_python", "_sr_git")


def _delete_source_tree(project_dir: Path, keep: Path | None) -> None:
    """Schedule deletion of the project dir AND the setup script's sibling
    artifacts (source-run wipe), leaving no trace on the client machine.

    A running process CANNOT reliably delete its own directory: on Windows the
    interpreter locks the current working directory and every loaded module/DLL
    (incl. a portable _sr_python it may be running from), so an in-process
    ``shutil.rmtree`` only partially succeeds (silently, with ignore_errors). So —
    exactly like the frozen .exe path — we hand the job to a DETACHED cleaner that
    waits for THIS process to exit, then force-removes every target. The export
    (``keep``) lives on the Desktop OUTSIDE these targets, so it is never touched.

    All safety guards run HERE, before anything is scheduled, so a bad layout
    aborts the wipe before any deletion command is spawned.
    """
    project_dir = Path(project_dir).resolve()
    keep_resolved = Path(keep).resolve() if keep is not None else None

    def _guard(target: Path) -> None:
        """Reject any target that is unsafe or overlaps the saved reports."""
        if target == Path.home().resolve() or target.parent == target:
            raise IOError(f"refusing to wipe an unsafe directory: {target}")
        if keep_resolved is not None and (
            keep_resolved == target
            or keep_resolved in target.parents
            or target in keep_resolved.parents
        ):
            raise IOError("refusing to wipe: export folder overlaps a delete target")

    # Project dir: full guards + signature allowlist so an unexpected layout can
    # never make us remove the wrong directory.
    _guard(project_dir)
    signature = ["main.py", "app", "requirements.txt"]
    if not all((project_dir / s).exists() for s in signature):
        raise IOError(
            f"refusing to wipe {project_dir}: it does not look like the SounRunner app "
            f"(missing one of {signature})"
        )

    targets = [project_dir]
    # Add the setup artifacts ONLY when they sit directly beside the project and
    # match the exact known names. Each is guarded the same way. We never glob or
    # walk — strictly this allowlist, strictly the project's own parent folder.
    parent = project_dir.parent
    for name in _SETUP_ARTIFACTS:
        sib = (parent / name).resolve()
        if sib.is_dir() and sib.name in _SETUP_ARTIFACTS and sib.parent == parent:
            _guard(sib)
            targets.append(sib)

    _schedule_delete(targets)


def _schedule_delete(targets: list[Path]) -> None:
    """Spawn a detached cleaner that waits for our PID to exit, then removes
    every path in ``targets`` in full. Windows uses a batch (cmd); POSIX uses a
    shell so the operator can wipe a source run on a Mac/Linux test box too.

    The cleaner itself lives in TEMP — never inside any target — so removing the
    targets can't delete the running cleaner out from under it.
    """
    pid = os.getpid()
    paths = [str(p) for p in targets]

    if sys.platform == "win32":
        import tempfile
        bat = Path(tempfile.gettempdir()) / f"_sr_wipe_{pid}.bat"
        # The running image for a source run is python.exe (or pythonw.exe);
        # filter on it so the PID digits can't match elsewhere in tasklist output.
        img = Path(sys.executable).name or "python.exe"
        # Per-target delete block: rmdir /s /q with bounded retries (the OS may
        # hold a dir for a moment after we exit). Bounded loops never spin forever.
        del_blocks = []
        for idx, tp in enumerate(paths):
            del_blocks.append(
                f"set /a d{idx}=0\n"
                f":del{idx}\n"
                f'rmdir /s /q "{tp}" >NUL 2>&1\n'
                f'if not exist "{tp}" goto next{idx}\n'
                f"set /a d{idx}+=1\n"
                f"if %d{idx}% GEQ 20 goto next{idx}\n"
                f"timeout /t 1 /nobreak >NUL\n"
                f"goto del{idx}\n"
                f":next{idx}"
            )
        del_section = "\n".join(del_blocks)
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
{del_section}
del /f /q "%~f0" >NUL 2>&1
"""
        bat.write_text(script, encoding="utf-8")
        DETACHED = 0x00000008          # DETACHED_PROCESS
        CREATE_NO_WINDOW = 0x08000000
        subprocess.Popen(
            ["cmd", "/c", str(bat)],
            cwd=str(bat.parent),       # NOT inside any dir we're about to delete
            creationflags=DETACHED | CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    else:
        # POSIX (Mac/Linux source-run test machines): a detached shell waits for
        # our PID to exit, then rm -rf each target. cwd is /, never a target.
        rm_cmds = " ; ".join(f"rm -rf {_sh_quote(p)}" for p in paths)
        sh = (
            f"i=0; while kill -0 {pid} 2>/dev/null && [ $i -lt 30 ]; do "
            f"sleep 1; i=$((i+1)); done; {rm_cmds}"
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
    removed = ("SounRunner and its setup files will be removed from this machine "
               "once this window closes." if mode == "source"
               else "App will remove itself once this window closes.")
    saved = (f"{count} report file(s) saved to {export_path}."
             if export_path else "No reports found to save.")
    return {"ok": True, "export_path": str(export_path) if export_path else None,
            "count": count, "mode": mode, "message": f"{saved} {removed}"}
