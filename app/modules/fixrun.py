"""Execute a generated SounRunner fix — locally or on a remote host.

This is the engine behind the report's "Run the fix" action. It takes a
``FixScript`` (from ``fixgen``) and actually applies it:

  - LOCAL  : run the fix on THIS machine (the engineer's box on-site) via the
             native interpreter — PowerShell for windows fixes, bash for linux.
  - REMOTE : push the fix to the target host —
               * Windows target -> WinRM  (pywinrm)
               * Linux  target  -> SSH    (paramiko)

CREDENTIAL HANDLING (non-negotiable for this private tool)
  - Credentials arrive per-run from the UI, are passed straight to the transport,
    and are NEVER written to disk, NEVER logged, and NEVER echoed back in any
    result. The caller holds them only for the duration of the call.
  - We scrub the returned stdout/stderr of the password if it ever appears, as a
    backstop against a remote tool echoing it.

SAFETY
  - Only ``windows``/``linux`` platform fixes are auto-runnable. ``dns``/``manual``
    fixes are configuration changes elsewhere and are returned as not-runnable
    (the operator applies them by hand from the steps).
  - The matching rollback script is always available via the existing
    /fix/<job>/rollback/<key> route, so any run is reversible.
  - Remote deps (paramiko/pywinrm) are imported lazily; if they're missing the
    call returns a clear, actionable error instead of crashing the app.

Returns a plain dict (JSON-serialisable) — never raises to the route:
    {ok, ran, transport, exit_code, stdout, stderr, error}
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


# Bound every execution so a hung fix can't wedge the worker thread.
_LOCAL_TIMEOUT = 180     # seconds for a local PowerShell/bash run
_REMOTE_TIMEOUT = 180    # seconds for an SSH/WinRM run


def _scrub(text: str, secret: str) -> str:
    """Remove a secret from output text (defence-in-depth — creds must not leak
    back through a tool that echoes them)."""
    if not text:
        return text or ""
    if secret:
        text = text.replace(secret, "********")
    return text


def _result(ok, ran, transport, exit_code=None, stdout="", stderr="", error="", secret=""):
    return {
        "ok": bool(ok),
        "ran": bool(ran),
        "transport": transport,
        "exit_code": exit_code,
        "stdout": _scrub(stdout, secret)[:20000],   # cap so a chatty fix can't bloat the response
        "stderr": _scrub(stderr, secret)[:20000],
        "error": error,
    }


def is_runnable(fix) -> bool:
    """True when this fix can be auto-executed (windows/linux), as opposed to a
    DNS/manual configuration change the operator applies elsewhere."""
    return getattr(fix, "platform", "") in ("windows", "linux")


def remote_available() -> dict:
    """Which remote transports are importable on this machine (for the UI)."""
    avail = {"ssh": False, "winrm": False}
    try:
        import paramiko  # noqa: F401
        avail["ssh"] = True
    except Exception:
        pass
    try:
        import winrm  # noqa: F401
        avail["winrm"] = True
    except Exception:
        pass
    return avail


# ── LOCAL execution ─────────────────────────────────────────────────────────

def _run_local(fix) -> dict:
    """Run the fix on THIS machine via the native interpreter."""
    script = fix.fix_script or ""
    if fix.platform == "windows":
        if sys.platform != "win32":
            return _result(False, False, "local",
                           error="This is a Windows fix; run it from the on-site Windows machine.")
        # Write to a temp .ps1 and execute with an unrestricted, non-interactive
        # PowerShell. The app already runs elevated on the client box, so this
        # inherits Administrator. -NoProfile keeps it deterministic.
        tmp = Path(tempfile.gettempdir()) / "_sr_fix.ps1"
        try:
            tmp.write_text(script, encoding="utf-8")
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-File", str(tmp)],
                capture_output=True, text=True, timeout=_LOCAL_TIMEOUT,
            )
            return _result(proc.returncode == 0, True, "local",
                           exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except subprocess.TimeoutExpired:
            return _result(False, True, "local", error=f"Fix timed out after {_LOCAL_TIMEOUT}s.")
        except Exception as exc:
            return _result(False, False, "local", error=f"Local run failed: {exc}")
        finally:
            try:
                tmp.unlink()
            except Exception:
                pass
    else:  # linux/bash
        if sys.platform == "win32":
            return _result(False, False, "local",
                           error="This is a Linux fix; run it from a Linux/macOS box or push it over SSH.")
        try:
            proc = subprocess.run(
                ["/bin/bash", "-c", script],
                capture_output=True, text=True, timeout=_LOCAL_TIMEOUT,
            )
            return _result(proc.returncode == 0, True, "local",
                           exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        except subprocess.TimeoutExpired:
            return _result(False, True, "local", error=f"Fix timed out after {_LOCAL_TIMEOUT}s.")
        except Exception as exc:
            return _result(False, False, "local", error=f"Local run failed: {exc}")


# ── REMOTE execution ────────────────────────────────────────────────────────

def _run_ssh(fix, target, username, password, key_text) -> dict:
    """Push a bash fix to a Linux host over SSH (paramiko)."""
    try:
        import paramiko
    except Exception:
        return _result(False, False, "ssh",
                       error="SSH support not installed. Run: pip install paramiko")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = dict(hostname=target, port=22, username=username,
                              timeout=20, banner_timeout=20, auth_timeout=20,
                              allow_agent=False, look_for_keys=False)
        if key_text:
            from io import StringIO
            pkey = None
            for loader in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                try:
                    pkey = loader.from_private_key(StringIO(key_text),
                                                   password=password or None)
                    break
                except Exception:
                    continue
            if pkey is None:
                return _result(False, False, "ssh", error="Could not parse the private key.")
            connect_kwargs["pkey"] = pkey
        else:
            connect_kwargs["password"] = password
        client.connect(**connect_kwargs)
        # Run the script via a heredoc-free bash -s stdin feed.
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=_REMOTE_TIMEOUT)
        stdin.write(fix.fix_script or "")
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return _result(code == 0, True, "ssh", exit_code=code,
                       stdout=out, stderr=err, secret=password or "")
    except Exception as exc:
        return _result(False, False, "ssh", error=f"SSH run failed: {exc}", secret=password or "")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _run_winrm(fix, target, username, password) -> dict:
    """Push a PowerShell fix to a Windows host over WinRM (pywinrm)."""
    try:
        import winrm
    except Exception:
        return _result(False, False, "winrm",
                       error="WinRM support not installed. Run: pip install pywinrm")
    try:
        # Try HTTP (5985) first, then HTTPS (5986). Negotiate auth covers
        # local + domain accounts on a default WinRM setup.
        last_exc = None
        for scheme, port in (("http", 5985), ("https", 5986)):
            try:
                session = winrm.Session(
                    f"{scheme}://{target}:{port}/wsman",
                    auth=(username, password),
                    transport="ntlm",
                    server_cert_validation="ignore",
                )
                r = session.run_ps(fix.fix_script or "")
                out = (r.std_out or b"").decode("utf-8", "replace")
                err = (r.std_err or b"").decode("utf-8", "replace")
                return _result(r.status_code == 0, True, "winrm",
                               exit_code=r.status_code, stdout=out, stderr=err,
                               secret=password or "")
            except Exception as exc:
                last_exc = exc
                continue
        return _result(False, False, "winrm",
                       error=f"WinRM run failed (5985/5986): {last_exc}", secret=password or "")
    except Exception as exc:
        return _result(False, False, "winrm", error=f"WinRM run failed: {exc}", secret=password or "")


# ── public entry point ──────────────────────────────────────────────────────

def run_fix(fix, mode: str, target: str = "", username: str = "",
            password: str = "", key_text: str = "") -> dict:
    """Apply ``fix`` and return a JSON-serialisable result.

    mode:
      "local"  -> run on this machine (no credentials used)
      "remote" -> push to ``target`` over SSH (linux) or WinRM (windows)

    Credentials are used transiently for the transport only and never stored
    or logged. The caller is responsible for not retaining them after this call.
    """
    if not is_runnable(fix):
        return _result(False, False, "none",
                       error="This fix is a configuration change (DNS/web/device). "
                             "Apply it manually from the steps — it is not auto-runnable.")

    if mode == "local":
        return _run_local(fix)

    if mode == "remote":
        if not target:
            return _result(False, False, "remote", error="No target host given for remote run.")
        if not username:
            return _result(False, False, "remote", error="A username is required for remote run.")
        if fix.platform == "windows":
            return _run_winrm(fix, target, username, password)
        return _run_ssh(fix, target, username, password, key_text)

    return _result(False, False, "none", error=f"Unknown run mode: {mode}")
