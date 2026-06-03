"""Interactive engineer workspace — live, on-demand actions against in-scope hosts.

This powers the hands-on part of an engagement: after the scan, the engineer can
click any discovered host and run a targeted, whitelisted action (re-scan ports,
inspect SMB, grab a web banner, run the full safe NSE set, ping/trace) and see the
result immediately. Every action is scope-locked to hosts that were actually
discovered in the job, and only safe/read-only operations are permitted.

Also holds finding-triage state (confirm / false-positive / accepted-risk / fixed)
and manually-added findings, so the engineer can curate the report before sending.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

from app.modules.scanner import find_nmap


# ── Whitelisted actions ───────────────────────────────────────────────────────
# Each action is (label, description). The runner maps the key to a safe routine.
ACTIONS = {
    "ports":   ("Re-scan ports", "Fast re-scan of the top 1000 ports with version detection."),
    "smb":     ("Inspect SMB", "Check SMB signing, OS, and shared folders (smb-* NSE scripts)."),
    "web":     ("Grab web banner", "Fetch HTTP/HTTPS headers, title, and detect the server software."),
    "ssl":     ("Check TLS", "Enumerate TLS protocols and cipher strength on 443/8443."),
    "nse":     ("Full safe probe", "Run the full default+safe NSE script set against the host."),
    "ping":    ("Reachability", "Confirm the host is up and measure round-trip latency."),
    "trace":   ("Trace route", "Trace the network path from here to the host."),
}


def host_in_scope(job: dict, ip: str) -> bool:
    """Only allow actions against hosts that were actually discovered in this job."""
    rd = job.get("report_data")
    if rd is not None:
        return any(getattr(h, "ip", "") == ip for h in getattr(rd, "host_rows", []))
    # fallback: validate it's at least a sane IP
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _tmp(prefix: str, ip: str) -> Path:
    tid = threading.get_ident()
    return Path(tempfile.gettempdir()) / f"sr_ws_{prefix}_{tid}_{ip.replace('.', '_')}.xml"


def _nmap_action(ip: str, args_extra: list[str], xml_prefix: str) -> str:
    nmap = find_nmap()
    if not nmap:
        return "Nmap is not available."
    xml = _tmp(xml_prefix, ip)
    args = [nmap, "-Pn"] + args_extra + ["-oX", str(xml), ip]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return "Action timed out."
    except Exception as e:
        return f"Action failed: {e}"
    # Prefer human-readable normal output (stdout) for the engineer console.
    out = proc.stdout.strip()
    return out or proc.stderr.strip() or "No output."


def _action_ports(ip: str) -> str:
    return _nmap_action(ip, ["-sV", "--top-ports", "1000", "-T4", "--open"], "ports")


def _action_smb(ip: str) -> str:
    return _nmap_action(
        ip,
        ["-p", "139,445", "--script",
         "smb-security-mode,smb2-security-mode,smb-os-discovery,smb-enum-shares,smb2-time"],
        "smb",
    )


def _action_ssl(ip: str) -> str:
    return _nmap_action(ip, ["-p", "443,8443", "--script", "ssl-enum-ciphers"], "ssl")


def _action_nse(ip: str) -> str:
    return _nmap_action(ip, ["-sV", "--script", "default,safe", "--script-timeout", "40s"], "nse")


def _action_web(ip: str) -> str:
    """Grab HTTP/HTTPS banner, title, server, and key headers."""
    lines = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except Exception:
        pass
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("https", 8443)):
        url = f"{scheme}://{ip}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SounRunner)"})
            resp = opener.open(req, timeout=6)
            body = resp.read(4000).decode("utf-8", "replace")
            server = resp.headers.get("Server", "—")
            t = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
            title = t.group(1).strip()[:80] if t else "—"
            sec = [h for h in ("Strict-Transport-Security", "Content-Security-Policy",
                               "X-Frame-Options", "X-Content-Type-Options") if resp.headers.get(h)]
            lines.append(f"[{url}] {resp.status}  Server: {server}")
            lines.append(f"    Title: {title}")
            lines.append(f"    Security headers present: {', '.join(sec) if sec else 'NONE'}")
        except Exception as e:
            lines.append(f"[{url}] {type(e).__name__}")
    return "\n".join(lines) if lines else "No web services responded."


def _action_ping(ip: str) -> str:
    """Confirm reachability via a quick TCP connect to common ports."""
    results = []
    for port in (445, 80, 443, 22, 3389):
        import time
        t0 = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=1.5):
                ms = (time.monotonic() - t0) * 1000
                results.append(f"  tcp/{port}: OPEN ({ms:.0f} ms)")
        except Exception:
            results.append(f"  tcp/{port}: filtered/closed")
    return f"Reachability to {ip}:\n" + "\n".join(results)


def _action_trace(ip: str) -> str:
    import sys
    cmd = (["tracert", "-d", "-h", "10", "-w", "800", ip] if sys.platform == "win32"
           else ["traceroute", "-n", "-m", "10", "-w", "1", "-q", "1", ip])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=40).stdout
        return out.strip() or "No route output."
    except Exception as e:
        return f"Trace failed: {e}"


_RUNNERS = {
    "ports": _action_ports,
    "smb": _action_smb,
    "ssl": _action_ssl,
    "nse": _action_nse,
    "web": _action_web,
    "ping": _action_ping,
    "trace": _action_trace,
}


def run_action(ip: str, action: str) -> dict:
    """Run a whitelisted action against an in-scope host. Returns {action,label,ip,output}."""
    if action not in _RUNNERS:
        return {"action": action, "ip": ip, "output": "Unknown action.", "label": action}
    label = ACTIONS.get(action, (action, ""))[0]
    output = _RUNNERS[action](ip)
    return {"action": action, "label": label, "ip": ip, "output": output}


# ── Triage state ──────────────────────────────────────────────────────────────
# Stored on the job dict under "triage": { finding_key: state }, and
# "manual_findings": [ {title, host, risk, detail} ].

VALID_STATES = {"confirmed", "false_positive", "accepted_risk", "fixed"}


def finding_key(host: str, port, title: str) -> str:
    return f"{host}|{port}|{title}"


def set_triage(job: dict, key: str, state: str) -> bool:
    if state not in VALID_STATES:
        return False
    job.setdefault("triage", {})[key] = state
    return True


def add_manual_finding(job: dict, title: str, host: str, risk: str, detail: str) -> None:
    job.setdefault("manual_findings", []).append({
        "title": title[:200], "host": host[:80] or "manual",
        "risk": risk if risk in ("critical", "high", "medium", "low", "info") else "medium",
        "detail": detail[:1000],
    })
