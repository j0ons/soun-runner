"""Web / admin panel discovery and HTTP security analysis.

For every HTTP/HTTPS service found, this:
  - grabs the Server banner, page title, and key response headers
  - fingerprints known device admin panels (routers, CCTV/DVR, NAS, iDRAC/iLO,
    printers) so the engineer knows exactly what's exposed
  - flags missing HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
  - flags login/admin pages reachable on the network (default-credential risk)

stdlib only (urllib + ssl). Read-only GET requests, no logins.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class WebFinding:
    host: str
    port: int
    url: str
    title: str = ""
    server: str = ""
    panel_type: str = ""      # e.g. "Router Admin Panel", "CCTV/DVR", "NAS"
    status_code: int = 0
    findings: list = field(default_factory=list)   # list[dict(title, detail, risk, recommendation)]

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def top_risk(self) -> str:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if not self.findings:
            return "info"
        return min((f["risk"] for f in self.findings), key=lambda r: order.get(r, 9))


# Admin-panel fingerprints — title/server/body signatures → device class
PANEL_SIGNATURES = [
    (r"linksys|smart wi-?fi", "Router Admin Panel (Linksys)"),
    (r"tp-link|tl-wr|archer", "Router Admin Panel (TP-Link)"),
    (r"netgear|routerlogin", "Router Admin Panel (Netgear)"),
    (r"mikrotik|routeros|winbox", "Router Admin Panel (MikroTik)"),
    (r"fortigate|fortinet", "Firewall Admin Panel (FortiGate)"),
    (r"pfsense|opnsense", "Firewall Admin Panel"),
    (r"unifi|ubiquiti", "Network Controller (Ubiquiti)"),
    (r"idrac|integrated dell remote", "Server Management (Dell iDRAC)"),
    (r"\bilo\b|integrated lights-out|hpe?ilo", "Server Management (HP iLO)"),
    (r"hikvision|dahua|dvr|nvr|webcam|ip camera|surveillance", "CCTV / DVR / Camera"),
    (r"synology|diskstation|dsm", "NAS (Synology)"),
    (r"qnap|qts", "NAS (QNAP)"),
    (r"webmin|usermin", "Server Admin Panel (Webmin)"),
    (r"cpanel|whm|plesk", "Hosting Control Panel"),
    (r"phpmyadmin", "Database Admin Panel (phpMyAdmin)"),
    (r"jenkins", "CI/CD Panel (Jenkins)"),
    (r"grafana", "Monitoring Panel (Grafana)"),
    (r"printer|jetdirect|laserjet|officejet", "Printer Web Interface"),
    (r"vmware esxi|vsphere", "Hypervisor (VMware ESXi)"),
    (r"proxmox", "Hypervisor (Proxmox)"),
    (r"router|gateway|admin login|sign in|log in|authentication required", "Generic Admin / Login Panel"),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS not set", "medium",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to force HTTPS and prevent downgrade attacks."),
    "Content-Security-Policy": ("CSP not set", "low",
        "Add a Content-Security-Policy header to mitigate cross-site scripting (XSS) and data injection."),
    "X-Frame-Options": ("X-Frame-Options not set", "low",
        "Add 'X-Frame-Options: SAMEORIGIN' (or a CSP frame-ancestors directive) to prevent clickjacking."),
    "X-Content-Type-Options": ("X-Content-Type-Options not set", "low",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing attacks."),
}


def _make_opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # allow weak DH so we can still fingerprint legacy device panels
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except Exception:
        pass
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    return urllib.request.build_opener(https_handler)


def _fingerprint_panel(title: str, server: str, body: str) -> str:
    blob = f"{title} {server} {body[:2000]}".lower()
    for pat, label in PANEL_SIGNATURES:
        if re.search(pat, blob, re.I):
            return label
    return ""


def scan_web_service(ip: str, port: int, log: Callable[[str], None] | None = None) -> "WebFinding | None":
    """Fetch one HTTP(S) service and analyse it."""
    def emit(m: str) -> None:
        if log:
            log(m)

    scheme = "https" if port in (443, 8443, 4443, 8444) else "http"
    url = f"{scheme}://{ip}:{port}/"
    wf = WebFinding(host=ip, port=port, url=url)

    opener = _make_opener()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SounRunner Assessment)"})
        resp = opener.open(req, timeout=8)
        body = resp.read(8000).decode("utf-8", "replace")
        wf.status_code = resp.status
        wf.server = resp.headers.get("Server", "")
        hdrs = resp.headers
    except urllib.error.HTTPError as e:
        # auth-required / error pages still tell us a lot
        wf.status_code = e.code
        wf.server = e.headers.get("Server", "") if e.headers else ""
        body = ""
        hdrs = e.headers
        if e.code == 401:
            wf.findings.append({
                "title": "Authentication-protected web service",
                "detail": f"The service at {url} requires authentication (HTTP 401). Verify it is not using default or weak credentials.",
                "risk": "medium",
                "recommendation": "Confirm strong, unique credentials are set. Restrict access to a management VLAN or VPN.",
            })
    except Exception as e:
        emit(f"[web] {url} — unreachable ({type(e).__name__})")
        return None

    # title
    t = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
    wf.title = t.group(1).strip()[:80] if t else ""

    # panel fingerprint
    wf.panel_type = _fingerprint_panel(wf.title, wf.server, body)

    # ── exposed admin panel finding ──────────────────────────────────────────
    if wf.panel_type:
        is_sensitive = any(k in wf.panel_type for k in
                           ("Router", "Firewall", "iDRAC", "iLO", "CCTV", "NAS",
                            "Hypervisor", "Database", "Webmin", "Jenkins", "Hosting"))
        wf.findings.append({
            "title": f"Exposed admin interface: {wf.panel_type}",
            "detail": f"A {wf.panel_type} is reachable at {url}" + (f" (\"{wf.title}\")" if wf.title else "") +
                      ". Management interfaces exposed on the network are a primary target — especially if they use default credentials.",
            "risk": "high" if is_sensitive else "medium",
            "recommendation": "Restrict this admin interface to a management VLAN or VPN only. Change all default credentials. Enable HTTPS and account lockout.",
        })
        emit(f"[web] {ip}:{port} — PANEL: {wf.panel_type}")

    # ── plaintext HTTP login ─────────────────────────────────────────────────
    login_signal = re.search(r"type=[\"']?password|name=[\"']?password|login|signin", body, re.I)
    if scheme == "http" and login_signal:
        wf.findings.append({
            "title": "Login form served over plaintext HTTP",
            "detail": f"The page at {url} contains a login form but is served over unencrypted HTTP. Credentials entered here are transmitted in cleartext and can be captured on the network.",
            "risk": "high",
            "recommendation": "Serve all login pages over HTTPS only. Redirect HTTP→HTTPS and install a valid TLS certificate.",
        })

    # ── security headers (only meaningful on a 200 page) ─────────────────────
    if wf.status_code == 200 and hdrs is not None:
        missing = []
        for hname, (title, risk, rec) in SECURITY_HEADERS.items():
            if not hdrs.get(hname):
                missing.append((hname, title, risk, rec))
        # only report HSTS individually (more important); bundle the rest
        for hname, title, risk, rec in missing:
            if hname == "Strict-Transport-Security" and scheme == "https":
                wf.findings.append({
                    "title": title, "detail":
                        f"The HTTPS service at {url} does not set HSTS, allowing protocol-downgrade attacks.",
                    "risk": risk, "recommendation": rec,
                })
        bundle = [m for m in missing if m[0] != "Strict-Transport-Security"]
        if len(bundle) >= 2:
            names = ", ".join(m[0] for m in bundle)
            wf.findings.append({
                "title": f"Missing HTTP security headers ({len(bundle)})",
                "detail": f"The web service at {url} is missing recommended security headers: {names}. These protect users against clickjacking, MIME-sniffing, and injection attacks.",
                "risk": "low",
                "recommendation": "Add X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy headers at the web server or reverse proxy.",
            })

    return wf if (wf.has_findings or wf.panel_type or wf.title) else None


# Ports we treat as web services
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 4443, 8444, 10000, 5000, 9000}


def scan_web_hosts(hosts, log: Callable[[str], None] | None = None) -> list[WebFinding]:
    """Scan all web services across discovered hosts."""
    results: list[WebFinding] = []
    for h in hosts:
        for port in h.open_ports:
            if port in WEB_PORTS:
                wf = scan_web_service(h.ip, port, log=log)
                if wf:
                    results.append(wf)
    return results
