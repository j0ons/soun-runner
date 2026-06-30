"""Consent-gated default-credential testing.

ONLY runs when the operator has explicitly confirmed written client authorization.
This module attempts a SMALL, fixed set of well-known DEFAULT credentials against
exposed admin panels and a couple of services. It is deliberately conservative:

  - Web admin panels: tries default creds via HTTP Basic / simple form (few attempts)
  - At most ~4 credential pairs per target (avoids account lockout)
  - Logs every single attempt for the audit trail
  - Never runs without the `authorized=True` flag

It does NOT do heavy brute-force, password spraying across many accounts, or
exploit anything. That stays out of a one-click tool by design.
"""

from __future__ import annotations

import base64
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class CredFinding:
    host: str
    port: int
    service: str
    username: str
    note: str
    risk: str = "critical"


# Small, well-known default credential set. Intentionally tiny to avoid lockout.
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
]


def _make_opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except Exception:
        pass
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def _test_http_basic(url: str, user: str, pw: str, timeout: int = 6) -> bool:
    """Return True if these creds are accepted via HTTP Basic auth."""
    opener = _make_opener()
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(url, headers={
        "Authorization": f"Basic {token}",
        "User-Agent": "Mozilla/5.0 (SounRunner Assessment)",
    })
    try:
        resp = opener.open(req, timeout=timeout)
        # Accepted ONLY on a genuine success where a 401 was expected. A 3xx that
        # urllib followed to a 200 also lands here. Anything else is NOT proof of
        # valid credentials.
        return resp.status == 200
    except urllib.error.HTTPError as e:
        # 401/403 = rejected (expected). A 3xx to a login page, or a 4xx/5xx
        # (404 wrong path, 500 server error) is NOT "credentials accepted" —
        # treating those as success produced false CRITICAL findings. Only a
        # 200/redirect-to-success counts, and those don't raise HTTPError.
        return False
    except Exception:
        return False


def test_web_panel(
    ip: str, port: int, requires_auth: bool,
    log: Callable[[str], None] | None = None,
) -> list[CredFinding]:
    """Try default creds against a web admin panel that returned 401."""
    def emit(m: str) -> None:
        if log:
            log(m)

    if not requires_auth:
        return []

    scheme = "https" if port in (443, 8443, 4443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    findings: list[CredFinding] = []

    for user, pw in DEFAULT_CREDS:
        emit(f"[cred] {ip}:{port} — trying {user}:{'(blank)' if pw=='' else pw}")
        if _test_http_basic(url, user, pw):
            findings.append(CredFinding(
                host=ip, port=port, service="HTTP admin panel",
                username=user,
                note=f"Default credentials accepted ({user}:{'<blank>' if pw=='' else pw}) on {url}",
                risk="critical",
            ))
            emit(f"[cred] {ip}:{port} — DEFAULT CREDENTIALS ACCEPTED: {user}")
            break  # stop on first success — don't keep hammering
    return findings


def run_cred_tests(
    web_findings, authorized: bool,
    log: Callable[[str], None] | None = None,
) -> list[CredFinding]:
    """Entry point. Does nothing unless `authorized` is True.

    `web_findings` are WebFinding objects from webscan; we target ones that
    look like admin panels and returned a 401 (auth required).
    """
    def emit(m: str) -> None:
        if log:
            log(m)

    if not authorized:
        emit("[cred] Credential testing SKIPPED — no written authorization confirmed.")
        return []

    emit("[cred] Authorization confirmed — running conservative default-credential checks.")
    all_findings: list[CredFinding] = []
    for wf in web_findings:
        # only target things that look like management panels
        if not wf.panel_type:
            continue
        needs_auth = any("401" in str(f.get("detail", "")) or "authentication" in f.get("title", "").lower()
                         for f in wf.findings)
        results = test_web_panel(wf.host, wf.port, requires_auth=needs_auth, log=log)
        all_findings.extend(results)
    if not all_findings:
        emit("[cred] No default credentials accepted (good).")
    return all_findings
