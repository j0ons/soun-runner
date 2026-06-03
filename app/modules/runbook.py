"""Remediation runbook generator + re-scan diff (proof-of-fix).

runbook(): turns the report's findings into an ordered, copy-paste remediation
plan grouped by priority — the document the engineer works from on-site.

diff_scans(): compares a new scan's findings against a prior job's findings to
produce a before/after proof-of-fix summary (fixed / still-open / new).
"""

from __future__ import annotations

from dataclasses import dataclass, field


RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Rough remediation effort/time per finding category keyword
EFFORT = [
    (["telnet", "ftp", "anonymous"], "15 min", "Disable legacy service"),
    (["smb signing", "signing disabled"], "30 min", "Group Policy change + reboot"),
    (["dmarc", "spf", "dkim"], "30 min", "DNS record change"),
    (["ssl", "tls", "cipher", "certificate", "hsts"], "1 hour", "Web server TLS config"),
    (["rdp", "remote desktop"], "1-2 hours", "VPN + NLA + firewall rule"),
    (["database", "mysql", "mssql", "mongodb", "redis", "postgres"], "1-2 hours", "Bind + firewall + auth"),
    (["end-of-life", "eol", "outdated", "unsupported"], "1-5 days", "OS/software migration"),
    (["admin interface", "admin panel", "exposed", "vnc"], "1 hour", "VLAN/VPN restriction"),
    (["default credential", "snmp"], "30 min", "Change credentials/strings"),
    (["security header", "header"], "30 min", "Web server header config"),
]


@dataclass
class RunbookStep:
    order: int
    risk: str
    title: str
    action: str
    effort: str
    effort_note: str
    host: str = ""
    port: int = 0


def _effort_for(blob: str) -> tuple[str, str]:
    b = blob.lower()
    for kws, eff, note in EFFORT:
        if any(k in b for k in kws):
            return eff, note
    return "30-60 min", "Standard remediation"


def build_runbook(findings) -> list[RunbookStep]:
    """Order findings by risk into a numbered remediation runbook."""
    ordered = sorted(findings, key=lambda f: RISK_ORDER.get(getattr(f, "risk", "info"), 9))
    steps: list[RunbookStep] = []
    for i, f in enumerate(ordered, 1):
        blob = f"{getattr(f,'title','')} {getattr(f,'detail','')}"
        eff, note = _effort_for(blob)
        steps.append(RunbookStep(
            order=i,
            risk=getattr(f, "risk", "info"),
            title=getattr(f, "title", ""),
            action=getattr(f, "recommendation", "") or "Review and restrict this exposure.",
            effort=eff,
            effort_note=note,
            host=getattr(f, "host", ""),
            port=getattr(f, "port", 0),
        ))
    return steps


@dataclass
class ScanDiff:
    fixed: list = field(default_factory=list)         # finding titles resolved
    still_open: list = field(default_factory=list)    # finding titles persisting
    new: list = field(default_factory=list)           # new finding titles
    prior_count: int = 0
    current_count: int = 0

    @property
    def fixed_count(self) -> int:
        return len(self.fixed)

    @property
    def remediation_rate(self) -> int:
        if self.prior_count == 0:
            return 0
        return round(100 * self.fixed_count / self.prior_count)


def _fkey(f) -> str:
    """Stable identity for a finding across scans."""
    return f"{getattr(f,'host','')}|{getattr(f,'port',0)}|{getattr(f,'title','')}"


def diff_scans(prior_findings, current_findings) -> ScanDiff:
    """Compare two finding sets → proof-of-fix diff."""
    prior = {_fkey(f): f for f in prior_findings}
    current = {_fkey(f): f for f in current_findings}

    d = ScanDiff(prior_count=len(prior), current_count=len(current))
    for k, f in prior.items():
        if k not in current:
            d.fixed.append({"title": getattr(f, "title", ""), "host": getattr(f, "host", ""), "risk": getattr(f, "risk", "")})
        else:
            d.still_open.append({"title": getattr(f, "title", ""), "host": getattr(f, "host", ""), "risk": getattr(f, "risk", "")})
    for k, f in current.items():
        if k not in prior:
            d.new.append({"title": getattr(f, "title", ""), "host": getattr(f, "host", ""), "risk": getattr(f, "risk", "")})
    return d
