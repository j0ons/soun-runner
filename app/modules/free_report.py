"""Lightweight FREE-tier report builder.

The free version is deliberately simple: live hosts + exposed dangerous services
+ a basic per-service risk note + an optional quick CVE hint. No deep probing,
no validation agent, no compliance, no topology, no engineer modules.

Keeps its own small data shape so it can never accidentally pull in the heavy
advanced sections.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.modules.scanner import ScanResult, RISK_ORDER

RISK_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Informational",
}
RISK_COLOR = {
    "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
    "low": "#3b82f6", "info": "#6b7280",
}


@dataclass
class FreeFinding:
    risk: str
    service: str
    port: int
    host: str
    note: str
    fix: str = ""              # engineer remediation step
    plain_what: str = ""       # client: what this is, plain language
    plain_why: str = ""        # client: why it matters, plain language

    @property
    def risk_label(self) -> str:
        return RISK_LABEL.get(self.risk, self.risk)

    @property
    def risk_color(self) -> str:
        return RISK_COLOR.get(self.risk, "#6b7280")


@dataclass
class FreeHostRow:
    ip: str
    device_type: str
    device_icon: str
    ports: str
    risk: str
    risk_label: str
    hostname: str = ""


@dataclass
class FreeReport:
    client_name: str
    target: str
    generated_at: str
    hosts_up: int = 0
    total_open_ports: int = 0
    scan_error: str = ""
    findings: list = field(default_factory=list)
    host_rows: list = field(default_factory=list)
    summary: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "medium")

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def overall_risk(self) -> str:
        if self.critical_count:
            return "critical"
        if self.high_count:
            return "high"
        if self.medium_count:
            return "medium"
        if self.findings:
            return "low"
        return "info"

    @property
    def overall_risk_label(self) -> str:
        return RISK_LABEL.get(self.overall_risk, "Minimal")

    @property
    def overall_risk_color(self) -> str:
        return RISK_COLOR.get(self.overall_risk, "#6b7280")


def build_free_report(client_name: str, target: str, scan_result: ScanResult) -> FreeReport:
    rpt = FreeReport(
        client_name=client_name,
        target=target,
        generated_at=datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC"),
        scan_error=scan_result.error,
        hosts_up=scan_result.host_count,
        total_open_ports=sum(len(h.open_ports) for h in scan_result.hosts),
    )

    # Findings: only dangerous (critical/high/medium) exposed services
    for host, svc in scan_result.findings_by_risk():
        if svc.risk not in ("critical", "high", "medium"):
            continue
        kb = _PORT_KB.get(svc.port, {})
        rpt.findings.append(FreeFinding(
            risk=svc.risk,
            service=svc.name or f"Port {svc.port}",
            port=svc.port,
            host=host.display_full,
            note=svc.risk_reason or f"Port {svc.port}/{svc.protocol} is open and exposed.",
            fix=kb.get("fix", "Review whether this service must be exposed. Restrict it to specific trusted IPs with a firewall rule, or disable it if unused."),
            plain_what=kb.get("what", "A service on one of your devices is open to the network."),
            plain_why=kb.get("why", "Open services give attackers more ways to try to break in. Anything not needed should be turned off."),
        ))

    rpt.findings.sort(key=lambda f: RISK_ORDER.get(f.risk, 99))

    # Host inventory (simple)
    for h in scan_result.hosts:
        rpt.host_rows.append(FreeHostRow(
            ip=h.ip,
            hostname=(h.hostname if h.hostname and h.hostname != h.ip else ""),
            device_type=h.device_type,
            device_icon=h.device_icon,
            ports=", ".join(str(p) for p in h.open_ports[:14]),
            risk=h.highest_risk,
            risk_label=RISK_LABEL.get(h.highest_risk, ""),
        ))

    rpt.summary = _summary(rpt)
    return rpt


# Port knowledge base: engineer fix + plain-language what/why for clients.
_PORT_KB: dict[int, dict] = {
    21: {
        "fix": "Disable FTP. Use SFTP (port 22) instead. If FTP is required, restrict source IPs at the firewall and enforce FTPS.",
        "what": "An old-style file-transfer service is switched on and visible to the network.",
        "why": "It sends passwords in plain text, so anyone watching the network can steal the login. It should be turned off.",
    },
    22: {
        "fix": "Restrict SSH to known admin IPs via firewall. Disable password login; use SSH keys only. Consider a non-standard port.",
        "what": "A remote-control service (used by IT to manage a device) is reachable on the network.",
        "why": "If it's left open to everyone, attackers can try thousands of passwords to break in. It should be locked to your IT team only.",
    },
    23: {
        "fix": "Disable Telnet immediately and replace with SSH. There is no safe way to run Telnet.",
        "what": "A very old remote-control service is switched on.",
        "why": "It has no protection at all — passwords travel in plain text. This is one of the most dangerous things to leave on. Turn it off.",
    },
    25: {
        "fix": "Require authentication and STARTTLS for SMTP. Block port 25 inbound from the internet. Disable open relay.",
        "what": "An email-sending service is exposed.",
        "why": "If misconfigured, spammers and scammers can use it to send fake emails in your name. It needs to be locked down.",
    },
    53: {
        "fix": "Disable open/recursive DNS for outside clients. Restrict DNS to the internal network.",
        "what": "A service that translates website names to addresses is visible to the network.",
        "why": "Left open, it can be abused by attackers to amplify attacks against others. It should be restricted to your own network.",
    },
    80: {
        "fix": "Redirect all HTTP traffic to HTTPS (encrypted). Remove the plain HTTP listener once confirmed.",
        "what": "A website/admin page is being served without encryption.",
        "why": "Anything typed into it (like passwords) can be read by others on the network. It should always use the secure (HTTPS) version.",
    },
    110: {"fix": "Disable plaintext POP3. Require POP3S (port 995) with TLS.", "what": "An old email-collection service is exposed unencrypted.", "why": "Email and passwords can be read in transit. Switch to the encrypted version."},
    135: {"fix": "Block Windows RPC (port 135) at the firewall. Restrict to the management network only.", "what": "A core Windows networking service is reachable.", "why": "Attackers commonly target it to break into Windows machines. It should not be open across the network."},
    139: {"fix": "Disable NetBIOS over TCP/IP where not needed. Block port 139 at the firewall.", "what": "An old Windows file-sharing service is switched on.", "why": "It can leak information and be used to steal login credentials. It should be disabled if not needed."},
    143: {"fix": "Disable plaintext IMAP. Require IMAPS (port 993) with TLS.", "what": "An old email service is exposed unencrypted.", "why": "Email and passwords can be intercepted. Use the encrypted version."},
    161: {"fix": "Change default SNMP community strings; upgrade to SNMPv3. Restrict to the monitoring server IP only.", "what": "A device-management/monitoring service is responding.", "why": "If it still uses default passwords, attackers can read (or change) device settings. It must be secured."},
    389: {"fix": "Block LDAP (389) externally; require LDAPS (636) with TLS.", "what": "A directory service (lists of users/computers) is exposed.", "why": "Attackers can use it to list all your users and groups. It should not be openly reachable."},
    443: {"fix": "Confirm the TLS certificate is valid and not expired. Disable old protocols (TLS 1.0/1.1).", "what": "A secure website/admin page is available.", "why": "This is normal, but the encryption settings should be checked to make sure they're strong and up to date."},
    445: {
        "fix": "Block SMB (445) at the firewall — never expose it to the internet. Disable SMBv1. Restrict to approved file servers only.",
        "what": "Windows file-sharing is switched on and reachable.",
        "why": "This is the #1 way ransomware spreads through a company. If a single computer gets infected, it can lock every shared file. It must be tightly controlled.",
    },
    1433: {"fix": "Block SQL Server (1433) from all but the application server. Enforce strong passwords; disable the 'sa' account if unused.", "what": "A database is directly reachable on the network.", "why": "Databases hold your most valuable data (customers, finances). If exposed, attackers can try to steal everything. It must be locked to the app server only."},
    3306: {"fix": "Bind MySQL to localhost/app-server IP. Block port 3306 at the firewall. Audit accounts.", "what": "A database is directly reachable on the network.", "why": "Your business data could be stolen if attackers reach it. Restrict it to the application server only."},
    3389: {
        "fix": "Block RDP (3389) at the firewall; allow only via VPN. Enable Network Level Authentication. Set an account-lockout policy.",
        "what": "Remote Desktop (controlling a Windows PC from elsewhere) is open to the network.",
        "why": "This is the single most common way attackers and ransomware get into a business. Open RDP gets attacked automatically, every day. It must be put behind a VPN.",
    },
    5432: {"fix": "Bind PostgreSQL to the app-server IP. Block port 5432 at the firewall.", "what": "A database is directly reachable on the network.", "why": "Exposed databases risk a full data breach. Restrict it to the application server."},
    5900: {
        "fix": "Disable VNC if not needed. If required, set a strong password, restrict to VPN, and block port 5900 at the firewall.",
        "what": "A screen-sharing/remote-control tool is reachable.",
        "why": "VNC often has weak or no password, letting attackers watch and control the screen directly. It should be removed or locked down.",
    },
    6379: {"fix": "Enable Redis authentication (requirepass); bind to localhost. Block port 6379 at the firewall.", "what": "A fast data-store service is exposed.", "why": "By default it has no password at all — anyone can read or wipe the data. It must be secured immediately."},
    8080: {"fix": "Verify this web service is intentional; redirect to HTTPS; add authentication if it's an admin panel.", "what": "An alternative website/admin page is exposed without encryption.", "why": "If it's an admin login without protection, attackers could take it over. It should be secured or removed."},
    8443: {"fix": "Confirm the TLS certificate and cipher settings. Restrict access if it's an admin interface.", "what": "A secure admin/web service is available.", "why": "Usually fine, but admin interfaces should be limited to your IT team and checked for strong encryption."},
    9200: {"fix": "Enable Elasticsearch security/authentication; bind to localhost. Block port 9200 externally.", "what": "A search/data service is exposed.", "why": "Frequently left with no password, exposing all stored data. This is a common, serious breach point. Secure it now."},
    27017: {"fix": "Enable MongoDB authentication; bind to the app-server IP. Block port 27017 at the firewall.", "what": "A database is directly reachable on the network.", "why": "Often deployed with no password, meaning anyone can read the whole database. It must require a login and be firewalled."},
}


def _summary(r: FreeReport) -> str:
    if r.scan_error:
        return f"The scan of {r.target} could not complete. Verify the target and that Nmap is installed."
    if r.hosts_up == 0:
        return f"No active devices were found on {r.target}."

    dw = "device" if r.hosts_up == 1 else "devices"
    parts = [f"This quick scan of {r.target} found {r.hosts_up} active {dw} with {r.total_open_ports} open services."]

    c, h, m = r.critical_count, r.high_count, r.medium_count
    if c or h:
        bits = []
        if c:
            bits.append(f"{c} Critical")
        if h:
            bits.append(f"{h} High")
        parts.append(
            f"It flagged {' and '.join(bits)} exposed service{'s' if (c+h) != 1 else ''} "
            "that could allow ransomware or unauthorised access."
        )
    elif m:
        parts.append(f"It flagged {m} medium-risk exposure{'s' if m != 1 else ''} worth reviewing.")
    else:
        parts.append("No high-risk service exposures were detected in this quick scan.")

    parts.append(
        "This is a free surface-level scan. A full Soun Al Hosn assessment adds deep configuration "
        "auditing, lateral-movement analysis, compliance mapping, and a fix-it roadmap."
    )
    return " ".join(parts)
