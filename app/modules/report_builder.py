"""Assembles all scan data into a structured ReportData object for the template."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app.modules.scanner import ScanResult, RISK_ORDER
from app.modules.dns_check import DnsResult

if TYPE_CHECKING:
    from app.modules.ssl_check import SslResult
    from app.modules.vuln_lookup import Cve


RISK_LABEL = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Informational",
}

RISK_COLOR = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "info":     "#6b7280",
}


@dataclass
class Finding:
    risk: str
    title: str
    host: str
    detail: str
    recommendation: str
    port: int = 0
    service: str = ""
    cves: list = field(default_factory=list)
    category: str = "network"   # network | email | ssl | vuln

    @property
    def risk_label(self) -> str:
        return RISK_LABEL.get(self.risk, self.risk)

    @property
    def risk_color(self) -> str:
        return RISK_COLOR.get(self.risk, "#6b7280")

    @property
    def has_cves(self) -> bool:
        return bool(self.cves)

    @property
    def top_cve_score(self) -> float:
        if not self.cves:
            return 0.0
        return max(c.cvss_score for c in self.cves)


@dataclass
class HostRow:
    ip: str
    hostname: str
    display: str
    os: str
    vendor: str
    mac: str
    ports: str
    risk: str
    risk_label: str
    risk_color: str
    dangerous: int
    services: list = field(default_factory=list)
    device_type: str = "Unknown Device"
    device_icon: str = "🖥"
    is_gateway: bool = False
    port_count: int = 0


@dataclass
class ReportData:
    # Meta
    client_name: str
    domain: str
    target: str
    scan_profile: str
    generated_at: str
    operator: str

    # Network
    findings: list[Finding] = field(default_factory=list)
    hosts_up: int = 0
    total_open_ports: int = 0
    scan_command: str = ""
    scan_error: str = ""
    host_rows: list[HostRow] = field(default_factory=list)

    # DNS / Email
    dns_checks: list = field(default_factory=list)
    dns_error: str = ""

    # SSL
    ssl_results: list = field(default_factory=list)

    # Network context (auto-detected)
    netinfo: object = None        # NetInfo
    topology: object = None       # TopologyResult

    # New v3.5 data
    web_results: list = field(default_factory=list)       # WebFinding
    compliance: object = None                             # ComplianceResult
    engineer_results: list = field(default_factory=list)  # ModuleResult
    runbook_steps: list = field(default_factory=list)     # RunbookStep
    scan_diff: object = None                              # ScanDiff (re-scan)
    deep_probe_count: int = 0
    validation: object = None                            # ValidationResult

    @property
    def has_validation(self) -> bool:
        return self.validation is not None and bool(getattr(self.validation, "reachable_edges", []))

    # Narrative
    executive_summary: str = ""
    engineer_notes: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    arabic: object = None  # ArabicSummary | None — Arabic executive summary page

    @property
    def has_web_data(self) -> bool:
        return bool(self.web_results)

    @property
    def has_compliance(self) -> bool:
        return self.compliance is not None and getattr(self.compliance, "has_gaps", False)

    @property
    def has_engineer_data(self) -> bool:
        return bool(self.engineer_results)

    @property
    def has_runbook(self) -> bool:
        return bool(self.runbook_steps)

    @property
    def has_diff(self) -> bool:
        return self.scan_diff is not None

    @property
    def has_netinfo(self) -> bool:
        return self.netinfo is not None and bool(getattr(self.netinfo, "public_ip", ""))

    @property
    def has_topology(self) -> bool:
        return self.topology is not None and bool(getattr(self.topology, "hops", []))

    # ── Computed counts ─────────────────────────────────────────────────────────

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
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "low")

    @property
    def overall_risk(self) -> str:
        if self.critical_count > 0:
            return "critical"
        if self.high_count > 0:
            return "high"
        if self.medium_count > 0:
            return "medium"
        if self.low_count > 0:
            return "low"
        return "info"

    @property
    def overall_risk_label(self) -> str:
        return RISK_LABEL.get(self.overall_risk, "Unknown")

    @property
    def overall_risk_color(self) -> str:
        return RISK_COLOR.get(self.overall_risk, "#6b7280")

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def has_scan_data(self) -> bool:
        return not self.scan_error and self.hosts_up > 0

    @property
    def has_dns_data(self) -> bool:
        return not self.dns_error and bool(self.dns_checks)

    @property
    def has_ssl_data(self) -> bool:
        return bool(self.ssl_results)

    @property
    def cve_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.has_cves]

    @property
    def risk_score(self) -> int:
        """0-100 numeric risk score for visual display."""
        weights = {"critical": 25, "high": 10, "medium": 4, "low": 1}
        raw = sum(weights.get(f.risk, 0) for f in self.findings)
        return min(100, raw)

    @property
    def risk_score_label(self) -> str:
        s = self.risk_score
        if s >= 75:
            return "Severe"
        if s >= 50:
            return "High"
        if s >= 25:
            return "Moderate"
        if s >= 10:
            return "Low"
        return "Minimal"


def build_report(
    client_name: str,
    domain: str,
    target: str,
    scan_profile: str,
    scan_result: ScanResult,
    dns_result: "DnsResult | None",
    ssl_results: "dict | None" = None,
    netinfo: object = None,
    topology: object = None,
    deep_findings: list | None = None,
    web_results: list | None = None,
    cred_findings: list | None = None,
    engineer_answers: dict | None = None,
    prior_findings: list | None = None,
    validation: object = None,
    enable_compliance: bool = True,
    operator: str = "Soun Al Hosn",
) -> ReportData:
    report = ReportData(
        client_name=client_name,
        domain=domain,
        target=target,
        scan_profile=scan_profile,
        generated_at=datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC"),
        operator=operator,
        scan_command=scan_result.scan_command,
        scan_error=scan_result.error,
        hosts_up=scan_result.host_count,
        total_open_ports=sum(len(h.open_ports) for h in scan_result.hosts),
        netinfo=netinfo,
        topology=topology,
    )

    # ── Network findings ─────────────────────────────────────────────────────────
    for host, svc in scan_result.findings_by_risk():
        if svc.risk == "info" and svc.port not in (80, 443, 8080, 8443):
            continue
        report.findings.append(Finding(
            risk=svc.risk,
            title=f"{RISK_LABEL.get(svc.risk, 'Risk')}: {svc.name or f'Port {svc.port}'} exposed on {host.display_name}",
            host=host.display_name,
            port=svc.port,
            service=svc.display_name,
            detail=svc.risk_reason or f"Port {svc.port}/{svc.protocol} is open.",
            recommendation=_port_recommendation(svc.port),
            cves=svc.cves if hasattr(svc, "cves") else [],
            category="network",
        ))

    # ── DNS / Email findings ─────────────────────────────────────────────────────
    if dns_result and dns_result.succeeded:
        report.dns_checks = dns_result.checks
        for check in dns_result.failed_checks + dns_result.warned_checks:
            report.findings.append(Finding(
                risk=check.risk,
                title=f"Email Security: {check.name} issue on {domain}",
                host=domain,
                detail=check.detail,
                recommendation=check.recommendation,
                category="email",
            ))
    elif dns_result:
        report.dns_error = dns_result.error

    # ── SSL findings ─────────────────────────────────────────────────────────────
    if ssl_results:
        report.ssl_results = list(ssl_results.values())
        for ssl_res in ssl_results.values():
            if ssl_res.error and not ssl_res.findings:
                continue
            for f in ssl_res.failed:
                report.findings.append(Finding(
                    risk=f.risk,
                    title=f"SSL/TLS: {f.name} on {ssl_res.host}:{ssl_res.port}",
                    host=ssl_res.host,
                    detail=f.detail,
                    recommendation=f.recommendation,
                    category="ssl",
                ))

    # ── Deep-probe findings (NSE config-level) ───────────────────────────────────
    if deep_findings:
        report.deep_probe_count = len(deep_findings)
        for pf in deep_findings:
            report.findings.append(Finding(
                risk=pf.risk,
                title=pf.title,
                host=pf.host,
                port=pf.port,
                service="",
                detail=pf.detail,
                recommendation=pf.recommendation,
                category="config",
            ))

    # ── Web / admin-panel findings ───────────────────────────────────────────────
    if web_results:
        report.web_results = web_results
        for wf in web_results:
            for wfind in wf.findings:
                report.findings.append(Finding(
                    risk=wfind["risk"],
                    title=wfind["title"],
                    host=wf.host,
                    port=wf.port,
                    service=wf.panel_type or wf.server,
                    detail=wfind["detail"],
                    recommendation=wfind["recommendation"],
                    category="web",
                ))

    # ── Credential-test findings ─────────────────────────────────────────────────
    if cred_findings:
        for cf in cred_findings:
            report.findings.append(Finding(
                risk=cf.risk,
                title=f"Default credentials accepted on {cf.service}",
                host=cf.host,
                port=cf.port,
                service=cf.service,
                detail=cf.note + " — this allows full unauthenticated administrative access.",
                recommendation="Change the default credentials immediately to a strong, unique password. Restrict the interface to a management VLAN/VPN.",
                category="cred",
            ))

    # ── Active Validation agent findings ─────────────────────────────────────────
    if validation is not None:
        report.validation = validation
        for vf in validation.findings:
            report.findings.append(Finding(
                risk=vf.risk,
                title=vf.title,
                host=vf.host or "network",
                port=getattr(vf, "port", 0),
                detail=vf.detail,
                recommendation=vf.recommendation,
                category="validation",
            ))

    # ── Engineer field-module findings ───────────────────────────────────────────
    if engineer_answers:
        from app.modules.engineer_modules import evaluate as eval_modules
        report.engineer_results = eval_modules(engineer_answers)
        for mr in report.engineer_results:
            for ef in mr.findings:
                report.findings.append(Finding(
                    risk=ef["risk"],
                    title=ef["title"],
                    host=mr.title,
                    detail=ef["detail"],
                    recommendation=ef["recommendation"],
                    category="engineer",
                ))

    # ── Sort all findings by risk ────────────────────────────────────────────────
    report.findings.sort(key=lambda f: RISK_ORDER.get(f.risk, 99))

    # ── Host rows ────────────────────────────────────────────────────────────────
    for h in scan_result.hosts:
        report.host_rows.append(HostRow(
            ip=h.ip,
            hostname=h.hostname,
            display=h.display_name,
            os=h.os_guess,
            vendor=h.vendor,
            mac=h.mac,
            ports=", ".join(str(p) for p in h.open_ports[:18]),
            risk=h.highest_risk,
            risk_label=RISK_LABEL.get(h.highest_risk, ""),
            risk_color=RISK_COLOR.get(h.highest_risk, "#6b7280"),
            dangerous=len(h.dangerous_services),
            services=[{"port": s.port, "name": s.name, "risk": s.risk, "product": s.product, "version": s.version} for s in h.services],
            device_type=h.device_type,
            device_icon=h.device_icon,
            is_gateway=h.is_gateway,
            port_count=len(h.open_ports),
        ))

    # ── Compliance mapping ───────────────────────────────────────────────────────
    if enable_compliance and report.findings:
        from app.modules.compliance import map_findings
        report.compliance = map_findings(report.findings)

    # ── Remediation runbook ──────────────────────────────────────────────────────
    if report.findings:
        from app.modules.runbook import build_runbook
        report.runbook_steps = build_runbook(report.findings)

    # ── Re-scan diff (proof of fix) ──────────────────────────────────────────────
    if prior_findings is not None:
        from app.modules.runbook import diff_scans
        report.scan_diff = diff_scans(prior_findings, report.findings)

    # ── Narratives ───────────────────────────────────────────────────────────────
    report.executive_summary = _executive_summary(report)
    report.engineer_notes = _engineer_notes(report)
    report.attack_paths = _attack_paths(report, scan_result)
    from app.modules.arabic import build_arabic_summary
    report.arabic = build_arabic_summary(report)

    return report


def _attack_paths(r: ReportData, scan_result: ScanResult) -> list[str]:
    """Generate plausible attack-path narratives from the findings.

    These translate raw findings into 'how an attacker would actually use this'
    — the part that makes a CISO take the report seriously.
    """
    paths: list[str] = []

    for host in scan_result.hosts:
        ports = set(host.open_ports)
        name = host.display_name

        # RDP brute-force → ransomware
        if 3389 in ports:
            paths.append(
                f"RANSOMWARE PATH — {name}: Exposed RDP (3389) is the #1 ransomware entry vector in the UAE. "
                "An attacker brute-forces or buys credentials on the dark web, logs in, disables backups, "
                "and deploys ransomware across the network. Mitigation: move RDP behind VPN + enable NLA + lockout policy."
            )
        # SMB → lateral movement
        if 445 in ports:
            paths.append(
                f"LATERAL MOVEMENT — {name}: Exposed SMB (445) allows an attacker who lands on any one machine "
                "to spread laterally, harvest credentials, and reach file servers. EternalBlue-class exploits target this. "
                "Mitigation: disable SMBv1, restrict 445 to file servers, enforce SMB signing."
            )
        # Unauthenticated DB exposure
        db = ports & {1433, 3306, 5432, 6379, 27017, 9200}
        if db:
            paths.append(
                f"DATA BREACH — {name}: Database port(s) {', '.join(map(str, sorted(db)))} are reachable on the network. "
                "If authentication is weak or absent (common default), an attacker dumps the entire database — "
                "customer records, financials, credentials. Mitigation: bind to app-server only, enforce strong auth, firewall the port."
            )
        # VNC
        if 5900 in ports:
            paths.append(
                f"REMOTE TAKEOVER — {name}: VNC (5900) often runs with no password or a weak one. "
                "An attacker connects and controls the machine's desktop directly. "
                "Mitigation: require a strong VNC password, restrict to VPN, or disable if unused."
            )
        # Telnet
        if 23 in ports:
            paths.append(
                f"CREDENTIAL THEFT — {name}: Telnet (23) transmits everything in cleartext. "
                "Anyone on the network can capture admin passwords with a packet sniffer. "
                "Mitigation: disable Telnet entirely, replace with SSH."
            )

    # Email spoofing path
    if r.has_dns_data:
        dmarc_weak = any(c.name == "DMARC Record" and c.status in ("fail", "warn") for c in r.dns_checks)
        if dmarc_weak:
            paths.append(
                f"BUSINESS EMAIL COMPROMISE — {r.domain}: Weak DMARC lets attackers send emails that appear to come "
                "from your domain. They impersonate the CEO or finance team to authorise fraudulent payments — "
                "a scam that costs UAE businesses millions yearly. Mitigation: set DMARC to p=quarantine, then p=reject."
            )

    return paths[:8]


# ── Narrative generators ─────────────────────────────────────────────────────────

def _executive_summary(r: ReportData) -> str:
    if r.scan_error:
        return (
            f"The network scan of {r.target} could not be completed. "
            "Please verify the target subnet and ensure Nmap is installed."
        )
    if r.hosts_up == 0:
        return (
            f"The scan of {r.target} found no active devices. "
            "This may indicate the subnet is incorrect or devices are blocking ICMP."
        )

    parts: list[str] = []

    dw = "device" if r.hosts_up == 1 else "devices"
    parts.append(
        f"This assessment scanned the {r.target} network and found "
        f"{r.hosts_up} active {dw} with {r.total_open_ports} open network service{'s' if r.total_open_ports != 1 else ''}."
    )

    c, h, m = r.critical_count, r.high_count, r.medium_count
    if c > 0 or h > 0:
        sev_parts = []
        if c > 0:
            sev_parts.append(f"{c} Critical")
        if h > 0:
            sev_parts.append(f"{h} High")
        label = " and ".join(sev_parts)
        parts.append(
            f"The assessment identified {label} risk{'s' if (c + h) != 1 else ''} "
            "that directly expose the business to ransomware, data breach, or unauthorised remote access."
        )
        if c > 0:
            parts.append(
                "Critical findings represent the highest-probability entry points for attackers "
                "and must be addressed before any other security work."
            )
    elif m > 0:
        parts.append(
            f"No critical or high risks were found. "
            f"{m} medium-risk issue{'s were' if m != 1 else ' was'} identified that reduce overall security posture if left unaddressed."
        )
    else:
        parts.append(
            "No significant network-layer risks were detected on this network. "
            "The environment appears reasonably hardened at the network perimeter level."
        )

    if r.has_dns_data:
        dns_issues = sum(1 for c in r.dns_checks if c.status in ("fail", "warn"))
        if dns_issues > 0:
            issue_word = "issues" if dns_issues != 1 else "issue"
            parts.append(
                f"Email security review of {r.domain} identified {dns_issues} configuration "
                f"{issue_word} that could allow attackers to send emails "
                "impersonating your organisation — a primary enabler of fraud and executive phishing."
            )

    if r.has_ssl_data:
        ssl_issues = sum(1 for sr in r.ssl_results for f in sr.findings if f.status in ("fail", "warn"))
        if ssl_issues > 0:
            parts.append(
                f"SSL/TLS analysis found {ssl_issues} certificate or protocol issue{'s' if ssl_issues != 1 else ''} "
                "that affect the security and trustworthiness of web services on this network."
            )

    parts.append(
        "Every finding in this report includes a specific, actionable remediation step. "
        "Soun Al Hosn can implement all remediation work — contact us for a scoped proposal."
    )

    return " ".join(parts)


def _engineer_notes(r: ReportData) -> list[str]:
    """Technical notes for the engineer/analyst — not shown to the client."""
    notes: list[str] = []

    # Flag services that need credential testing
    cred_ports = {21, 22, 23, 110, 143, 161, 389, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
    for row in r.host_rows:
        for svc in row.services:
            if svc["port"] in cred_ports and svc["risk"] in ("critical", "high"):
                notes.append(
                    f"FOLLOW-UP: {row.ip}:{svc['port']} ({svc['name']}) — "
                    "consider credential brute-force test with client permission."
                )

    # Flag old/undetected versions
    for row in r.host_rows:
        for svc in row.services:
            v = svc.get("version", "")
            if v and any(old in v for old in ("5.", "4.", "3.", "2.", "1.")):
                notes.append(
                    f"VERSION CHECK: {row.ip}:{svc['port']} {svc['product']} {v} — "
                    "verify this is the latest supported release; check vendor EOL status."
                )
            elif svc.get("product") and not v:
                notes.append(
                    f"VERSION UNKNOWN: {row.ip}:{svc['port']} {svc['product']} — "
                    "version not detected; consider manual banner grab for CVE lookup."
                )

    # SMB without version
    for row in r.host_rows:
        for svc in row.services:
            if svc["port"] in (139, 445):
                notes.append(
                    f"SMB: {row.ip} — run 'nmap -p 445 --script smb-security-mode,smb2-security-mode "
                    f"-sV {row.ip}' to check SMBv1 status and signing requirement."
                )

    # SNMP found
    for row in r.host_rows:
        for svc in row.services:
            if svc["port"] == 161:
                notes.append(
                    f"SNMP: {row.ip} — run 'snmpwalk -v2c -c public {row.ip}' to test default community string. "
                    "Full device config may be readable."
                )

    return notes[:10]  # cap at 10 notes


# ── Per-port remediation ─────────────────────────────────────────────────────────

def _port_recommendation(port: int) -> str:
    recs: dict[int, str] = {
        21:    "Disable FTP immediately. Switch to SFTP (runs over SSH, port 22) or SCP. If FTP is required for a legacy system, restrict source IPs with a firewall rule and enforce TLS (FTPS).",
        22:    "Restrict SSH to known admin IPs using firewall rules (e.g. 'ufw allow from 10.0.0.5 to any port 22'). Disable password auth — use SSH keys only. Review /etc/ssh/sshd_config: set PasswordAuthentication no, PermitRootLogin no.",
        23:    "Disable Telnet immediately. All Telnet traffic is cleartext — credentials are visible to anyone on the network. Run 'systemctl disable telnet' or equivalent. Replace with SSH.",
        25:    "Configure SMTP to require STARTTLS for all connections. Disable open relay (check 'smtpd_relay_restrictions' in Postfix). Restrict port 25 inbound to your mail provider's IPs only.",
        53:    "Disable recursive DNS for external clients. In BIND: set 'recursion no' or restrict with 'allow-recursion { localhost; internal-net; };'. In dnsmasq: ensure --no-resolv is set for external-facing interfaces.",
        80:    r"Add a 301 permanent redirect from HTTP to HTTPS. In nginx: 'return 301 https://$host$request_uri;'. In Apache: 'Redirect permanent / https://yourdomain.com/'. Then disable the HTTP listener.",
        110:   "Disable POP3 on port 110. Configure your mail server to only accept POP3S (port 995) with TLS. In Dovecot: set 'disable_plaintext_auth = yes'.",
        111:   "Block RPCBind at the firewall. This port is required for NFS but should never be accessible from untrusted networks. Add: 'iptables -A INPUT -p tcp --dport 111 -j DROP' from external sources.",
        135:   "Block Windows RPC (port 135) at the perimeter and between VLANs using firewall rules. This port should only be accessible within the management VLAN.",
        139:   "Disable NetBIOS over TCP/IP on all Windows machines not running legacy apps. Go to Network Adapter → Properties → TCP/IPv4 → Advanced → WINS → Disable NetBIOS over TCP/IP.",
        143:   "Disable IMAP on port 143. Require IMAPS (port 993). In Dovecot: set 'disable_plaintext_auth = yes' and configure TLS certificate.",
        161:   "Change SNMP community strings from 'public'/'private' immediately. Upgrade to SNMPv3 (requires authentication + encryption). Restrict SNMP access: 'snmpd.conf: rocommunity <new-string> 10.0.0.5' — monitoring server IP only.",
        389:   "Block LDAP port 389 externally. Require LDAPS (port 636) for all LDAP communication. In Active Directory: enable 'LDAP Channel Binding and LDAP Signing' policy via Group Policy.",
        445:   r"Block SMB port 445 at the perimeter firewall — it must never reach the internet. On each Windows machine: disable SMBv1 via PowerShell: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. Restrict to file server IPs only.",
        512:   "Disable rexec immediately: 'systemctl disable rexec' or remove the xinetd/inetd entry. There is no modern use case for this service.",
        513:   "Disable rlogin immediately: 'systemctl disable rlogin'. Replace all rlogin usage with SSH.",
        514:   "If rsh: disable immediately. If syslog: bind to localhost or the syslog server IP only. Block port 514/UDP from untrusted sources.",
        873:   "Require rsync authentication. In /etc/rsyncd.conf: add 'auth users = rsyncuser' and 'secrets file = /etc/rsyncd.secrets'. Block port 873 at the firewall for all except the backup server.",
        1433:  "Block SQL Server port 1433 from all networks except the application server IP. In SQL Server Configuration Manager, restrict SQL Server to listen on loopback or app-server IP only. Enable Windows Authentication; disable SA if not needed.",
        1521:  "Block Oracle DB port 1521 from all untrusted networks. Restrict access to the application server IP only via firewall rules. Change default Oracle credentials (system/manager, sys/change_on_install) immediately.",
        2049:  "Review NFS exports in /etc/exports. Restrict all exports to specific trusted IPs: '/data 10.0.1.5(rw,sync,no_subtree_check)'. Upgrade to NFSv4 with Kerberos (sec=krb5).",
        3306:  "Bind MySQL to localhost: set 'bind-address = 127.0.0.1' in /etc/mysql/mysql.conf.d/mysqld.cnf. Block port 3306 at the firewall. Audit MySQL users: 'SELECT User, Host FROM mysql.user;' — remove any with Host='%'.",
        3389:  "Block RDP (port 3389) at the firewall. Only allow RDP via VPN. Enable Network Level Authentication (NLA) via Group Policy: Computer Config → Admin Templates → Remote Desktop Services → Require NLA. Set account lockout: 3 failed attempts → 30-minute lockout.",
        4443:  "Verify TLS configuration. Run: 'nmap --script ssl-enum-ciphers -p 4443 <host>' to check cipher suites. Disable TLS 1.0/1.1.",
        5432:  "Bind PostgreSQL to the app server IP only. Edit postgresql.conf: set 'listen_addresses = 'localhost''. Update pg_hba.conf to restrict access: 'host all all 10.0.0.5/32 scram-sha-256'. Block port 5432 at the firewall.",
        5900:  "Disable VNC if not actively needed. If VNC is required: enable VNC password authentication (minimum 8 characters), restrict access to VPN only, and block port 5900 at the firewall perimeter.",
        5985:  "Restrict WinRM HTTP to the management VLAN. Prefer WinRM HTTPS (5986). Enforce authentication: 'winrm set winrm/config/service/auth @{Basic=\"false\"}'. Block port 5985 from general LAN access.",
        5986:  "Restrict WinRM HTTPS to authorised management systems only. Enforce certificate authentication. Add a Windows Firewall rule limiting source IPs.",
        6379:  "Enable Redis authentication immediately: add 'requirepass <strong-password>' to redis.conf. Bind Redis: set 'bind 127.0.0.1'. Block port 6379 at the firewall for all except the application server.",
        8080:  "Verify this web service is intentional and not an exposed admin panel. Redirect HTTP to HTTPS. Add authentication if it is a management interface.",
        8443:  "Verify TLS certificate is valid (not self-signed, not expired). Check cipher configuration. Restrict access if this is an admin interface.",
        9200:  "Enable Elasticsearch X-Pack security: set 'xpack.security.enabled: true' in elasticsearch.yml. Require authentication. Bind to 'network.host: localhost'. Block port 9200 from all networks except the app server. This is one of the most exploited services in the wild.",
        27017: "Enable MongoDB authentication: edit /etc/mongod.conf and set 'authorization: enabled'. Bind to the app server: 'net: bindIp: 127.0.0.1,<app-server-ip>'. Block port 27017 at the firewall. Audit all database users.",
        27018: "Same as primary MongoDB: enable authentication, restrict binding, block at firewall.",
    }
    return recs.get(
        port,
        "Verify whether this service needs to be accessible on the network. "
        "If not required for business operations, disable it or restrict access to specific management IPs using firewall rules."
    )
