"""Fix-script generator for Soun Runner findings ("Deploy a Fix").

Given a finding, produce a concrete, SCOPED, REVERSIBLE remediation:
  - a fix script (PowerShell for Windows targets, bash for Linux/web),
  - a matching rollback script that undoes exactly what the fix did,
  - human-readable preview steps,
  - a safety warning when the fix could affect the operator's own access path
    (e.g. closing RDP/SSH while connected through it).

DESIGN / SAFETY PRINCIPLES
  - Nothing here EXECUTES anything. We only generate text the engineer reviews
    and runs themselves on the target, with their own eyes on every command.
  - Every change we create is tagged with a "SounRunner-" marker so it is easy
    to identify and cleanly remove (firewall rules, etc.).
  - Fixes are per-finding and per-host; we never emit a bulk "harden everything"
    blob. The operator applies one fix at a time.
  - Destructive/连接-affecting fixes (RDP/SSH/WinRM/VNC) carry a loud warning.

This builds on the per-port intent already encoded in report_builder and the
ordering/effort logic in runbook.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

TAG = "SounRunner"  # marker prefix for any artifacts we create on the target


def _local_ips() -> set:
    """Best-effort set of IP addresses that belong to THIS machine, so we can
    tell whether a finding's host is local (fix runs here) or remote (needs a
    remote transport / manual run on the target)."""
    ips = {"127.0.0.1", "::1", "localhost"}
    try:
        host = socket.gethostname()
        ips.add(host.lower())
        for res in socket.getaddrinfo(host, None):
            ips.add(res[4][0])
    except Exception:
        pass
    # The address used to reach the internet (the primary outbound IP).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return {str(i).lower() for i in ips}


def host_is_local(host: str, local_ips: set | None = None) -> bool:
    """True if `host` refers to the machine Soun Runner is running on."""
    if not host:
        return False
    h = str(host).strip().lower()
    if h in ("", "network", "manual"):
        return False
    li = local_ips if local_ips is not None else _local_ips()
    if h in li:
        return True
    # hostname like 'WS01' or 'box.mshome.net' that resolves to a local IP
    try:
        for res in socket.getaddrinfo(h, None):
            if res[4][0].lower() in li:
                return True
    except Exception:
        pass
    return False


@dataclass
class FixScript:
    title: str                       # short label
    finding_title: str               # the finding this fixes
    host: str
    port: int
    platform: str                    # "windows" | "linux" | "dns" | "manual"
    language: str                    # "powershell" | "bash" | "text"
    summary: str                     # one-line what-it-does
    fix_script: str                  # the remediation commands
    rollback_script: str             # the undo commands
    steps: list = field(default_factory=list)     # human-readable bullet steps
    warnings: list = field(default_factory=list)  # safety warnings (may be empty)
    note: str = ""                   # extra context
    location: str = "unknown"        # "local" | "remote" | "n/a" (DNS/manual)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def run_hint(self) -> str:
        """How to actually run this fix, given where the host is."""
        if self.location == "local":
            return ("This finding is on THIS machine. You can run the fix script "
                    "here directly in an elevated PowerShell.")
        if self.location == "remote":
            return (f"This finding is on a REMOTE host ({self.host}). Run the fix "
                    "script ON that host (via console/RDP/AnyDesk), or push it with "
                    "your remote-admin tool. Soun Runner does not execute it remotely.")
        return ("This is a configuration change (DNS / web server / device) - apply "
                "it at the relevant system per the steps.")

    @property
    def fix_filename(self) -> str:
        ext = {"powershell": "ps1", "bash": "sh", "text": "txt"}.get(self.language, "txt")
        safe = _slug(f"{self.finding_title}-{self.host or 'target'}")
        return f"sounrunner-fix-{safe}.{ext}"

    @property
    def rollback_filename(self) -> str:
        ext = {"powershell": "ps1", "bash": "sh", "text": "txt"}.get(self.language, "txt")
        safe = _slug(f"{self.finding_title}-{self.host or 'target'}")
        return f"sounrunner-rollback-{safe}.{ext}"


def _slug(s: str) -> str:
    out = []
    for ch in s.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in " -_":
            out.append("-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")[:60] or "fix"


# Ports we treat as "remote access to the box" — closing these can cut the
# operator's own session, so they always get a connection-loss warning.
_ACCESS_PORTS = {22, 3389, 5985, 5986, 5900}

# Human service names for common ports (for nicer script comments).
_PORT_NAME = {
    21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MS-SQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    9200: "Elasticsearch", 27017: "MongoDB", 161: "SNMP", 25: "SMTP",
}


def _ps_header(title: str) -> str:
    return (
        "# " + "=" * 72 + "\n"
        f"# Soun Runner - FIX SCRIPT\n"
        f"# {title}\n"
        "# Review every line before running. Run in an elevated PowerShell.\n"
        "# A matching ROLLBACK script is provided to undo this change.\n"
        "# " + "=" * 72 + "\n\n"
        "$ErrorActionPreference = 'Stop'\n\n"
    )


def _ps_rollback_header(title: str) -> str:
    return (
        "# " + "=" * 72 + "\n"
        f"# Soun Runner - ROLLBACK SCRIPT\n"
        f"# Undo: {title}\n"
        "# Run in an elevated PowerShell to revert the fix.\n"
        "# " + "=" * 72 + "\n\n"
        "$ErrorActionPreference = 'Continue'\n\n"
    )


# ── Per-port firewall block (Windows) ──────────────────────────────────────────

def _fw_block_windows(finding, port: int, svc: str) -> FixScript:
    rule = f"{TAG}-Block-{port}-Inbound"
    warn = []
    if port in _ACCESS_PORTS:
        warn.append(
            f"This blocks inbound {svc} (port {port}). If you are connected to this "
            f"host THROUGH {svc} (e.g. RDP/WinRM/SSH/VNC), running it may cut your "
            f"session. Be at the console or on AnyDesk/another path before applying."
        )
    fix = _ps_header(f"Restrict {svc} (port {port}) on {finding.host}")
    fix += (
        f"# Block inbound {svc} from outside the local subnet. Adjust -RemoteAddress\n"
        f"# to your management subnet if you need internal access to keep working.\n"
        f"New-NetFirewallRule -DisplayName '{rule}' "
        f"-Direction Inbound -Protocol TCP -LocalPort {port} "
        f"-Action Block -RemoteAddress Internet -Profile Any | Out-Null\n\n"
        f"Write-Host 'Created firewall rule: {rule}'\n"
    )
    rb = _ps_rollback_header(f"Restrict {svc} (port {port})")
    rb += (
        f"Get-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue | "
        f"Remove-NetFirewallRule\n"
        f"Write-Host 'Removed firewall rule: {rule}'\n"
    )
    return FixScript(
        title=f"Restrict {svc} (port {port})",
        finding_title=finding.title, host=finding.host, port=port,
        platform="windows", language="powershell",
        summary=f"Block inbound {svc} from the internet via a tagged firewall rule.",
        fix_script=fix, rollback_script=rb, warnings=warn,
        steps=[
            f"Creates a Windows Firewall rule '{rule}' blocking inbound TCP {port} from the internet.",
            "Keeps internal access if you set -RemoteAddress to your LAN/management subnet.",
            "Rollback removes that exact rule by name.",
        ],
    )


# ── Disable legacy/cleartext service (Telnet/FTP) ───────────────────────────────

def _disable_service_windows(finding, port: int, svc: str, feature: str) -> FixScript:
    fix = _ps_header(f"Disable {svc} on {finding.host}")
    fix += (
        f"# Disable the {svc} service/feature (cleartext / legacy - no safe use).\n"
        f"# Also block the port as defense-in-depth.\n"
        f"Disable-WindowsOptionalFeature -Online -FeatureName '{feature}' -NoRestart "
        f"-ErrorAction SilentlyContinue | Out-Null\n"
        f"New-NetFirewallRule -DisplayName '{TAG}-Block-{port}-Inbound' "
        f"-Direction Inbound -Protocol TCP -LocalPort {port} -Action Block | Out-Null\n\n"
        f"Write-Host 'Disabled {svc} and blocked port {port}.'\n"
    )
    rb = _ps_rollback_header(f"Disable {svc}")
    rb += (
        f"Enable-WindowsOptionalFeature -Online -FeatureName '{feature}' -NoRestart "
        f"-ErrorAction SilentlyContinue | Out-Null\n"
        f"Get-NetFirewallRule -DisplayName '{TAG}-Block-{port}-Inbound' "
        f"-ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"
        f"Write-Host 'Re-enabled {svc} and removed the block rule.'\n"
    )
    return FixScript(
        title=f"Disable {svc} (port {port})",
        finding_title=finding.title, host=finding.host, port=port,
        platform="windows", language="powershell",
        summary=f"Disable the {svc} feature and block its port.",
        fix_script=fix, rollback_script=rb,
        steps=[
            f"Disables the {svc} Windows feature ({feature}).",
            f"Adds a firewall block on TCP {port} as backup.",
            "Rollback re-enables the feature and removes the block.",
        ],
    )


# ── SMB hardening ───────────────────────────────────────────────────────────────

def _smb_harden_windows(finding) -> FixScript:
    fix = _ps_header(f"Harden SMB on {finding.host}")
    fix += (
        "# Disable the obsolete SMBv1 protocol and require SMB signing.\n"
        "# SMBv1 (EternalBlue-class) has no safe modern use.\n"
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
        "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force\n\n"
        "# Restrict inbound SMB (445) to the internet edge (keep LAN access).\n"
        f"New-NetFirewallRule -DisplayName '{TAG}-Block-445-WAN' "
        "-Direction Inbound -Protocol TCP -LocalPort 445 -Action Block "
        "-RemoteAddress Internet | Out-Null\n\n"
        "Write-Host 'SMBv1 disabled, signing required, WAN 445 blocked.'\n"
    )
    rb = _ps_rollback_header("Harden SMB")
    rb += (
        "# NOTE: re-enabling SMBv1 is NOT recommended; included only for completeness.\n"
        "Set-SmbServerConfiguration -RequireSecuritySignature $false -Force\n"
        f"Get-NetFirewallRule -DisplayName '{TAG}-Block-445-WAN' "
        "-ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"
        "# Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force  # uncomment only if truly needed\n"
        "Write-Host 'Reverted SMB signing requirement and WAN block (SMBv1 left disabled).'\n"
    )
    return FixScript(
        title="Harden SMB (445)",
        finding_title=finding.title, host=finding.host, port=445,
        platform="windows", language="powershell",
        summary="Disable SMBv1, require signing, block SMB from the internet.",
        fix_script=fix, rollback_script=rb,
        steps=[
            "Disables SMBv1 (the EternalBlue protocol).",
            "Requires SMB signing to prevent relay attacks.",
            "Blocks inbound 445 from the internet (LAN access preserved).",
        ],
        note="SMBv1 should stay disabled; rollback intentionally leaves it off.",
    )


# ── RDP hardening (NLA + lockout + WAN block) ───────────────────────────────────

def _rdp_harden_windows(finding) -> FixScript:
    rule = f"{TAG}-Block-3389-WAN"
    fix = _ps_header(f"Harden RDP on {finding.host}")
    fix += (
        "# Require Network Level Authentication (NLA) for RDP.\n"
        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name 'UserAuthentication' -Value 1\n\n"
        "# Account lockout: 5 bad attempts -> 15-minute lockout (slows brute force).\n"
        "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15\n\n"
        "# Block RDP from the internet; keep it reachable only via LAN/VPN.\n"
        f"New-NetFirewallRule -DisplayName '{rule}' -Direction Inbound -Protocol TCP "
        "-LocalPort 3389 -Action Block -RemoteAddress Internet | Out-Null\n\n"
        "Write-Host 'RDP: NLA on, lockout set, internet access blocked.'\n"
    )
    rb = _ps_rollback_header("Harden RDP")
    rb += (
        f"Get-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"
        "net accounts /lockoutthreshold:0\n"
        "Write-Host 'Removed RDP internet block and lockout policy (NLA left enabled).'\n"
    )
    return FixScript(
        title="Harden RDP (3389)",
        finding_title=finding.title, host=finding.host, port=3389,
        platform="windows", language="powershell",
        summary="Enable NLA, set account lockout, block RDP from the internet.",
        fix_script=fix, rollback_script=rb,
        warnings=[
            "If you are connected to this host via RDP, blocking internet RDP is "
            "usually safe (you stay on if you're on the LAN/VPN), but confirm you "
            "have console or AnyDesk access before applying."
        ],
        steps=[
            "Turns on Network Level Authentication (NLA).",
            "Sets a 5-attempt / 15-minute account lockout to slow brute force.",
            "Blocks RDP from the internet (RDP via VPN/LAN still works).",
        ],
    )


# ── Generic DB / service bind+firewall (Linux-leaning, with Windows fw too) ──────

def _db_restrict(finding, port: int, svc: str) -> FixScript:
    rule = f"{TAG}-Block-{port}-WAN"
    fix = _ps_header(f"Restrict {svc} (port {port}) on {finding.host}")
    fix += (
        f"# Databases should never be reachable from untrusted networks.\n"
        f"# 1) Block {svc} from the internet at the host firewall.\n"
        f"New-NetFirewallRule -DisplayName '{rule}' -Direction Inbound -Protocol TCP "
        f"-LocalPort {port} -Action Block -RemoteAddress Internet | Out-Null\n\n"
        f"# 2) RECOMMENDED (manual, service-specific): bind {svc} to localhost or the\n"
        f"#    app-server IP, and require strong authentication. See the steps below.\n\n"
        f"Write-Host 'Blocked {svc} (port {port}) from the internet. Now bind/auth per the steps.'\n"
    )
    rb = _ps_rollback_header(f"Restrict {svc} (port {port})")
    rb += (
        f"Get-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"
        f"Write-Host 'Removed the {svc} internet block.'\n"
    )
    bind_hint = {
        3306: "MySQL: set bind-address = 127.0.0.1 in my.cnf; 'SELECT User,Host FROM mysql.user;' remove Host='%'.",
        5432: "PostgreSQL: listen_addresses='localhost' in postgresql.conf; restrict pg_hba.conf to app IP.",
        6379: "Redis: add 'requirepass <strong>' and 'bind 127.0.0.1' to redis.conf.",
        27017: "MongoDB: set 'authorization: enabled' and 'bindIp: 127.0.0.1,<app-ip>' in mongod.conf.",
        9200: "Elasticsearch: set xpack.security.enabled: true and network.host: localhost.",
        1433: "MS-SQL: listen on app-server IP only; enable Windows Auth; disable SA if unused.",
        1521: "Oracle: restrict listener to app IP; change default SYS/SYSTEM credentials.",
    }.get(port, f"Bind {svc} to localhost/app-server only and require strong auth.")
    return FixScript(
        title=f"Restrict {svc} (port {port})",
        finding_title=finding.title, host=finding.host, port=port,
        platform="windows", language="powershell",
        summary=f"Block {svc} from the internet; bind + require auth (manual step).",
        fix_script=fix, rollback_script=rb,
        steps=[
            f"Blocks inbound {svc} (TCP {port}) from the internet via a tagged firewall rule.",
            bind_hint,
            "Rollback removes the firewall rule.",
        ],
        note="DB binding/auth is service-specific and must be applied in the DB config; the firewall block is the immediate containment.",
    )


# ── SNMP / default credentials ──────────────────────────────────────────────────

def _snmp_fix(finding) -> FixScript:
    steps = [
        "Change SNMP community strings off 'public'/'private' to strong unique values.",
        "Prefer SNMPv3 (auth + encryption) over v1/v2c.",
        "Restrict SNMP (UDP 161) to your monitoring server IP only.",
    ]
    body = (
        "Default/weak SNMP lets an attacker read (and sometimes write) full device "
        "configuration. Apply on the device:\n\n"
        "  - Linux (net-snmp): in /etc/snmp/snmpd.conf replace\n"
        "      rocommunity public\n"
        "    with a v3 user:\n"
        "      createUser monitorUser SHA '<authPass>' AES '<privPass>'\n"
        "      rouser monitorUser priv\n"
        "    then restrict source: 'rocommunity <strong> <monitoring-ip>'\n\n"
        "  - Network gear (Cisco/etc.): 'no snmp-server community public', then\n"
        "      snmp-server group ...v3 priv / snmp-server user ...\n"
        "    and an ACL limiting SNMP to the NMS IP.\n\n"
        "  - Firewall: allow UDP/161 only from the monitoring server.\n"
    )
    return FixScript(
        title="Fix SNMP exposure",
        finding_title=finding.title, host=finding.host, port=161,
        platform="manual", language="text",
        summary="Replace default community strings, move to SNMPv3, restrict source IP.",
        fix_script=body, rollback_script="(Revert by restoring the previous snmpd.conf / device SNMP config from backup.)",
        steps=steps,
        note="SNMP config is device-specific; this is a precise checklist rather than a single script.",
    )


def _default_creds_fix(finding) -> FixScript:
    svc = finding.service or "the service"
    body = (
        f"Default credentials accepted on {svc} ({finding.host}:{finding.port}). "
        "This is full unauthenticated admin access. Immediately:\n\n"
        "  1) Log in and change the default password to a strong, unique one.\n"
        "  2) If a default ADMIN USERNAME exists, rename/disable it where possible.\n"
        "  3) Restrict the management interface to a VLAN/VPN (firewall the port).\n"
        "  4) Enable MFA on the interface if supported.\n"
    )
    return FixScript(
        title="Change default credentials",
        finding_title=finding.title, host=finding.host, port=finding.port,
        platform="manual", language="text",
        summary="Change default creds, restrict the management interface.",
        fix_script=body, rollback_script="(No rollback - do not restore default credentials.)",
        steps=[
            "Change the default password to a strong unique value.",
            "Disable/rename the default admin account if possible.",
            "Restrict the interface to management VLAN/VPN.",
        ],
        note="Never roll back to default credentials.",
    )


# ── Email security (SPF/DKIM/DMARC) → DNS records ───────────────────────────────

def _email_fix(finding, domain: str) -> FixScript:
    name = finding.title.lower()
    domain = domain or "yourdomain.tld"
    if "spf" in name:
        rec_host, rec_val = domain, '"v=spf1 include:_spf.google.com -all"'
        steps = ["Add a single SPF TXT record. Replace the include: with your real mail provider(s).",
                 "Use -all (hard fail) once you've confirmed all senders are listed."]
        what = "SPF"
    elif "dkim" in name:
        rec_host, rec_val = f"<selector>._domainkey.{domain}", '"v=DKIM1; k=rsa; p=<public-key-from-provider>"'
        steps = ["Generate a DKIM key in your mail provider and publish the TXT record it gives you.",
                 "The selector and public key come from the provider (Google/M365/etc.)."]
        what = "DKIM"
    else:  # DMARC
        rec_host, rec_val = f"_dmarc.{domain}", '"v=DMARC1; p=quarantine; rua=mailto:dmarc@' + domain + '; fo=1"'
        steps = ["Start at p=quarantine, monitor the rua reports, then move to p=reject.",
                 "DMARC requires SPF and/or DKIM to be in place first."]
        what = "DMARC"
    body = (
        f"# {what} fix for {domain} - add this DNS TXT record at your DNS host.\n"
        f"# (BIND zone-file style; in a web DNS panel, enter the Host/Type/Value fields.)\n\n"
        f"; Type: TXT\n"
        f"{rec_host}.    IN    TXT    {rec_val}\n\n"
        f"# After adding, verify with:  nslookup -type=TXT {rec_host}\n"
    )
    return FixScript(
        title=f"Fix {what} for {domain}",
        finding_title=finding.title, host=domain, port=0,
        platform="dns", language="text",
        summary=f"Publish the {what} TXT record to stop email spoofing.",
        fix_script=body,
        rollback_script=f"(Remove the {what} TXT record you added for {rec_host}.)",
        steps=steps,
        note="DNS changes can take up to a few hours to propagate.",
    )


# ── SSL/TLS web-server config ───────────────────────────────────────────────────

def _tls_fix(finding) -> FixScript:
    body = (
        "Fix weak TLS by enforcing modern protocols/ciphers and HSTS. Apply to the\n"
        "web server in front of this service, then reload it.\n\n"
        "# nginx (in the server { } block):\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';\n"
        "    ssl_prefer_server_ciphers on;\n"
        '    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;\n'
        "    # redirect HTTP->HTTPS in the port-80 server block:\n"
        "    # return 301 https://$host$request_uri;\n\n"
        "# Apache (httpd-ssl.conf / vhost):\n"
        "    SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
        "    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
        "    SSLHonorCipherOrder on\n"
        '    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"\n\n'
        "# IIS: use IIS Crypto (Nartac) to disable TLS 1.0/1.1 and weak ciphers, then reboot.\n\n"
        "# Reload:  nginx -t && nginx -s reload   |   apachectl configtest && apachectl graceful\n"
    )
    rb = (
        "(Restore your previous web-server SSL config from backup and reload. "
        "Always keep a copy of the original config before editing.)"
    )
    return FixScript(
        title="Fix SSL/TLS configuration",
        finding_title=finding.title, host=finding.host, port=finding.port,
        platform="manual", language="text",
        summary="Enforce TLS 1.2+/strong ciphers, add HSTS, redirect HTTP->HTTPS.",
        fix_script=body, rollback_script=rb,
        steps=[
            "Restrict to TLS 1.2/1.3 and a strong cipher list.",
            "Add the HSTS header and redirect HTTP to HTTPS.",
            "Test the config, then reload the web server.",
        ],
        note="Back up the existing web-server config before applying.",
    )


# ── Dispatcher ──────────────────────────────────────────────────────────────────

# Optional-feature names for legacy Windows services we can disable.
_WIN_FEATURE = {23: "TelnetClient", 21: "IIS-FTPServer"}


def _classify_location(fx: "FixScript", finding, local_ips: set | None) -> None:
    """Tag the fix as local/remote/n-a based on where the finding's host is."""
    if fx.platform in ("dns", "manual"):
        fx.location = "n/a"
        return
    if host_is_local(getattr(finding, "host", ""), local_ips):
        fx.location = "local"
    else:
        fx.location = "remote"
        # Add an explicit note so the operator knows it won't auto-run remotely.
        if not any("REMOTE host" in w for w in fx.warnings):
            fx.warnings.append(
                f"This host ({fx.host}) is NOT the machine Soun Runner is running on. "
                "Apply the fix ON that host (console/RDP/AnyDesk) - it will not run there automatically."
            )


# Device types that are NOT general-purpose Windows/Linux hosts. A PowerShell or
# bash fix can't run on these — they're configured through their own admin UI /
# console — so for these we emit manual, device-specific guidance instead.
_APPLIANCE_TYPES = {
    "Router / Gateway", "Firewall", "Network Device", "Hypervisor / ESXi",
    "NAS / Storage", "IP Camera / CCTV", "Printer", "VoIP / Phone",
    "IoT / Embedded", "Unknown Device",
}

# Per-device-type "how to remediate this on the appliance" guidance.
_APPLIANCE_GUIDE = {
    "Router / Gateway": [
        "Log into the router/gateway admin page (usually http://<this-ip> or the vendor app).",
        "Find Firewall / Port Forwarding / Remote Management and REMOVE any rule that exposes this port to the WAN/internet.",
        "Disable 'Remote Management' / 'Remote Admin' unless you truly need it; if you do, restrict it to specific source IPs and use HTTPS.",
        "Change the default admin password and update the firmware.",
    ],
    "Firewall": [
        "Log into the firewall management console (FortiGate/Palo Alto/etc.).",
        "Locate the policy/VIP that publishes this service and restrict or remove it; expose only what the business needs.",
        "Limit management access to a trusted management subnet; enforce MFA on admin logins.",
        "Confirm firmware is current and default credentials are changed.",
    ],
    "Hypervisor / ESXi": [
        "This is a hypervisor (ESXi/vSphere) — do NOT run Windows/Linux host scripts against it.",
        "In the ESXi host / vCenter UI: enable the ESXi firewall and restrict management (443/902/22) to your management network only.",
        "Disable SSH and the ESXi Shell unless actively needed; enable Lockdown Mode.",
        "Apply the latest ESXi patches and rotate the root password.",
    ],
    "NAS / Storage": [
        "Log into the NAS admin UI (Synology DSM / QNAP QTS / etc.).",
        "Disable the exposed service if unused, or restrict it to the LAN; never expose SMB/management to the internet.",
        "Enable the NAS firewall + auto-block, enforce HTTPS, and turn on 2-factor for admin.",
        "Update firmware/DSM and change default accounts.",
    ],
    "IP Camera / CCTV": [
        "This is a camera/NVR — configure it from its own web UI or the vendor app, not via host scripts.",
        "Remove any internet/WAN exposure (port-forward or UPnP) for this device; keep cameras on an isolated VLAN.",
        "Change the default password, disable unused services (Telnet/ONVIF if not needed), and update firmware.",
        "If remote viewing is required, use the vendor's secure relay or a VPN — not a direct port forward.",
    ],
    "Printer": [
        "Configure the printer from its embedded web page (EWS).",
        "Disable unused/legacy protocols (raw 9100, Telnet, FTP) and require HTTPS for admin.",
        "Set an admin password and keep the printer off the internet; restrict to the office LAN.",
        "Update the printer firmware.",
    ],
    "VoIP / Phone": [
        "Configure on the PBX/phone admin console.",
        "Restrict SIP/management to trusted networks; never expose SIP directly to the internet without a SBC.",
        "Change default credentials and enable transport security (TLS/SRTP) where supported.",
    ],
}
_APPLIANCE_GUIDE_DEFAULT = [
    "This device is an appliance/embedded system — it is configured from its own admin interface, not via Windows/Linux scripts.",
    "Open its web admin UI (http(s)://<this-ip>) or vendor app.",
    "Disable or firewall-off the exposed service; remove any internet exposure for it.",
    "Change default credentials and update its firmware.",
]


def _appliance_guidance(finding, device_type: str, svc: str, port: int) -> FixScript:
    """Manual, device-specific remediation for an appliance the operator can't
    run a host script on (router, ESXi, NAS, camera, printer, …)."""
    steps = _APPLIANCE_GUIDE.get(device_type, _APPLIANCE_GUIDE_DEFAULT)
    body = (
        f"# {device_type} — {svc} (port {port}) on {finding.host}\n"
        f"# This device is configured from its OWN admin interface — not via a\n"
        f"# Windows/Linux script. Apply these steps on the device itself:\n\n"
        + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(steps))
        + "\n"
    )
    return FixScript(
        title=f"Secure {svc} on {device_type}",
        finding_title=finding.title, host=finding.host, port=port,
        platform="manual", language="text",
        summary=f"{device_type}: apply this on the device's own admin interface — not auto-runnable.",
        fix_script=body, rollback_script="", steps=list(steps),
        warnings=[f"{device_type} detected — a host fix script would not run here; "
                  f"follow the device steps instead."],
        note="SounRunner does not log into appliances. Apply these on the device itself.",
        location="n/a",
    )


def generate_fix(finding, domain: str = "", local_ips: set | None = None) -> "FixScript | None":
    """Map a single finding to a FixScript, or None if we have no recipe for it.

    `finding` is anything with .risk/.title/.host/.port/.service/.category
    attributes. The result is tagged .location = local|remote|n/a so the caller
    knows whether the fix runs on this machine or on a remote host.
    """
    cat = (getattr(finding, "category", "") or "").lower()
    port = int(getattr(finding, "port", 0) or 0)
    title = (getattr(finding, "title", "") or "").lower()
    svc = _PORT_NAME.get(port, getattr(finding, "service", "") or f"port {port}")

    fx = None
    # Email / DNS
    if cat == "email" or any(k in title for k in ("spf", "dkim", "dmarc", "email security")):
        fx = _email_fix(finding, domain)
    # SSL / TLS
    elif cat == "ssl" or any(k in title for k in ("ssl", "tls", "cipher", "certificate", "hsts")):
        fx = _tls_fix(finding)
    # Default credentials
    elif cat == "cred" or "default credential" in title:
        fx = _default_creds_fix(finding)
    # SNMP
    elif port == 161 or "snmp" in title:
        fx = _snmp_fix(finding)
    # Service/port-based fixes.
    # GUARD: if the host is an appliance (router, ESXi, NAS, camera, printer,
    # IoT…) a Windows/Linux host script can't run on it — emit device-specific
    # manual guidance instead of a PowerShell fix that would never apply.
    elif (getattr(finding, "device_type", "") in _APPLIANCE_TYPES
          and port and cat in ("network", "config", "web", "validation")):
        fx = _appliance_guidance(finding, getattr(finding, "device_type", ""), svc, port)
    elif port == 3389:
        fx = _rdp_harden_windows(finding)
    elif port in (139, 445):
        fx = _smb_harden_windows(finding)
    elif port in _WIN_FEATURE:
        fx = _disable_service_windows(finding, port, svc, _WIN_FEATURE[port])
    elif port in (1433, 1521, 3306, 5432, 6379, 9200, 27017, 27018):
        fx = _db_restrict(finding, port, svc)
    # Generic exposed service -> firewall block (only if we know the port)
    elif port and cat in ("network", "config", "web", "validation"):
        fx = _fw_block_windows(finding, port, svc)

    if fx is not None:
        _classify_location(fx, finding, local_ips)
    return fx


def generate_all(findings, domain: str = "") -> list:
    """Generate fixes for every finding we have a recipe for (deduped by host+port+title)."""
    seen = set()
    out = []
    local_ips = _local_ips()  # compute once for all findings
    for f in findings:
        fx = generate_fix(f, domain, local_ips=local_ips)
        if not fx:
            continue
        key = (fx.host, fx.port, fx.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(fx)
    return out
