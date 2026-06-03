"""Deep service probing via nmap NSE scripts.

Turns "port X is open" into config-level findings: SMB signing disabled,
anonymous FTP allowed, RDP NLA off, weak SSL ciphers, default SNMP community
strings, exposed SMB shares, etc.

All scripts used here are SAFE / read-only and run fine on production networks.
No exploits, no logins, no DoS. Credential testing lives in credtest.py.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.modules.scanner import find_nmap


@dataclass
class ProbeFinding:
    host: str
    port: int
    title: str
    detail: str
    risk: str             # critical | high | medium | low | info
    recommendation: str = ""
    category: str = "config"
    evidence: str = ""


# Map open ports → the NSE scripts worth running against them.
# Only safe, default-category scripts are used.
PORT_SCRIPTS: dict[int, list[str]] = {
    21:   ["ftp-anon"],
    22:   ["ssh-auth-methods", "ssh2-enum-algos"],
    139:  ["smb-security-mode", "smb-os-discovery", "smb-enum-shares"],
    445:  ["smb-security-mode", "smb2-security-mode", "smb-os-discovery", "smb-enum-shares", "smb2-time"],
    161:  ["snmp-info"],
    443:  ["ssl-enum-ciphers"],
    1433: ["ms-sql-info"],
    3306: ["mysql-info"],
    3389: ["rdp-ntlm-info"],
    5900: ["vnc-info"],
    8443: ["ssl-enum-ciphers"],
}


def _scripts_for_ports(open_ports: set[int]) -> dict[str, list[int]]:
    """Group: which ports to run, mapping script-set per host run."""
    relevant: dict[int, list[str]] = {}
    for p in open_ports:
        if p in PORT_SCRIPTS:
            relevant[p] = PORT_SCRIPTS[p]
    return relevant


def probe_host(
    ip: str,
    open_ports: list[int],
    log: Callable[[str], None] | None = None,
) -> list[ProbeFinding]:
    """Run deep NSE probes against one host's relevant open ports."""
    def emit(m: str) -> None:
        if log:
            log(m)

    nmap = find_nmap()
    if not nmap:
        return []

    relevant = _scripts_for_ports(set(open_ports))
    if not relevant:
        return []

    ports = ",".join(str(p) for p in sorted(relevant.keys()))
    scripts = ",".join(sorted({s for lst in relevant.values() for s in lst}))

    import threading as _t
    xml_path = Path(tempfile.gettempdir()) / f"sounrunner_probe_{_t.get_ident()}_{ip.replace('.', '_')}.xml"
    args = [
        nmap, "-Pn", "-sV",
        "-p", ports,
        "--script", scripts,
        "--script-timeout", "60s",
        "-oX", str(xml_path),
        ip,
    ]
    emit(f"[probe] {ip} — deep probing ports {ports}")

    try:
        subprocess.run(args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        emit(f"[probe] {ip} — probe timed out, partial results")
    except Exception as e:
        emit(f"[probe] {ip} — probe error: {e}")
        return []

    if not xml_path.exists():
        return []

    findings = _parse_probe_xml(xml_path.read_text(encoding="utf-8", errors="replace"), ip)
    for f in findings:
        emit(f"[probe] {ip}:{f.port} — {f.title} [{f.risk}]")
    return findings


def _parse_probe_xml(xml: str, ip: str) -> list[ProbeFinding]:
    findings: list[ProbeFinding] = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        # host-level scripts (SMB scripts land here)
        for script in host.findall(".//hostscript/script"):
            findings.extend(_interpret(ip, 0, script.get("id", ""), script.get("output", "")))
        # port-level scripts
        for port in host.findall(".//port"):
            portid = int(port.get("portid", 0))
            for script in port.findall("script"):
                findings.extend(_interpret(ip, portid, script.get("id", ""), script.get("output", "")))

    return findings


def _interpret(ip: str, port: int, script_id: str, output: str) -> list[ProbeFinding]:
    """Translate raw NSE output into structured findings."""
    out = output or ""
    low = out.lower()
    res: list[ProbeFinding] = []

    # ── SMB security mode ────────────────────────────────────────────────────
    if script_id in ("smb-security-mode", "smb2-security-mode"):
        p = port or 445
        if "message_signing: disabled" in low or "signing disabled" in low:
            res.append(ProbeFinding(
                host=ip, port=p,
                title="SMB message signing disabled",
                detail="SMB signing is disabled. An attacker on the network can perform SMB relay / man-in-the-middle attacks to authenticate as other users and access file shares.",
                risk="high",
                recommendation="Enable SMB signing. On Windows: Group Policy → 'Microsoft network server: Digitally sign communications (always)' = Enabled. On Samba: set 'server signing = mandatory' in smb.conf.",
                evidence=out.strip()[:300],
            ))
        if "authentication_level: share" in low or "account_used: guest" in low:
            res.append(ProbeFinding(
                host=ip, port=p,
                title="SMB guest / share-level authentication enabled",
                detail="The SMB service allows guest or share-level access. Unauthenticated users may be able to browse or read shared files.",
                risk="high",
                recommendation="Disable guest access. On Samba: set 'map to guest = never' and 'restrict anonymous = 2'. On Windows: disable the Guest account and require authenticated access to all shares.",
                evidence=out.strip()[:300],
            ))

    # ── SMB OS discovery ─────────────────────────────────────────────────────
    if script_id == "smb-os-discovery":
        m = re.search(r"OS:\s*([^\n]+)", out)
        if m:
            os_str = m.group(1).strip()
            # flag clearly outdated Samba / Windows
            if re.search(r"samba\s*3\.|samba\s*2\.|windows (xp|2003|2000|vista|7|server 2008)", os_str, re.I):
                res.append(ProbeFinding(
                    host=ip, port=port or 445,
                    title=f"End-of-life operating system: {os_str}",
                    detail=f"The host is running {os_str}, which is end-of-life and no longer receives security patches. It is exposed to numerous public exploits.",
                    risk="critical",
                    recommendation="Plan migration to a supported OS version urgently. EOL systems cannot be secured and are a primary breach vector.",
                    evidence=os_str,
                ))

    # ── SMB shares ───────────────────────────────────────────────────────────
    if script_id == "smb-enum-shares":
        shares = re.findall(r"\\\\[^\s:]+", out)
        anon = "anonymous" in low or "access: read" in low.replace("access: read/write", "")
        if shares and ("read" in low):
            res.append(ProbeFinding(
                host=ip, port=port or 445,
                title="SMB shares enumerable / readable",
                detail=f"SMB shares are visible and at least partially readable: {', '.join(sorted(set(shares))[:6])}. Sensitive files may be exposed to anyone on the network.",
                risk="high" if anon else "medium",
                recommendation="Review every share's permissions. Remove anonymous/Everyone access. Restrict shares to specific AD groups. Disable administrative shares not in use.",
                evidence=out.strip()[:400],
            ))

    # ── FTP anonymous ────────────────────────────────────────────────────────
    if script_id == "ftp-anon":
        if "anonymous ftp login allowed" in low or "anonymous login allowed" in low:
            res.append(ProbeFinding(
                host=ip, port=port or 21,
                title="Anonymous FTP login allowed",
                detail="The FTP server allows anonymous login. Anyone can connect without credentials and potentially read or upload files.",
                risk="high",
                recommendation="Disable anonymous FTP. In vsftpd: set 'anonymous_enable=NO'. Better: replace FTP with SFTP entirely and restrict by IP.",
                evidence=out.strip()[:300],
            ))

    # ── RDP NLA ──────────────────────────────────────────────────────────────
    if script_id == "rdp-ntlm-info":
        # presence of this output means RDP responded; check NLA
        if "nla" in low and ("not" in low or "disabled" in low):
            res.append(ProbeFinding(
                host=ip, port=port or 3389,
                title="RDP without Network Level Authentication (NLA)",
                detail="Remote Desktop is exposed without NLA. This makes it easier to brute-force and exposes the login screen to pre-auth attacks.",
                risk="high",
                recommendation="Enable NLA: System Properties → Remote → 'Allow connections only from computers running Remote Desktop with Network Level Authentication'. Move RDP behind VPN.",
                evidence=out.strip()[:300],
            ))
        # extract domain/hostname leak
        dom = re.search(r"(DNS_Domain_Name|Target_Name):\s*(\S+)", out)
        if dom:
            res.append(ProbeFinding(
                host=ip, port=port or 3389,
                title="RDP leaks internal domain/host information",
                detail=f"The RDP service discloses internal naming information ({dom.group(2)}) to unauthenticated clients, aiding attacker reconnaissance.",
                risk="low",
                recommendation="This is inherent to RDP exposure. The real fix is to not expose RDP directly — place it behind a VPN or RD Gateway.",
                evidence=out.strip()[:200],
            ))

    # ── SNMP ─────────────────────────────────────────────────────────────────
    if script_id == "snmp-info":
        res.append(ProbeFinding(
            host=ip, port=port or 161,
            title="SNMP responding to queries",
            detail="The SNMP service responded to queries. If it uses a default community string (public/private), full device configuration may be readable and in some cases writable.",
            risk="high",
            recommendation="Change default community strings. Upgrade to SNMPv3 (auth + encryption). Restrict SNMP to the monitoring server IP only.",
            evidence=out.strip()[:250],
        ))

    # ── SSL cipher enumeration ───────────────────────────────────────────────
    if script_id == "ssl-enum-ciphers":
        weak = []
        for pat, label in [("SSLv3", "SSLv3"), ("TLSv1.0", "TLS 1.0"), ("TLSv1.1", "TLS 1.1"),
                           ("RC4", "RC4 cipher"), ("3DES", "3DES cipher"), ("NULL", "NULL cipher"),
                           ("EXPORT", "EXPORT cipher")]:
            if pat in out:
                weak.append(label)
        # grade
        grade_m = re.search(r"least strength:\s*([A-F])", out)
        grade = grade_m.group(1) if grade_m else ""
        if weak or grade in ("C", "D", "E", "F"):
            detail = "The TLS service supports weak protocols/ciphers"
            if weak:
                detail += f": {', '.join(weak)}"
            if grade:
                detail += f" (overall cipher grade: {grade})"
            detail += ". These are vulnerable to downgrade and decryption attacks."
            res.append(ProbeFinding(
                host=ip, port=port or 443,
                title="Weak TLS protocols / ciphers supported",
                detail=detail,
                risk="high" if grade in ("D", "E", "F") or weak else "medium",
                recommendation="Disable SSLv3, TLS 1.0, and TLS 1.1. Disable RC4, 3DES, and NULL ciphers. Require TLS 1.2+ with ECDHE+AES-GCM. Test with: nmap --script ssl-enum-ciphers.",
                evidence=(f"Grade {grade}; " if grade else "") + ", ".join(weak),
            ))

    # ── MSSQL / MySQL info ───────────────────────────────────────────────────
    if script_id in ("ms-sql-info", "mysql-info"):
        ver = re.search(r"[Vv]ersion[:\s]+([0-9.]+)", out)
        db = "SQL Server" if "sql" in script_id else "MySQL"
        res.append(ProbeFinding(
            host=ip, port=port or (1433 if "sql" in script_id else 3306),
            title=f"{db} reachable and fingerprinted on the network",
            detail=f"The {db} database responded to unauthenticated probes" + (f" (version {ver.group(1)})" if ver else "") + ". A database directly reachable on the network is a high-value target for data theft.",
            risk="high",
            recommendation=f"Bind the database to the application server IP only. Block its port at the firewall. Enforce strong authentication and audit all accounts.",
            evidence=out.strip()[:250],
        ))

    # ── VNC ──────────────────────────────────────────────────────────────────
    if script_id == "vnc-info":
        res.append(ProbeFinding(
            host=ip, port=port or 5900,
            title="VNC service exposed and fingerprinted",
            detail="A VNC remote-desktop service is reachable on the network. VNC often runs with weak or no authentication and gives full desktop control.",
            risk="high",
            recommendation="Require a strong VNC password, restrict access to VPN only, and block port 5900 at the firewall. Disable VNC if not actively required.",
            evidence=out.strip()[:200],
        ))

    return res
