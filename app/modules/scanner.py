"""Network scanner — runs Nmap and returns structured host/service data."""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator


# Ports classified as dangerous when exposed on a network
DANGEROUS_PORTS: dict[int, dict] = {
    21:   {"name": "FTP",          "risk": "high",    "reason": "Cleartext file transfer — credentials and data sent in plaintext, commonly exploited"},
    22:   {"name": "SSH",          "risk": "medium",  "reason": "Remote access — verify it is intentional, restricted to admin IPs, and key-based auth only"},
    23:   {"name": "Telnet",       "risk": "critical","reason": "Cleartext remote administration — all keystrokes and passwords visible on the wire; must be disabled"},
    25:   {"name": "SMTP",         "risk": "medium",  "reason": "Mail relay — open relay enables spam abuse and phishing on behalf of this domain"},
    53:   {"name": "DNS",          "risk": "low",     "reason": "DNS service exposed — verify open recursion is disabled to prevent DNS amplification attacks"},
    80:   {"name": "HTTP",         "risk": "low",     "reason": "Unencrypted web service — user credentials and session tokens sent in plaintext"},
    110:  {"name": "POP3",         "risk": "medium",  "reason": "Cleartext email retrieval — email and passwords visible on the wire"},
    111:  {"name": "RPCBind",      "risk": "high",    "reason": "RPC portmapper — used to attack NFS and RPC services; should not be exposed on the LAN"},
    135:  {"name": "MS-RPC",       "risk": "high",    "reason": "Windows RPC endpoint mapper — used in many Windows exploits; restrict to management VLAN"},
    139:  {"name": "NetBIOS",      "risk": "high",    "reason": "Legacy Windows file sharing — enables NetBIOS name poisoning and credential theft attacks"},
    143:  {"name": "IMAP",         "risk": "medium",  "reason": "Cleartext email retrieval — email and credentials visible in transit"},
    161:  {"name": "SNMP",         "risk": "high",    "reason": "Network management — default community strings (public/private) allow full device configuration read/write"},
    389:  {"name": "LDAP",         "risk": "high",    "reason": "Directory service — unauthenticated LDAP allows enumeration of all users and groups"},
    443:  {"name": "HTTPS",        "risk": "info",    "reason": "Encrypted web service — verify TLS certificate is valid and not expired"},
    445:  {"name": "SMB",          "risk": "critical","reason": "Windows file sharing — primary ransomware entry point; EternalBlue/WannaCry exploits this port"},
    512:  {"name": "rexec",        "risk": "critical","reason": "Remote execution service — cleartext, no authentication — must be disabled immediately"},
    513:  {"name": "rlogin",       "risk": "critical","reason": "Remote login — cleartext protocol with weak trust-based auth — must be disabled"},
    514:  {"name": "rsh/syslog",   "risk": "high",    "reason": "Remote shell or syslog — rsh is cleartext with no password; syslog leaks system events"},
    873:  {"name": "rsync",        "risk": "high",    "reason": "File sync — unauthenticated rsync allows arbitrary file read/write"},
    1433: {"name": "MSSQL",        "risk": "critical","reason": "SQL Server directly exposed on the network — attackers can brute-force and dump your entire database"},
    1521: {"name": "Oracle DB",    "risk": "critical","reason": "Oracle database directly exposed — brute-force and default credentials risk full data breach"},
    2049: {"name": "NFS",          "risk": "high",    "reason": "Network File System — misconfigured NFS exports allow unauthenticated access to shared files"},
    3306: {"name": "MySQL",        "risk": "critical","reason": "MySQL database directly exposed on the network — should only be accessible from the application server"},
    3389: {"name": "RDP",          "risk": "critical","reason": "Remote Desktop Protocol — most common ransomware entry point; brute-forced and exploited daily in UAE"},
    4443: {"name": "HTTPS-Alt",    "risk": "low",     "reason": "Alternative HTTPS port — verify this web service is intentional"},
    5432: {"name": "PostgreSQL",   "risk": "critical","reason": "PostgreSQL database directly exposed — restrict to application server IP only"},
    5900: {"name": "VNC",          "risk": "critical","reason": "VNC remote desktop — often runs without auth or with weak passwords; commonly exploited"},
    5985: {"name": "WinRM HTTP",   "risk": "high",    "reason": "Windows Remote Management over HTTP — cleartext remote PowerShell; restrict to management VLAN"},
    5986: {"name": "WinRM HTTPS",  "risk": "high",    "reason": "Windows Remote Management over HTTPS — restrict to authorised management systems only"},
    6379: {"name": "Redis",        "risk": "critical","reason": "Redis cache/database — by default runs with no authentication; commonly left exposed and abused"},
    8080: {"name": "HTTP-Alt",     "risk": "medium",  "reason": "Alternative HTTP port — unencrypted web service; verify it is intentional and not an admin panel"},
    8443: {"name": "HTTPS-Alt",    "risk": "low",     "reason": "Alternative HTTPS port — verify TLS is correctly configured and access is restricted"},
    9200: {"name": "Elasticsearch","risk": "critical","reason": "Elasticsearch — frequently left with no authentication, exposing all indexed data to the network"},
    27017:{"name": "MongoDB",      "risk": "critical","reason": "MongoDB — commonly deployed with no password; full database readable by anyone on the network"},
    27018:{"name": "MongoDB-Shard","risk": "critical","reason": "MongoDB shard port — same exposure risk as primary MongoDB; no authentication by default"},
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    product: str
    version: str
    risk: str = "info"
    risk_reason: str = ""
    cves: list = field(default_factory=list)

    @property
    def display_name(self) -> str:
        parts = [self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)

    @property
    def is_dangerous(self) -> bool:
        return self.risk in ("critical", "high")


@dataclass
class Host:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    state: str = "up"
    services: list[Service] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    is_gateway: bool = False

    @property
    def display_name(self) -> str:
        return self.hostname if self.hostname and self.hostname != self.ip else self.ip

    @property
    def display_full(self) -> str:
        """`hostname (ip)` when a name resolved, else the bare IP — so a finding
        can be tied to the physical box without cross-referencing the asset table."""
        if self.hostname and self.hostname != self.ip:
            return f"{self.hostname} ({self.ip})"
        return self.ip

    @property
    def highest_risk(self) -> str:
        if not self.services:
            return "info"
        return min((s.risk for s in self.services), key=lambda r: RISK_ORDER.get(r, 99))

    @property
    def dangerous_services(self) -> list[Service]:
        return [s for s in self.services if s.is_dangerous]

    @property
    def open_ports(self) -> list[int]:
        return [s.port for s in self.services if s.state == "open"]

    @property
    def device_type(self) -> str:
        """Infer device category from open ports, OS, vendor, and MAC."""
        return classify_device(self)

    @property
    def device_icon(self) -> str:
        return DEVICE_ICONS.get(self.device_type, "🖥")


# Device classification — order matters (most specific first)
DEVICE_ICONS = {
    "Router / Gateway":   "🌐",
    "Firewall":           "🛡",
    "Windows Server":     "🖧",
    "Windows Workstation":"💻",
    "Linux Server":       "🐧",
    "NAS / Storage":      "💾",
    "IP Camera / CCTV":   "📹",
    "Printer":            "🖨",
    "VoIP / Phone":       "☎",
    "Database Server":    "🗄",
    "Web Server":         "🌍",
    "Hypervisor / ESXi":  "📦",
    "Network Device":     "🔌",
    "IoT / Embedded":     "🔧",
    "Unknown Device":     "🖥",
}


def classify_device(host: "Host") -> str:
    ports = set(host.open_ports)
    os_l = (host.os_guess or "").lower()
    vendor_l = (host.vendor or "").lower()
    hn_l = (host.hostname or "").lower()
    svc_names = " ".join(s.name.lower() + " " + (s.product or "").lower() for s in host.services)

    if host.is_gateway:
        return "Router / Gateway"

    # Vendor / hostname strong signals
    if any(v in vendor_l for v in ("synology", "qnap", "netgear rdc", "western digital")):
        return "NAS / Storage"
    if any(v in vendor_l for v in ("hikvision", "dahua", "axis comm", "uniview")) or "camera" in hn_l or "dvr" in hn_l or "nvr" in hn_l:
        return "IP Camera / CCTV"
    if any(v in vendor_l for v in ("hewlett packard", "canon", "epson", "brother", "lexmark", "xerox")) and (9100 in ports or 631 in ports or 515 in ports):
        return "Printer"
    if any(v in vendor_l for v in ("cisco", "fortinet", "palo alto", "juniper", "mikrotik", "ubiquiti", "tp-link", "huawei")):
        if 443 in ports or 80 in ports or 22 in ports:
            return "Firewall" if any(x in vendor_l for x in ("fortinet", "palo alto")) else "Network Device"

    # Service / product strong signals
    if "idrac" in svc_names or "ilo" in svc_names or "ipmi" in svc_names or "bmc" in svc_names or 623 in ports:
        return "Windows Server"  # server management controller → physical server
    if "esxi" in svc_names or "vmware" in svc_names or 902 in ports:
        return "Hypervisor / ESXi"
    if "webmin" in svc_names or 10000 in ports and "miniserv" in svc_names:
        return "Linux Server"

    # Service / port signals
    if 9100 in ports or 631 in ports or 515 in ports or "printer" in svc_names or "jetdirect" in svc_names:
        return "Printer"
    if any(p in ports for p in (554, 8000)) and ("rtsp" in svc_names or "camera" in svc_names):
        return "IP Camera / CCTV"
    if 5000 in ports and ("synology" in svc_names or "dsm" in svc_names):
        return "NAS / Storage"
    if 5900 in ports and ("vmware" in svc_names or "esxi" in os_l) or "vmware esx" in os_l or 902 in ports:
        return "Hypervisor / ESXi"
    if 5060 in ports or "sip" in svc_names or "asterisk" in svc_names:
        return "VoIP / Phone"

    db_ports = {1433, 1521, 3306, 5432, 6379, 27017, 9200}
    if ports & db_ports:
        return "Database Server"

    # OS-based
    if "windows server" in os_l or (445 in ports and 3389 in ports and 88 in ports):
        return "Windows Server"
    if "windows" in os_l or vendor_l == "microsoft" or (445 in ports and 3389 in ports):
        return "Windows Workstation"
    if "linux" in os_l and (80 in ports or 443 in ports or 22 in ports):
        return "Linux Server"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "Web Server"
    if 22 in ports:
        return "Linux Server"

    if not ports:
        return "Unknown Device"
    return "IoT / Embedded"


@dataclass
class ScanResult:
    target: str
    hosts: list[Host] = field(default_factory=list)
    scan_command: str = ""
    error: str = ""
    raw_xml: str = ""

    @property
    def succeeded(self) -> bool:
        return not self.error

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def all_services(self) -> list[tuple[Host, Service]]:
        return [(h, s) for h in self.hosts for s in h.services]

    @property
    def critical_findings(self) -> list[tuple[Host, Service]]:
        return [(h, s) for h, s in self.all_services if s.risk == "critical"]

    @property
    def high_findings(self) -> list[tuple[Host, Service]]:
        return [(h, s) for h, s in self.all_services if s.risk == "high"]

    def findings_by_risk(self) -> list[tuple[Host, Service]]:
        pairs = self.all_services
        return sorted(pairs, key=lambda x: RISK_ORDER.get(x[1].risk, 99))


def find_nmap() -> str | None:
    """Locate nmap binary — checks PATH first, then common install locations."""
    candidates = ["nmap"]
    if sys.platform == "win32":
        candidates += [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    # On Windows, shutil.which may miss absolute paths — try direct existence
    if sys.platform == "win32":
        for path in candidates[1:]:
            if Path(path).exists():
                return path
    return None


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a target spec: one or more IPs/CIDRs separated by space or comma."""
    parts = [p.strip() for p in target.replace(",", " ").split() if p.strip()]
    if not parts:
        return False, "No target specified."
    for part in parts:
        ok = False
        try:
            ipaddress.ip_network(part, strict=False)
            ok = True
        except ValueError:
            try:
                ipaddress.ip_address(part)
                ok = True
            except ValueError:
                ok = False
        if not ok:
            return False, f"'{part}' is not a valid IP address or subnet (e.g. 192.168.1.0/24)"
    return True, ""


def _build_args(nmap: str, profile: str, xml_path: Path, target: str) -> list[str]:
    """Return the nmap argument list for the given profile."""
    base = [nmap, "-sV", "--open", "-oX", str(xml_path)]
    if profile == "quick":
        return base + ["--top-ports", "100", "-T4", target]
    if profile == "thorough":
        return base + ["--top-ports", "1000", "-T3", target]
    # standard
    return base + ["--top-ports", "500", "-T4", target]


def run_scan(target: str, profile: str = "standard", xml_out: Path | None = None) -> ScanResult:
    """Run Nmap scan and return parsed results."""
    nmap = find_nmap()
    if not nmap:
        return ScanResult(
            target=target,
            error="Nmap is not installed. Download from https://nmap.org/download and install it, then restart Soun Runner.",
        )

    valid, err = validate_target(target)
    if not valid:
        return ScanResult(target=target, error=err)

    # Use a temp file so it works on Windows (no /tmp) and avoids permission issues
    if xml_out:
        xml_path = xml_out
    else:
        xml_path = Path(tempfile.gettempdir()) / "sounrunner_scan.xml"

    args = _build_args(nmap, profile, xml_path, target)
    cmd_str = " ".join(args)

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=900,  # 15 min — enough for thorough /24 scan
        )
    except subprocess.TimeoutExpired:
        return ScanResult(target=target, scan_command=cmd_str, error="Scan timed out after 15 minutes.")
    except FileNotFoundError:
        return ScanResult(target=target, scan_command=cmd_str, error="Nmap binary not found.")

    if proc.returncode != 0 and not xml_path.exists():
        return ScanResult(
            target=target,
            scan_command=cmd_str,
            error=f"Nmap failed: {proc.stderr[:400]}",
        )

    raw_xml = xml_path.read_text(encoding="utf-8", errors="replace") if xml_path.exists() else ""
    hosts = _parse_xml(raw_xml) if raw_xml else []

    return ScanResult(
        target=target,
        hosts=hosts,
        scan_command=cmd_str,
        raw_xml=raw_xml,
    )


def _discovery_args(nmap: str, xml_path: Path, target: str) -> list[str]:
    """Stage-1 host discovery — multi-probe so we don't miss hosts that block
    ICMP ping (Windows VMs, hardened Linux, appliances).

    Uses ONLY probes that work WITHOUT root/administrator privilege, because
    the field operator usually runs as a normal user:
      -PE        ICMP echo   (nmap auto-falls-back to TCP if unprivileged)
      -PS…       TCP SYN to common service ports — the key ping-blocker catcher
      -PA…       TCP ACK to common ports — slips past some stateless filters
    nmap automatically performs an ARP sweep on the local subnet when possible.
    (-PU/-PR raw probes require root and are intentionally omitted.)
    """
    common_syn = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5900,8006,8080,8443"
    common_ack = "80,443,3389,8006"
    targets = [t for t in target.replace(",", " ").split() if t]
    return [
        nmap, "-sn", "-n",
        "-PE",
        f"-PS{common_syn}",
        f"-PA{common_ack}",
        "-T4", "-v", "--stats-every", "2s",
        "-oX", str(xml_path),
    ] + targets


def _service_args(nmap: str, profile: str, xml_path: Path, targets: str) -> list[str]:
    """Stage-2 service/version scan against only the live hosts.

    -Pn skips re-discovery (we already confirmed these hosts are up), so
    ping-blocking hosts are still fully port-scanned instead of being dropped.

    -R --system-dns forces reverse-DNS on every host using the OPERATING SYSTEM
    resolver (not nmap's own). On a client LAN the OS resolver also answers from
    the local DNS / hosts file / AD, so we recover human-readable hostnames
    (e.g. "RECEPTION-PC") instead of bare IPs — which is what the operator needs
    to know which box a finding belongs to. nbstat (NetBIOS) is added too so
    Windows machines that don't have a PTR record still surface their name.
    """
    base = [nmap, "-sV", "-Pn", "--open", "-R", "--system-dns",
            "--script", "nbstat", "-v", "--stats-every", "3s", "-oX", str(xml_path)]
    if profile == "quick":
        ports = ["--top-ports", "100", "-T4"]
    elif profile == "thorough":
        ports = ["--top-ports", "1000", "-T3"]
    else:
        ports = ["--top-ports", "500", "-T4"]
    return base + ports + targets.split()


def run_scan_streaming(
    target: str,
    profile: str,
    gateway: str = "",
    log=None,
    job_id: str = "",
) -> ScanResult:
    """Two-stage streaming scan: (1) host discovery, (2) service scan.

    Streams genuine nmap output line-by-line via the `log` callback so the
    operator sees real activity, then returns a fully parsed ScanResult.

    `job_id` makes the temp XML filenames unique so concurrent scans never
    overwrite each other's output.
    """
    def emit(msg: str) -> None:
        if log:
            log(msg)

    nmap = find_nmap()
    if not nmap:
        return ScanResult(target=target, error="Nmap is not installed. Download from https://nmap.org/download and restart Soun Runner.")

    valid, err = validate_target(target)
    if not valid:
        return ScanResult(target=target, error=err)

    tmp = Path(tempfile.gettempdir())
    suffix = (job_id or str(os.getpid()))
    disco_xml = tmp / f"sounrunner_disco_{suffix}.xml"
    svc_xml = tmp / f"sounrunner_svc_{suffix}.xml"
    # Remove any leftover XML from previous runs so output never accumulates.
    for f in (disco_xml, svc_xml):
        try:
            f.unlink()
        except FileNotFoundError:
            pass

    # ── Stage 1: host discovery ──────────────────────────────────────────────
    emit(f"[discovery] Sweeping {target} for live hosts …")
    disco_args = _discovery_args(nmap, disco_xml, target)
    live_ips: list[str] = []
    try:
        proc = subprocess.Popen(disco_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for raw in proc.stdout:  # type: ignore[union-attr]
            line = raw.rstrip()
            if not line:
                continue
            if "Nmap scan report for" in line and "[host down]" not in line:
                ip_part = line.replace("Nmap scan report for", "").strip()
                emit(f"[discovery] HOST UP → {ip_part}")
            elif "Stats:" in line or "% done" in line:
                emit(f"[discovery] {line.strip()}")
            elif line.startswith("Initiating") or line.startswith("Completed"):
                emit(f"[discovery] {line.strip()}")
        proc.wait()
    except Exception as e:
        return ScanResult(target=target, error=f"Discovery failed: {e}")

    # Parse discovery to get live IP list
    if disco_xml.exists():
        disco_hosts = _parse_xml(disco_xml.read_text(encoding="utf-8", errors="replace"))
        live_ips = [h.ip for h in disco_hosts]

    if not live_ips:
        emit("[discovery] No live hosts found.")
        return ScanResult(target=target, hosts=[], scan_command=" ".join(disco_args))

    emit(f"[discovery] {len(live_ips)} live host(s) found. Starting service enumeration …")

    # ── Stage 2: service / version scan on live hosts only ───────────────────
    targets_str = " ".join(live_ips)
    svc_args = _service_args(nmap, profile, svc_xml, targets_str)
    cmd_str = " ".join(svc_args[:8]) + f" … ({len(live_ips)} hosts)"
    try:
        proc = subprocess.Popen(svc_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        cur_host = ""
        for raw in proc.stdout:  # type: ignore[union-attr]
            line = raw.rstrip()
            if not line:
                continue
            if "Scanning" in line and "[" in line:
                emit(f"[scan] {line.strip()}")
            elif "Nmap scan report for" in line:
                cur_host = line.replace("Nmap scan report for", "").strip()
                emit(f"[scan] Enumerating {cur_host} …")
            elif "Discovered open port" in line:
                emit(f"[scan] {line.replace('Discovered open port', 'OPEN PORT').strip()}")
            elif "/tcp" in line and "open" in line:
                emit(f"[scan]   {line.strip()}")
            elif "Stats:" in line or "% done" in line:
                emit(f"[scan] {line.strip()}")
            elif line.startswith("Completed") and "Scan" in line:
                emit(f"[scan] {line.strip()}")
        proc.wait()
    except Exception as e:
        return ScanResult(target=target, error=f"Service scan failed: {e}")

    raw_xml = svc_xml.read_text(encoding="utf-8", errors="replace") if svc_xml.exists() else ""
    hosts = _parse_xml(raw_xml) if raw_xml else []

    # Emit the resolved IP→hostname map so the operator can tell which physical
    # box each finding belongs to. The XML hostname (PTR/NetBIOS) is authoritative,
    # so we print it here rather than scraping nmap's stdout.
    if hosts:
        emit("[scan] Identified hosts:")
        for h in hosts:
            label = f"{h.ip}" + (f"  ({h.hostname})" if h.hostname else "  (no name resolved)")
            emit(f"[scan]   • {label}")

    # Flag the gateway host
    if gateway:
        for h in hosts:
            if h.ip == gateway:
                h.is_gateway = True

    emit(f"[scan] Service enumeration complete — {len(hosts)} host(s) profiled.")
    return ScanResult(target=target, hosts=hosts, scan_command=cmd_str, raw_xml=raw_xml)


def _parse_xml(xml) -> list[Host]:
    hosts: list[Host] = []
    if isinstance(xml, bytes):
        xml = xml.decode("utf-8", errors="replace")

    # Robustness: the -oX file can contain stray/duplicate data appended after
    # the first complete document (overlapping writes, leftover from a prior run).
    # Take the FIRST complete <nmaprun>…</nmaprun> document — it is the run we
    # launched and contains the full host/port results.
    start = xml.find("<nmaprun")
    if start != -1:
        end = xml.find("</nmaprun>", start)
        if end != -1:
            # preserve the XML declaration/prolog before <nmaprun> for the parser
            prolog = xml[:start]
            xml = prolog + xml[start: end + len("</nmaprun>")]

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        # Last-resort: strip stray control chars and retry once
        import re as _re
        cleaned = _re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", xml)
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            return hosts

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        mac_el = host_el.find("address[@addrtype='mac']")
        mac = mac_el.get("addr", "") if mac_el is not None else ""
        vendor = mac_el.get("vendor", "") if mac_el is not None else ""

        hostname = ""
        for hn in host_el.findall(".//hostname"):
            if hn.get("type") in ("PTR", "user"):
                hostname = hn.get("name", "")
                break

        os_guess = ""
        osmatch = host_el.find(".//osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name", "")

        host = Host(ip=ip, hostname=hostname, os_guess=os_guess, mac=mac, vendor=vendor)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portnum = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")

                svc_el = port_el.find("service")
                svc_name = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""

                risk = "info"
                risk_reason = ""
                if portnum in DANGEROUS_PORTS:
                    risk = DANGEROUS_PORTS[portnum]["risk"]
                    risk_reason = DANGEROUS_PORTS[portnum]["reason"]

                host.services.append(Service(
                    port=portnum,
                    protocol=proto,
                    state="open",
                    name=svc_name or DANGEROUS_PORTS.get(portnum, {}).get("name", str(portnum)),
                    product=product,
                    version=version,
                    risk=risk,
                    risk_reason=risk_reason,
                ))

        # Sort services by risk then port
        host.services.sort(key=lambda s: (RISK_ORDER.get(s.risk, 99), s.port))
        hosts.append(host)

    # Sort hosts: most dangerous first
    hosts.sort(key=lambda h: RISK_ORDER.get(h.highest_risk, 99))
    return hosts


def stream_scan(target: str, profile: str = "standard") -> Generator[str, None, ScanResult]:
    """Generator that yields live nmap output lines, then returns ScanResult."""
    nmap = find_nmap()
    if not nmap:
        yield "error: Nmap not installed"
        return ScanResult(target=target, error="Nmap not installed.")

    valid, err = validate_target(target)
    if not valid:
        yield f"error: {err}"
        return ScanResult(target=target, error=err)

    xml_path = Path(tempfile.gettempdir()) / "sounrunner_scan.xml"
    args = _build_args(nmap, profile, xml_path, target)
    cmd_str = " ".join(args)
    yield f"Running: {cmd_str}"

    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip()
            if line:
                yield line
        proc.wait()
    except Exception as exc:
        yield f"error: {exc}"
        return ScanResult(target=target, scan_command=cmd_str, error=str(exc))

    raw_xml = xml_path.read_text(encoding="utf-8", errors="replace") if xml_path.exists() else ""
    hosts = _parse_xml(raw_xml) if raw_xml else []

    return ScanResult(target=target, hosts=hosts, scan_command=cmd_str, raw_xml=raw_xml)
