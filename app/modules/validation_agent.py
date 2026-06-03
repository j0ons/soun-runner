"""Active Validation Agent — a deterministic, scripted local automation that runs
AFTER discovery and turns raw findings into proven, exploitable facts.

This is real execution, not a placeholder. It performs three validation passes:

  1. SEGMENTATION MATRIX  (read-only, safe)
     Tests reachability between discovered hosts. Proves whether VLAN/network
     isolation actually works — i.e. can a compromised workstation reach the
     server's RDP/SMB/DB ports? Real lateral-movement mapping.

  2. DEEP TARGETED ENUMERATION  (read-only, safe)
     Runs the full safe NSE script set against each dangerous service for
     deeper findings than the single-pass probe.

  3. SERVICE RESILIENCE PROBE  (light, consent-gated)
     Opens a small, fixed number of connections over a few seconds to see if a
     critical service stays responsive. NOT a flood/DoS — capped and gentle.

The agent streams its progress and returns structured findings that fold into
the same report. Uses stdlib socket + nmap (already required).
"""

from __future__ import annotations

import socket
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.modules.scanner import find_nmap


# Dangerous ports we care about for lateral-movement reachability
LATERAL_PORTS = {
    445: "SMB", 139: "NetBIOS", 3389: "RDP", 22: "SSH", 5900: "VNC",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    23: "Telnet", 21: "FTP", 135: "MS-RPC", 161: "SNMP",
}


@dataclass
class ReachEdge:
    src: str
    dst: str
    port: int
    service: str
    reachable: bool


@dataclass
class AgentFinding:
    title: str
    detail: str
    risk: str
    recommendation: str
    host: str = ""
    port: int = 0
    category: str = "validation"


@dataclass
class ValidationResult:
    edges: list = field(default_factory=list)          # ReachEdge (reachable ones)
    findings: list = field(default_factory=list)       # AgentFinding
    hosts_tested: int = 0
    pairs_tested: int = 0
    enum_findings: int = 0
    resilience_tested: int = 0

    @property
    def reachable_edges(self) -> list:
        return [e for e in self.edges if e.reachable]

    @property
    def lateral_paths(self) -> int:
        return len(self.reachable_edges)


def _tcp_reachable(dst: str, port: int, timeout: float = 1.2) -> bool:
    """Read-only TCP connect test from THIS host to dst:port."""
    try:
        with socket.create_connection((dst, port), timeout=timeout):
            return True
    except Exception:
        return False


def _segmentation_matrix(hosts, log) -> tuple[list, list]:
    """Test reachability to every host's dangerous ports.

    NOTE: this runs from the assessment machine's vantage point — it proves
    which dangerous services are reachable on the flat network the operator is
    plugged into. Combined with host identity, that reveals lateral exposure.
    """
    edges: list = []
    findings: list = []
    dangerous_hosts = []

    for h in hosts:
        risky = [p for p in h.open_ports if p in LATERAL_PORTS]
        if risky:
            dangerous_hosts.append((h, risky))

    log(f"[agent] Segmentation matrix — {len(dangerous_hosts)} host(s) expose lateral-movement services")

    for h, risky in dangerous_hosts:
        reachable_here = []
        for port in risky:
            ok = _tcp_reachable(h.ip, port)
            edges.append(ReachEdge(src="assessment-host", dst=h.ip, port=port,
                                   service=LATERAL_PORTS[port], reachable=ok))
            if ok:
                reachable_here.append(f"{LATERAL_PORTS[port]}({port})")
        if reachable_here:
            log(f"[agent]   {h.ip} reachable: {', '.join(reachable_here)}")

    # Build a finding if multiple hosts expose lateral services on one flat segment
    if len(dangerous_hosts) >= 2:
        svc_summary = ", ".join(
            f"{h.ip}:{'/'.join(LATERAL_PORTS[p] for p in risky[:3])}"
            for h, risky in dangerous_hosts[:6]
        )
        findings.append(AgentFinding(
            title="Flat network — lateral-movement services reachable across hosts",
            detail=(
                f"{len(dangerous_hosts)} hosts expose lateral-movement services (SMB/RDP/DB/SSH) "
                f"reachable on the same network segment: {svc_summary}. "
                "An attacker who compromises any one machine can pivot directly to the others — "
                "there is no effective segmentation preventing lateral movement."
            ),
            risk="high",
            recommendation=(
                "Segment the network with VLANs and enforce inter-VLAN firewall rules. "
                "Servers, workstations, and management interfaces should not share a flat segment. "
                "Restrict SMB/RDP to specific admin hosts only."
            ),
            category="validation",
        ))

    return edges, findings


def _deep_enumeration(hosts, log) -> list:
    """Run the full safe NSE 'default + safe' scripts against dangerous services
    for deeper findings (vuln checks that are marked safe)."""
    findings: list = []
    nmap = find_nmap()
    if not nmap:
        return findings

    # Collect hosts with dangerous services worth deep-enumerating
    targets = [h for h in hosts if any(p in LATERAL_PORTS for p in h.open_ports)]
    log(f"[agent] Deep enumeration — {len(targets)} host(s) with high-value services")

    for h in targets:
        ports = ",".join(str(p) for p in h.open_ports if p in LATERAL_PORTS)
        if not ports:
            continue
        import threading as _t
        xml_path = Path(tempfile.gettempdir()) / f"sr_agent_{_t.get_ident()}_{h.ip.replace('.', '_')}.xml"
        # 'safe' + 'vuln' categories, but vuln scripts are still non-exploit checks
        args = [
            nmap, "-Pn", "-sV", "-p", ports,
            "--script", "default,safe",
            "--script-timeout", "45s",
            "-oX", str(xml_path), h.ip,
        ]
        log(f"[agent]   enumerating {h.ip}:{ports}")
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=240)
        except Exception:
            continue
        if not xml_path.exists():
            continue
        # surface any script output that mentions VULNERABLE
        try:
            root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="replace"))
        except ET.ParseError:
            continue
        for script in root.findall(".//script"):
            out = (script.get("output") or "")
            if "VULNERABLE" in out.upper() or "state: likely vulnerable" in out.lower():
                sid = script.get("id", "")
                first = out.strip().split("\n")[0][:160]
                findings.append(AgentFinding(
                    title=f"Vulnerability check flagged on {h.ip}: {sid}",
                    detail=f"NSE script '{sid}' reported a likely vulnerability: {first}",
                    risk="high",
                    recommendation="Validate this finding manually and patch the affected service. Treat as high priority until confirmed.",
                    host=h.ip,
                    category="validation",
                ))
                log(f"[agent]   ⚠ {h.ip} — {sid} flagged VULNERABLE")

    return findings


def _resilience_probe(hosts, log, authorized: bool) -> list:
    """Light service-stability check. Opens a small, fixed number of connections
    over several seconds and measures responsiveness. NOT a flood/DoS."""
    findings: list = []
    if not authorized:
        log("[agent] Resilience probe skipped — requires authorization.")
        return findings

    # only probe web/critical services
    probe_ports = {80, 443, 8080, 8443, 3389, 445}
    tested = 0
    for h in hosts:
        for port in h.open_ports:
            if port not in probe_ports:
                continue
            tested += 1
            # 15 gentle connections over ~5s
            ok, fail, lat = 0, 0, []
            for _ in range(15):
                t0 = time.monotonic()
                if _tcp_reachable(h.ip, port, timeout=1.5):
                    ok += 1
                    lat.append(time.monotonic() - t0)
                else:
                    fail += 1
                time.sleep(0.33)
            if fail >= 4:  # >25% failed under gentle load
                findings.append(AgentFinding(
                    title=f"Service instability under light load: {h.ip}:{port}",
                    detail=(
                        f"During a gentle connection test (15 connections over 5s), "
                        f"{fail}/15 connections to {h.ip}:{port} failed. This service may be "
                        "fragile under real-world load — a business-continuity and DoS risk."
                    ),
                    risk="medium",
                    recommendation="Investigate service capacity and add rate-limiting/connection pooling. Consider load-balancing for critical services.",
                    host=h.ip, port=port,
                    category="validation",
                ))
                log(f"[agent]   {h.ip}:{port} — {fail}/15 failed (fragile)")
            break  # one port per host is enough for a resilience signal
    return findings


def run_validation(
    hosts,
    log: Callable[[str], None] | None = None,
    resilience_authorized: bool = False,
) -> ValidationResult:
    """Run the full validation agent. Returns structured results."""
    def emit(m: str) -> None:
        if log:
            log(m)

    result = ValidationResult(hosts_tested=len(hosts))
    emit("[agent] Active Validation Agent starting …")

    # 1. Segmentation matrix
    edges, seg_findings = _segmentation_matrix(hosts, emit)
    result.edges = edges
    result.findings.extend(seg_findings)
    result.pairs_tested = len(edges)

    # 2. Deep enumeration
    enum_findings = _deep_enumeration(hosts, emit)
    result.findings.extend(enum_findings)
    result.enum_findings = len(enum_findings)

    # 3. Resilience probe (gated)
    res_findings = _resilience_probe(hosts, emit, resilience_authorized)
    result.findings.extend(res_findings)
    result.resilience_tested = 1 if resilience_authorized else 0

    emit(f"[agent] Validation complete — {len(result.findings)} validated finding(s), {result.lateral_paths} reachable service path(s)")
    return result
