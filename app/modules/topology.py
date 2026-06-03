"""Network path / topology discovery — traces the route from the client LAN
out through the gateway to the ISP edge and the public internet.

Each hop is enriched with reverse-DNS and (for public hops) ASN/ISP/geo data.
This maps the *perimeter* — what stands between the client network and the
internet — which is exactly the picture a CISO pays to see.

Cross-platform, stdlib + urllib only. Streams hops as they are found.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Generator


@dataclass
class Hop:
    number: int
    ip: str
    rtt_ms: float = 0.0
    hostname: str = ""
    is_private: bool = False
    is_timeout: bool = False
    isp: str = ""
    asn: str = ""
    city: str = ""
    country: str = ""
    role: str = ""        # "Local Gateway" | "Internal Hop" | "ISP Edge" | "Internet"

    @property
    def display(self) -> str:
        if self.is_timeout:
            return "* * * (no response)"
        return self.hostname or self.ip


@dataclass
class TopologyResult:
    target_traced: str
    hops: list[Hop] = field(default_factory=list)
    public_ip: str = ""
    error: str = ""

    @property
    def hop_count(self) -> int:
        return len([h for h in self.hops if not h.is_timeout])

    @property
    def isp_edge(self) -> "Hop | None":
        for h in self.hops:
            if not h.is_private and not h.is_timeout:
                return h
        return None

    @property
    def internal_hops(self) -> list[Hop]:
        return [h for h in self.hops if h.is_private and not h.is_timeout]

    @property
    def external_hops(self) -> list[Hop]:
        return [h for h in self.hops if not h.is_private and not h.is_timeout]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _enrich_public(hop: Hop) -> None:
    """Add ASN / ISP / geo for a public hop via ip-api.com."""
    try:
        url = f"http://ip-api.com/json/{hop.ip}?fields=status,isp,org,as,city,country"
        req = urllib.request.Request(url, headers={"User-Agent": "SounRunner/3.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read().decode("utf-8"))
        if d.get("status") == "success":
            hop.isp = d.get("isp", "")
            hop.asn = d.get("as", "")
            hop.city = d.get("city", "")
            hop.country = d.get("country", "")
    except Exception:
        pass


def _traceroute_cmd(target: str, max_hops: int) -> list[str]:
    if sys.platform == "win32":
        # tracert: -d no DNS (we do our own), -h max hops, -w timeout ms
        return ["tracert", "-d", "-h", str(max_hops), "-w", "1500", target]
    # macOS / Linux: -n numeric, -m max, -w wait, -q 1 query
    return ["traceroute", "-n", "-m", str(max_hops), "-w", "2", "-q", "1", target]


def _parse_hop_line(line: str) -> tuple[int, str, float] | None:
    """Parse a single traceroute/tracert line → (hop_no, ip, rtt_ms)."""
    line = line.strip()
    if not line:
        return None

    # Windows tracert:  "  3    12 ms    11 ms    13 ms  94.207.x.x"
    # Unix traceroute:  " 3  94.207.x.x  3.953 ms"
    m = re.match(r"^\s*(\d+)\s+(.*)$", line)
    if not m:
        return None
    hop_no = int(m.group(1))
    rest = m.group(2)

    # all timeouts
    if rest.replace("*", "").replace(" ", "") == "":
        return (hop_no, "", 0.0)

    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", rest)
    if not ip_match:
        return (hop_no, "", 0.0)
    ip = ip_match.group(1)

    rtt_match = re.search(r"([\d.]+)\s*ms", rest)
    rtt = float(rtt_match.group(1)) if rtt_match else 0.0

    return (hop_no, ip, rtt)


def trace_path(
    target: str = "8.8.8.8",
    max_hops: int = 15,
    log: Callable[[str], None] | None = None,
) -> TopologyResult:
    """Run traceroute, enrich hops, and return a full topology map.

    `log` is an optional callback for live streaming of each hop.
    """
    result = TopologyResult(target_traced=target)

    def emit(msg: str) -> None:
        if log:
            log(msg)

    cmd = _traceroute_cmd(target, max_hops)
    emit(f"Tracing path to internet via {target} …")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except FileNotFoundError:
        result.error = "traceroute/tracert not available on this system."
        emit(result.error)
        return result
    except Exception as e:
        result.error = str(e)
        emit(f"Trace error: {e}")
        return result

    seen_ips: set[str] = set()
    for raw in proc.stdout:  # type: ignore[union-attr]
        parsed = _parse_hop_line(raw)
        if not parsed:
            continue
        hop_no, ip, rtt = parsed

        if not ip:
            hop = Hop(number=hop_no, ip="", is_timeout=True)
            result.hops.append(hop)
            emit(f"  hop {hop_no:>2}  * * *  (no response — filtered or ICMP-blocked)")
            continue

        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        priv = _is_private(ip)
        hop = Hop(number=hop_no, ip=ip, rtt_ms=rtt, is_private=priv)
        hop.hostname = _reverse_dns(ip)

        if priv:
            hop.role = "Local Gateway" if hop_no == 1 else "Internal Hop"
            label = f"[{hop.role}]"
            emit(f"  hop {hop_no:>2}  {ip:<16} {rtt:>6.1f}ms  {label}")
        else:
            _enrich_public(hop)
            # first public hop = ISP edge
            if not any(h for h in result.hops if not h.is_private and not h.is_timeout):
                hop.role = "ISP Edge"
            else:
                hop.role = "Internet Backbone"
            isp_short = (hop.isp or "")[:32]
            emit(f"  hop {hop_no:>2}  {ip:<16} {rtt:>6.1f}ms  [{hop.role}] {isp_short} {hop.asn}")

        result.hops.append(hop)

    proc.wait()
    emit(f"Path discovery complete — {result.hop_count} live hop(s) mapped.")
    return result
