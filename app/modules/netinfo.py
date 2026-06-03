"""Network auto-detection — local subnet, gateway, public IP, ISP/ASN.

Cross-platform (Windows / macOS / Linux), stdlib + urllib only.
Used to pre-fill the assessment form and to anchor topology discovery.
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


@dataclass
class NetInfo:
    local_ip: str = ""
    subnet: str = ""             # e.g. 192.168.1.0/24
    gateway: str = ""
    public_ip: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    city: str = ""
    country: str = ""
    hostname: str = ""
    interface: str = ""
    error: str = ""

    @property
    def has_public_info(self) -> bool:
        return bool(self.public_ip and self.isp)


def _local_ip() -> str:
    """Determine the primary outbound IP without sending traffic."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()


def _detect_gateway() -> str:
    """Find the default gateway across Windows / macOS / Linux."""
    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=8
            ).stdout
            # Find "Default Gateway . . . : x.x.x.x"
            matches = re.findall(r"Default Gateway[ .]*:\s*([\d.]+)", out)
            for m in matches:
                if m and m != "0.0.0.0":
                    return m
            return ""
        elif sys.platform == "darwin":
            out = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=8
            ).stdout
            m = re.search(r"gateway:\s*([\d.]+)", out)
            return m.group(1) if m else ""
        else:  # linux
            out = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=8
            ).stdout
            m = re.search(r"default via ([\d.]+)", out)
            if m:
                return m.group(1)
            # fallback: route -n
            out = subprocess.run(
                ["route", "-n"], capture_output=True, text=True, timeout=8
            ).stdout
            for line in out.splitlines():
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
            return ""
    except Exception:
        return ""


def _detect_interface() -> str:
    """Best-effort active interface name."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=6
            ).stdout
            m = re.search(r"interface:\s*(\S+)", out)
            return m.group(1) if m else ""
        elif sys.platform != "win32":
            out = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=6
            ).stdout
            m = re.search(r"default via [\d.]+ dev (\S+)", out)
            return m.group(1) if m else ""
    except Exception:
        pass
    return ""


def lookup_ip_info(ip: str = "") -> dict:
    """Query ip-api.com (free, no key) for ISP/ASN/geo. Empty ip = self."""
    try:
        target = ip if ip else ""
        url = f"http://ip-api.com/json/{target}?fields=status,query,isp,org,as,city,country,regionName"
        req = urllib.request.Request(url, headers={"User-Agent": "SounRunner/3.0"})
        with urllib.request.urlopen(req, timeout=7) as r:
            data = json.loads(r.read().decode("utf-8"))
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return {}


def detect() -> NetInfo:
    """Run full local network auto-detection."""
    info = NetInfo()

    try:
        info.hostname = socket.gethostname()
    except Exception:
        pass

    info.local_ip = _local_ip()
    info.interface = _detect_interface()

    # Derive /24 subnet from local IP
    if info.local_ip and not info.local_ip.startswith("127."):
        try:
            net = ipaddress.ip_network(f"{info.local_ip}/24", strict=False)
            info.subnet = str(net)
        except Exception:
            info.subnet = ""

    info.gateway = _detect_gateway()

    # Public IP / ISP / ASN
    pub = lookup_ip_info()
    if pub:
        info.public_ip = pub.get("query", "")
        info.isp = pub.get("isp", "")
        info.org = pub.get("org", "")
        info.asn = pub.get("as", "")
        info.city = pub.get("city", "")
        info.country = pub.get("country", "")

    if not info.local_ip or info.local_ip == "127.0.0.1":
        info.error = "Could not determine local network interface."

    return info


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def discover_routed_subnets(local_subnet: str = "", max_hops: int = 6) -> list[dict]:
    """Find neighbouring private subnets reachable through the gateway by tracing
    a short path and collecting the private hops along the way. Each becomes a
    candidate /24 the operator can choose to scan (catches segmented VMs).

    Returns list of {"subnet": "10.0.160.0/24", "via": "10.0.160.253", "hops": 2}.
    Best-effort; returns [] on any failure.
    """
    found: dict[str, dict] = {}
    try:
        if sys.platform == "win32":
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", "8.8.8.8"]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", "8.8.8.8"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=40).stdout

        for line in out.splitlines():
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if not m:
                continue
            ip = m.group(1)
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not addr.is_private:
                break  # reached the public internet — stop
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            if net == local_subnet:
                continue
            if net not in found:
                found[net] = {"subnet": net, "via": ip, "hops": len(found) + 1}
    except Exception:
        return []

    return list(found.values())
