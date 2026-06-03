"""CVE lookup against NVD API — stdlib only, no requests dependency.

Queries the NIST NVD CVE 2.0 API by CPE keyword to find known vulnerabilities
for detected service versions. Results are cached in-memory per session.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

_CACHE: dict[str, list["Cve"]] = {}
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_HEADERS = {"User-Agent": "SounRunner/2.0 (sounalhosn.ae)"}
_RATE_LIMIT_DELAY = 0.6  # NVD public API: 5 req/30 sec without key → ~6/min safe


@dataclass
class Cve:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published: str
    url: str

    @property
    def risk(self) -> str:
        if self.cvss_score >= 9.0:
            return "critical"
        if self.cvss_score >= 7.0:
            return "high"
        if self.cvss_score >= 4.0:
            return "medium"
        return "low"


def _nvd_request(params: dict) -> dict:
    qs = urllib.parse.urlencode(params)
    url = f"{_NVD_BASE}?{qs}"
    req = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _parse_cvss(vuln: dict) -> tuple[float, str]:
    """Extract highest available CVSS score and severity from NVD response."""
    metrics = vuln.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            sev = data.get("baseSeverity", "")
            if not sev:
                if score >= 9.0:
                    sev = "CRITICAL"
                elif score >= 7.0:
                    sev = "HIGH"
                elif score >= 4.0:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"
            return score, sev.title()
    return 0.0, "Unknown"


def lookup_cves(product: str, version: str, max_results: int = 5) -> list[Cve]:
    """Look up CVEs for a product/version combination.

    Returns up to max_results CVEs sorted by CVSS score descending.
    Returns empty list on any error (network, rate limit, etc.).
    """
    if not product:
        return []

    # Build a clean keyword query
    product_clean = re.sub(r"[^\w\s\-.]", "", product.lower()).strip()
    version_clean = re.sub(r"[^\w\s\-.]", "", version.lower()).strip() if version else ""

    cache_key = f"{product_clean}:{version_clean}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    try:
        time.sleep(_RATE_LIMIT_DELAY)  # respect rate limit

        # Search by keyword; version in product keyword gives best signal
        keyword = f"{product_clean} {version_clean}".strip() if version_clean else product_clean
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results * 2, 20),
            "noRejected": "",
        }

        data = _nvd_request(params)
        vulns = data.get("vulnerabilities", [])

        results: list[Cve] = []
        for v in vulns:
            cve_data = v.get("cve", {})
            cve_id = cve_data.get("id", "")
            descriptions = cve_data.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            desc = desc[:200] + "…" if len(desc) > 200 else desc

            score, severity = _parse_cvss(cve_data)
            published = cve_data.get("published", "")[:10]
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            if score > 0:
                results.append(Cve(
                    cve_id=cve_id,
                    description=desc,
                    cvss_score=score,
                    severity=severity,
                    published=published,
                    url=url,
                ))

        # Sort by score descending, keep top N
        results.sort(key=lambda c: c.cvss_score, reverse=True)
        results = results[:max_results]

        _CACHE[cache_key] = results
        return results

    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        # Network unavailable or rate limited — fail silently, don't break the scan
        _CACHE[cache_key] = []
        return []
    except Exception:
        _CACHE[cache_key] = []
        return []


# Well-known service → CVE lookup hints
# Maps nmap service names to cleaner search terms for better NVD hits
_SERVICE_SEARCH_MAP: dict[str, str] = {
    "ms-wbt-server": "windows remote desktop rdp",
    "microsoft-ds": "windows smb",
    "netbios-ssn": "samba smb",
    "msrpc": "windows rpc",
    "domain": "bind dns",
    "http": "apache nginx",
    "ssh": "openssh",
    "ftp": "vsftpd proftpd",
    "telnet": "telnet",
    "mysql": "mysql",
    "ms-sql-s": "mssql sql server",
    "postgresql": "postgresql",
    "mongodb": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "vnc": "vnc tightvnc",
    "ldap": "openldap",
    "snmp": "snmp net-snmp",
}


def get_search_term(svc_name: str, product: str) -> str:
    """Return the best search term for NVD lookup."""
    # Prefer actual product name if detected by nmap
    if product and len(product) > 2:
        return product
    return _SERVICE_SEARCH_MAP.get(svc_name.lower(), svc_name)
