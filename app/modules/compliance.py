"""Compliance mapping — maps findings to UAE and international control frameworks.

Translates technical findings into the language management and auditors care about:
  - UAE IA (NESA / SIA Information Assurance Standards)
  - ISO/IEC 27001:2022 Annex A controls
  - PCI-DSS v4.0 requirements

This is what turns a technical report into a board-level compliance gap report.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ControlMapping:
    finding_key: str
    nesa: str = ""
    iso27001: str = ""
    pci: str = ""


@dataclass
class ComplianceGap:
    control_id: str
    framework: str        # "UAE IA" | "ISO 27001" | "PCI-DSS"
    control_name: str
    failing_findings: list = field(default_factory=list)   # finding titles
    risk: str = "medium"


# Keyword → control mapping. Each finding is matched by keywords in its title/detail.
# Format: (match_keywords, NESA control, ISO control, PCI requirement, control_name)
RULES = [
    (["rdp", "remote desktop"],
     "T7.5.1 Remote Access", "A.8.16 / A.6.7 Remote working", "PCI 1.3 / 8.3.2",
     "Secure remote access"),
    (["smb", "netbios", "signing", "file sharing"],
     "T3.2.1 Network Segregation", "A.8.20 Network security", "PCI 1.2 / 2.2",
     "Network service hardening"),
    (["telnet", "ftp", "cleartext", "plaintext", "http login"],
     "T5.5.1 Cryptography in transit", "A.8.24 Use of cryptography", "PCI 4.1 / 4.2",
     "Encryption of data in transit"),
    (["database", "mysql", "mssql", "postgres", "mongodb", "redis", "sql"],
     "T3.4.1 Asset Protection", "A.8.12 Data leakage prevention", "PCI 1.3 / 7.1",
     "Restrict access to cardholder/sensitive data"),
    (["ssl", "tls", "cipher", "certificate", "weak", "hsts"],
     "T5.5.2 Cryptographic Standards", "A.8.24 Use of cryptography", "PCI 4.2.1",
     "Strong cryptography for transmissions"),
    (["dmarc", "spf", "dkim", "email", "spoof"],
     "T8.3.1 Email Security", "A.8.23 Web filtering / messaging", "PCI 5.4",
     "Anti-phishing / email authentication"),
    (["snmp", "default community", "default credential", "default password"],
     "T6.2.1 Identity & Access", "A.5.17 Authentication information", "PCI 2.2.2 / 8.3",
     "Change vendor default credentials"),
    (["admin interface", "admin panel", "management interface", "exposed"],
     "T3.2.2 Management Network", "A.8.20 Network security", "PCI 2.2 / 1.3",
     "Isolate management interfaces"),
    (["end-of-life", "eol", "outdated", "unsupported", "no longer"],
     "T4.1.1 Patch Management", "A.8.8 Technical vulnerabilities", "PCI 6.3.3",
     "Maintain supported, patched systems"),
    (["vnc", "remote control"],
     "T7.5.1 Remote Access", "A.8.16 Monitoring activities", "PCI 8.3.2",
     "Secure remote access"),
    (["cve", "vulnerability", "exploit"],
     "T4.1.2 Vulnerability Management", "A.8.8 Technical vulnerabilities", "PCI 6.3.1 / 11.3",
     "Identify and remediate vulnerabilities"),
]


@dataclass
class ComplianceResult:
    gaps: list = field(default_factory=list)            # list[dict]
    frameworks_touched: set = field(default_factory=set)

    @property
    def has_gaps(self) -> bool:
        return bool(self.gaps)

    @property
    def gap_count(self) -> int:
        return len(self.gaps)


def map_findings(findings) -> ComplianceResult:
    """Map a list of report Finding objects to compliance control gaps.

    `findings` items must have `.title`, `.detail`, `.risk`.
    """
    result = ComplianceResult()
    # control_id → aggregated gap
    agg: dict[str, dict] = {}

    for f in findings:
        blob = f"{getattr(f, 'title', '')} {getattr(f, 'detail', '')}".lower()
        risk = getattr(f, "risk", "medium")

        for keywords, nesa, iso, pci, name in RULES:
            if any(kw in blob for kw in keywords):
                # one row per (control name) — group findings under it
                key = name
                if key not in agg:
                    agg[key] = {
                        "control_name": name,
                        "nesa": nesa,
                        "iso27001": iso,
                        "pci": pci,
                        "findings": [],
                        "risk": risk,
                    }
                title = getattr(f, "title", "")
                if title not in agg[key]["findings"]:
                    agg[key]["findings"].append(title)
                # escalate risk to the highest seen
                order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if order.get(risk, 9) < order.get(agg[key]["risk"], 9):
                    agg[key]["risk"] = risk
                break  # one control per finding (first match wins)

    result.gaps = sorted(
        agg.values(),
        key=lambda g: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(g["risk"], 9),
    )
    if result.gaps:
        result.frameworks_touched = {"UAE IA (NESA)", "ISO 27001:2022", "PCI-DSS v4.0"}
    return result
