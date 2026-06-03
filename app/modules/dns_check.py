"""DNS and email security checks — SPF, DMARC, DKIM, MX."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class DnsCheck:
    name: str
    status: str          # "pass" | "fail" | "warn" | "info" | "error"
    detail: str
    recommendation: str = ""
    risk: str = "info"   # "critical" | "high" | "medium" | "low" | "info"


@dataclass
class DnsResult:
    domain: str
    checks: list[DnsCheck] = field(default_factory=list)
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return not self.error

    @property
    def failed_checks(self) -> list[DnsCheck]:
        return [c for c in self.checks if c.status == "fail"]

    @property
    def warned_checks(self) -> list[DnsCheck]:
        return [c for c in self.checks if c.status == "warn"]

    @property
    def risk_summary(self) -> str:
        risks = [c.risk for c in self.checks if c.status in ("fail", "warn")]
        if "critical" in risks:
            return "critical"
        if "high" in risks:
            return "high"
        if "medium" in risks:
            return "medium"
        if "low" in risks:
            return "low"
        return "info"


def check_domain(domain: str) -> DnsResult:
    """Run all DNS/email security checks for a domain."""
    domain = domain.strip().lower().lstrip("@")
    if not domain or "." not in domain:
        return DnsResult(domain=domain, error=f"'{domain}' does not look like a valid domain.")

    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return DnsResult(
            domain=domain,
            error="dnspython not installed. Run: pip install dnspython",
        )

    result = DnsResult(domain=domain)

    result.checks.append(_check_spf(domain))
    result.checks.append(_check_dmarc(domain))
    result.checks.extend(_check_mx(domain))
    result.checks.extend(_check_dkim(domain))

    return result


def _resolve_txt(domain: str, prefix: str = "") -> list[str]:
    """Resolve TXT records, returns list of strings or raises."""
    import dns.resolver
    target = f"{prefix}{domain}" if prefix else domain
    answers = dns.resolver.resolve(target, "TXT", lifetime=10)
    return ["".join(r.strings[i].decode("utf-8", errors="replace") for i in range(len(r.strings))) for r in answers]


def _check_spf(domain: str) -> DnsCheck:
    try:
        records = _resolve_txt(domain)
        spf_records = [r for r in records if r.startswith("v=spf1")]

        if not spf_records:
            return DnsCheck(
                name="SPF Record",
                status="fail",
                detail="No SPF record found.",
                recommendation="Add an SPF TXT record to prevent email spoofing. Example: v=spf1 include:yourmailprovider.com ~all",
                risk="high",
            )

        if len(spf_records) > 1:
            return DnsCheck(
                name="SPF Record",
                status="warn",
                detail=f"Multiple SPF records found ({len(spf_records)}). Only one is allowed.",
                recommendation="Remove duplicate SPF records — multiple records cause SPF failures.",
                risk="medium",
            )

        spf = spf_records[0]

        if "+all" in spf:
            return DnsCheck(
                name="SPF Record",
                status="fail",
                detail=f"SPF record uses '+all' — allows any server to send as your domain.",
                recommendation="Change to '~all' (softfail) or '-all' (fail) to restrict spoofing.",
                risk="critical",
            )

        qualifier = "softfail (~all)" if "~all" in spf else "hardfail (-all)" if "-all" in spf else "neutral"
        return DnsCheck(
            name="SPF Record",
            status="pass",
            detail=f"SPF record present ({qualifier}): {spf[:120]}",
            risk="info",
        )

    except Exception as exc:
        return DnsCheck(
            name="SPF Record",
            status="error",
            detail=f"Could not check SPF: {exc}",
            risk="info",
        )


def _check_dmarc(domain: str) -> DnsCheck:
    try:
        records = _resolve_txt(domain, prefix="_dmarc.")
        dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

        if not dmarc_records:
            return DnsCheck(
                name="DMARC Record",
                status="fail",
                detail="No DMARC record found.",
                recommendation="Add a DMARC TXT record at _dmarc.yourdomain.com to protect against email spoofing.",
                risk="high",
            )

        dmarc = dmarc_records[0]

        policy_match = re.search(r"p=(\w+)", dmarc)
        policy = policy_match.group(1) if policy_match else "none"

        if policy == "none":
            return DnsCheck(
                name="DMARC Record",
                status="warn",
                detail=f"DMARC record found but policy is 'none' — only monitors, does not block spoofing.",
                recommendation="Upgrade DMARC policy to p=quarantine or p=reject to actively block spoofed emails.",
                risk="medium",
            )

        return DnsCheck(
            name="DMARC Record",
            status="pass",
            detail=f"DMARC record present with policy={policy}: {dmarc[:120]}",
            risk="info",
        )

    except Exception as exc:
        if "NXDOMAIN" in str(exc) or "NoAnswer" in str(exc):
            return DnsCheck(
                name="DMARC Record",
                status="fail",
                detail="No DMARC record found at _dmarc." + domain,
                recommendation="Add a DMARC TXT record. Start with: v=DMARC1; p=none; rua=mailto:reports@yourdomain.com",
                risk="high",
            )
        return DnsCheck(
            name="DMARC Record",
            status="error",
            detail=f"Could not check DMARC: {exc}",
            risk="info",
        )


def _check_dkim(domain: str) -> list[DnsCheck]:
    """Check for DKIM records at common selectors."""
    common_selectors = ["default", "google", "mail", "k1", "selector1", "selector2", "dkim", "smtp"]
    try:
        import dns.resolver
        found_selectors: list[str] = []
        for sel in common_selectors:
            try:
                records = _resolve_txt(domain, prefix=f"{sel}._domainkey.")
                if any("v=DKIM1" in r or "k=rsa" in r for r in records):
                    found_selectors.append(sel)
            except Exception:
                continue

        if found_selectors:
            return [DnsCheck(
                name="DKIM",
                status="pass",
                detail=f"DKIM record found (selector{'s' if len(found_selectors) > 1 else ''}: {', '.join(found_selectors)}).",
                risk="info",
            )]

        return [DnsCheck(
            name="DKIM",
            status="warn",
            detail="No DKIM record found at common selectors. This does not mean DKIM is absent — it may use a non-standard selector.",
            recommendation="Confirm with your email provider that DKIM is enabled. Without DKIM, spoofed emails may bypass spam filters.",
            risk="medium",
        )]

    except Exception as exc:
        return [DnsCheck(
            name="DKIM",
            status="error",
            detail=f"Could not check DKIM: {exc}",
            risk="info",
        )]


def _check_mx(domain: str) -> list[DnsCheck]:
    checks: list[DnsCheck] = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=10)
        mx_records = sorted(answers, key=lambda r: r.preference)

        if not mx_records:
            checks.append(DnsCheck(
                name="MX Records",
                status="warn",
                detail="No MX records found — domain may not accept email.",
                risk="low",
            ))
            return checks

        mx_hosts = [str(r.exchange).rstrip(".") for r in mx_records[:5]]
        checks.append(DnsCheck(
            name="MX Records",
            status="pass",
            detail=f"Mail servers: {', '.join(mx_hosts)}",
            risk="info",
        ))

    except Exception as exc:
        checks.append(DnsCheck(
            name="MX Records",
            status="error",
            detail=f"Could not resolve MX: {exc}",
            risk="info",
        ))

    return checks
