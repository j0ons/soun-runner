"""SSL/TLS certificate and cipher analysis — stdlib only, no dependencies."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class SslFinding:
    name: str
    status: str        # pass | fail | warn | info | error
    detail: str
    recommendation: str = ""
    risk: str = "info"


@dataclass
class SslResult:
    host: str
    port: int
    findings: list[SslFinding] = field(default_factory=list)
    error: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    days_until_expiry: int = 9999
    protocol: str = ""
    cipher: str = ""

    @property
    def succeeded(self) -> bool:
        return not self.error

    @property
    def failed(self) -> list[SslFinding]:
        return [f for f in self.findings if f.status in ("fail", "warn")]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_ssl(host: str, port: int = 443, timeout: int = 8) -> SslResult:
    result = SslResult(host=host, port=port)

    # Skip IP addresses — no cert hostname validation possible
    if _is_ip(host):
        result.error = "SSL checks require a hostname, not an IP address."
        return result

    try:
        ctx = ssl.create_default_context()
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        cert = tls_sock.getpeercert()
        cipher_info = tls_sock.cipher()       # (name, protocol, bits)
        protocol = tls_sock.version() or ""

        tls_sock.close()
        raw_sock.close()

        result.protocol = protocol
        result.cipher = cipher_info[0] if cipher_info else ""

        # --- Certificate subject / issuer ---
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer_raw = dict(x[0] for x in cert.get("issuer", []))
        result.cert_subject = subj.get("commonName", "")
        result.cert_issuer = issuer_raw.get("organizationName", issuer_raw.get("commonName", ""))

        # --- Expiry check ---
        expiry_str = cert.get("notAfter", "")
        if expiry_str:
            result.cert_expiry = expiry_str
            try:
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days = (expiry_dt - now).days
                result.days_until_expiry = days
                if days < 0:
                    result.findings.append(SslFinding(
                        name="Certificate Expired",
                        status="fail",
                        detail=f"Certificate expired {abs(days)} day{'s' if abs(days) != 1 else ''} ago ({expiry_str}).",
                        recommendation="Renew the SSL certificate immediately. Expired certificates cause browser warnings and destroy client trust.",
                        risk="critical",
                    ))
                elif days < 14:
                    result.findings.append(SslFinding(
                        name="Certificate Expiring Soon",
                        status="fail",
                        detail=f"Certificate expires in {days} days ({expiry_str}). Renewal is urgent.",
                        recommendation="Renew the SSL certificate now. Let's Encrypt certificates can be auto-renewed via certbot.",
                        risk="high",
                    ))
                elif days < 30:
                    result.findings.append(SslFinding(
                        name="Certificate Expiring Soon",
                        status="warn",
                        detail=f"Certificate expires in {days} days ({expiry_str}).",
                        recommendation="Plan certificate renewal in the next two weeks to avoid service disruption.",
                        risk="medium",
                    ))
                else:
                    result.findings.append(SslFinding(
                        name="Certificate Validity",
                        status="pass",
                        detail=f"Certificate valid for {days} more days (expires {expiry_str}).",
                        risk="info",
                    ))
            except Exception:
                pass

        # --- Self-signed check ---
        org = issuer_raw.get("organizationName", "")
        cn_issuer = issuer_raw.get("commonName", "")
        is_self_signed = (subj.get("commonName") == cn_issuer) or org == ""
        if is_self_signed and result.cert_issuer:
            result.findings.append(SslFinding(
                name="Self-Signed Certificate",
                status="warn",
                detail=f"Certificate is self-signed (issuer: {result.cert_issuer}). Browsers will show a security warning.",
                recommendation="Replace with a certificate from a trusted CA (Let's Encrypt is free). Self-signed certs erode client trust.",
                risk="medium",
            ))

        # --- Protocol version check ---
        weak_protocols = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
        if protocol in weak_protocols:
            result.findings.append(SslFinding(
                name="Weak TLS Protocol",
                status="fail",
                detail=f"Server negotiated {protocol} — this protocol version is deprecated and vulnerable to POODLE/BEAST attacks.",
                recommendation="Disable TLS 1.0 and TLS 1.1 on the web server. Require TLS 1.2 minimum, preferably TLS 1.3.",
                risk="high",
            ))
        elif protocol in ("TLSv1.2", "TLSv1.3"):
            result.findings.append(SslFinding(
                name="TLS Protocol Version",
                status="pass",
                detail=f"Server is using {protocol}.",
                risk="info",
            ))

        # --- Cipher strength ---
        cipher_name = cipher_info[0] if cipher_info else ""
        key_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0
        weak_ciphers = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}
        if any(w in cipher_name.upper() for w in weak_ciphers):
            result.findings.append(SslFinding(
                name="Weak Cipher Suite",
                status="fail",
                detail=f"Weak cipher negotiated: {cipher_name} ({key_bits} bits).",
                recommendation="Disable RC4, DES, 3DES, and NULL ciphers. Configure the server to prefer ECDHE+AES-256 cipher suites.",
                risk="high",
            ))
        elif key_bits and key_bits < 128:
            result.findings.append(SslFinding(
                name="Short Cipher Key",
                status="warn",
                detail=f"Cipher key length is {key_bits} bits ({cipher_name}). Recommended minimum is 128 bits.",
                recommendation="Configure stronger cipher suites with at least 128-bit key length.",
                risk="medium",
            ))

    except ssl.SSLCertVerificationError as e:
        result.error = f"Certificate validation failed: {e}"
        result.findings.append(SslFinding(
            name="Certificate Validation Error",
            status="fail",
            detail=f"SSL certificate could not be validated: {e}",
            recommendation="Check that the certificate is valid, not expired, and matches the hostname. Replace self-signed certs.",
            risk="high",
        ))
    except ssl.SSLError as e:
        result.error = f"SSL error: {e}"
    except (socket.timeout, TimeoutError):
        result.error = f"Connection timed out ({host}:{port})"
    except ConnectionRefusedError:
        result.error = f"Connection refused on port {port}"
    except Exception as e:
        result.error = f"Could not check SSL: {e}"

    return result


def check_ssl_for_hosts(hosts_with_ports: list[tuple[str, int]]) -> dict[str, SslResult]:
    """Check SSL for a list of (hostname_or_ip, port) tuples."""
    results: dict[str, SslResult] = {}
    for host, port in hosts_with_ports:
        key = f"{host}:{port}"
        results[key] = check_ssl(host, port)
    return results
