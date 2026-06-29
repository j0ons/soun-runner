"""Email a finished job's reports off the scanned machine to Soun Al Hosn.

This is how an engineer — already AnyDesk'd into a client machine — pulls the
generated reports back to the office in one click. The reports otherwise just
sit in the local ``reports/`` folder; this attaches them to an email and sends
them to the Soun inbox.

Stdlib only (``smtplib`` + ``email``) — no extra dependency. Configure via
environment variables (set them in START-WINDOWS.bat / START-MAC.command):

    SOUN_SMTP_HOST       e.g. smtp.gmail.com            (required)
    SOUN_SMTP_PORT       587 (STARTTLS) or 465 (SSL)    default 587
    SOUN_SMTP_USER       the sending mailbox / login     (required)
    SOUN_SMTP_PASSWORD   app password for that mailbox   (required)
    SOUN_SMTP_FROM       From address    default = SOUN_SMTP_USER
    SOUN_REPORT_TO       recipient       default Mohamed@sounalhosn.ae

If the SMTP settings are missing, send() returns a clear, actionable error
instead of raising — the UI shows it and the engineer can still download the
PDFs manually.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

# Default destination — the Soun inbox these reports should land in.
DEFAULT_TO = "Mohamed@sounalhosn.ae"


@dataclass
class SmtpConfig:
    host: str
    port: int
    user: str
    password: str
    sender: str
    recipient: str
    use_ssl: bool  # True for port 465 (implicit SSL), else STARTTLS


def _load_config() -> "tuple[SmtpConfig | None, str]":
    """Read SMTP settings from the environment. Returns (config, error)."""
    host = os.environ.get("SOUN_SMTP_HOST", "").strip()
    user = os.environ.get("SOUN_SMTP_USER", "").strip()
    password = os.environ.get("SOUN_SMTP_PASSWORD", "")

    missing = [
        name for name, val in (
            ("SOUN_SMTP_HOST", host),
            ("SOUN_SMTP_USER", user),
            ("SOUN_SMTP_PASSWORD", password),
        ) if not val
    ]
    if missing:
        return None, (
            "Email is not configured on this machine. Set these environment "
            "variable(s) before launching SounRunner: " + ", ".join(missing) +
            ". (Edit START-WINDOWS.bat / START-MAC.command.)"
        )

    try:
        port = int(os.environ.get("SOUN_SMTP_PORT", "587"))
    except ValueError:
        port = 587

    sender = os.environ.get("SOUN_SMTP_FROM", "").strip() or user
    recipient = os.environ.get("SOUN_REPORT_TO", "").strip() or DEFAULT_TO

    return SmtpConfig(
        host=host, port=port, user=user, password=password,
        sender=sender, recipient=recipient, use_ssl=(port == 465),
    ), ""


def is_configured() -> bool:
    """True when the SMTP settings needed to send are all present. Lets the
    auto-send stay silent on machines that haven't set email up."""
    config, _ = _load_config()
    return config is not None


def _attach(msg: EmailMessage, path: Path) -> bool:
    """Attach a file to the message. Returns True if it existed and was added."""
    if not path.exists() or not path.is_file():
        return False
    data = path.read_bytes()
    if path.suffix.lower() == ".pdf":
        maintype, subtype = "application", "pdf"
    elif path.suffix.lower() in (".html", ".htm"):
        maintype, subtype = "text", "html"
    else:
        maintype, subtype = "application", "octet-stream"
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=path.name)
    return True


def _section(title: str, rows: "list") -> "list[str]":
    """Render one labelled section. rows may be (label, value) pairs or plain
    strings. Empty values are dropped; an empty section returns nothing."""
    lines: list[str] = []
    for row in rows or []:
        if isinstance(row, (tuple, list)):
            lbl, val = row[0], row[1]
            # Drop only genuinely absent fields (None / empty string). A numeric
            # 0 is meaningful here ("Critical: 0", "Open services: 0") — keep it.
            if val is None or (isinstance(val, str) and not val.strip()):
                continue
            lines.append(f"  {lbl + ':':<16} {val}")
        elif row:
            lines.append(f"  • {row}")
    if not lines:
        return []
    return ["", title, "-" * len(title), *lines]


def _build_body(client, label, target, details, present) -> str:
    """Assemble the full plain-text email body from the context dict."""
    head = [
        "SOUN AL HOSN CYBERSECURITY — Soun Runner",
        "=" * 44,
        "",
        f"{label} report for: {client}",
    ]
    if details.get("company"):
        head.append(f"Company:        {details['company']}")
    if details.get("domain"):
        head.append(f"Domain:         {details['domain']}")
    head.append(f"Scope / target: {target or 'N/A'}")
    if details.get("generated_at"):
        head.append(f"Generated:      {details['generated_at']}")
    if details.get("operator"):
        head.append(f"Operator:       {details['operator']}")

    body: list[str] = list(head)
    body += _section("ENGAGEMENT", details.get("engagement"))
    body += _section("SCAN RUN & MACHINE", details.get("run"))
    body += _section("NETWORK CONTEXT", details.get("network"))
    body += _section("FINDINGS", details.get("findings"))
    body += _section("DISCOVERED HOSTS", details.get("hosts"))

    body += ["", "ATTACHED REPORTS", "-" * 16]
    body += [f"  • {lbl}: {p.name}" for lbl, p in present]

    job_id = details.get("job_id")
    body += [
        "",
        "—",
        "Sent automatically by Soun Runner" + (f" (job {job_id})." if job_id else "."),
        "Soun Al Hosn Cybersecurity LLC · Dubai, UAE · info@sounalhosn.ae · +971 52 203 4204",
    ]
    return "\n".join(body)


def send_reports(
    *,
    client_name: str,
    target: str,
    mode: str,
    attachments: "list[tuple[str, Path]]",
    details: "dict | None" = None,
) -> dict:
    """Email the given report files to the Soun inbox.

    attachments: list of (label, Path). Missing files are skipped silently; the
    returned ``attached`` list reflects what was actually sent.

    details: a context dict the route assembles from the job / report data.
    Any section whose values are empty is simply omitted, so the same builder
    works for a rich advanced assessment and a lean free scan. Recognised keys:
        company, domain, profile, mode_label, generated_at, operator, job_id
        engagement: list[(label, value)]   — company / engagement facts
        run:        list[(label, value)]    — the scan run + the machine it ran on
        network:    list[(label, value)]    — client public IP / ISP / ASN / location
        findings:   list[(label, value)]    — severity breakdown + risk score
        hosts:      list[str]               — one line per discovered host

    Returns {"ok": bool, "message": str, "attached": [filenames]}.
    """
    config, err = _load_config()
    if config is None:
        return {"ok": False, "message": err, "attached": []}

    details = details or {}
    client = client_name or "Unnamed client"
    label = details.get("mode_label") or ("Free scan" if mode == "free" else "Assessment")

    msg = EmailMessage()
    msg["Subject"] = f"Soun Runner — {label} report: {client}"
    msg["From"] = config.sender
    msg["To"] = config.recipient
    msg["Date"] = formatdate(localtime=True)

    # Resolve which files actually exist before building the message, so we can
    # bail early with a clear error and list them in the body.
    present = [(lbl, p) for lbl, p in attachments if p.exists() and p.is_file()]
    if not present:
        return {
            "ok": False,
            "message": "No report files were found to attach. Generate the "
                       "report first, then try again.",
            "attached": [],
        }

    body = _build_body(client, label, target, details, present)

    # set_content() must run BEFORE add_attachment() — the first attachment turns
    # the message multipart, after which set_content() is no longer valid.
    msg.set_content(body)

    attached: list[str] = []
    for _label, path in present:
        if _attach(msg, path):
            attached.append(path.name)

    try:
        if config.use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(config.host, config.port, timeout=30, context=ctx) as srv:
                srv.login(config.user, config.password)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(config.host, config.port, timeout=30) as srv:
                srv.ehlo()
                srv.starttls(context=ssl.create_default_context())
                srv.ehlo()
                srv.login(config.user, config.password)
                srv.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        return {
            "ok": False,
            "message": "SMTP login was rejected. Check SOUN_SMTP_USER / "
                       "SOUN_SMTP_PASSWORD (Gmail needs an App Password, not "
                       "your normal password).",
            "attached": [],
        }
    except (OSError, smtplib.SMTPException) as exc:
        return {"ok": False, "message": f"Could not send email: {exc}", "attached": []}

    return {
        "ok": True,
        "message": f"Emailed {len(attached)} file(s) to {config.recipient}.",
        "attached": attached,
    }
