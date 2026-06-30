# Architecture & Data Flow

## End-to-end flow

```
Engineer runs a scan (free or advanced) on the client machine
        │
        ▼
Scan pipeline finishes  (_run_job  /  _run_free_job  in app/routes.py)
   • writes report HTML + PDF into reports/
   • calls _auto_email(job, log)        ◄── automatic send
        │
        ▼
_auto_email  → is_configured()? ── no ──► silently skip (logs nothing)
        │ yes
        ▼
_send_job_email(job)
   • _job_attachments(job)   → [(label, Path), …]  PDF-first, HTML fallback
   • _email_details(job)     → rich context dict
   • emailer.send_reports(…)
        │
        ▼
emailer.send_reports
   • _load_config()          → SmtpConfig  (env / config.local / baked-in)
   • _build_body(…)          → plain-text body with all sections
   • attaches the PDF(s)
   • SMTP_SSL (465) or STARTTLS (587) → login → send_message
        │
        ▼
Email lands in Mohamed@sounalhosn.ae  (From: reports@sounalhosn.ae)
```

The **manual** path (`POST /email/<job_id>` ← the "✉ Email to Soun" button) joins
at `_send_job_email`, so manual and automatic share identical logic.

## Why a shared `_send_job_email`

Both the button route and the auto-send need the exact same three steps (gather
attachments, build context, call `send_reports`). Factoring it out means the
email body and attachment logic can never drift between the two paths.

## Config precedence (per field)

```
environment variable  >  config.local  >  baked-in obfuscated default
```

- `config.local` is loaded into `os.environ` at startup by
  `app/__init__.py::load_local_config()` — but only for keys **not already set**,
  so a launcher `export`/`set` still wins.
- `emailer._load_config()` then reads `os.environ`, falling back to the baked-in
  `_DEFAULTS` blob per field.

Net effect: **works out-of-the-box anywhere** (baked-in), **overridable** on any
machine that wants different creds (config.local / env).

## Attachment selection (`_job_attachments`)

```
free  job → Client report (pdf→html), Engineer report (pdf→html)
other job → Assessment report (pdf→html)
```

PDF-first; if PDF generation was skipped (e.g. WeasyPrint/Playwright missing on a
locked-down client box) it falls back to the HTML so a report still goes out, and
labels it "(HTML — PDF unavailable)".

## The email body (`_build_body` + `_section`)

Plain text, assembled from a `details` dict. Sections render only if they have
content (empty fields drop out), so the **same builder serves a rich advanced
assessment and a lean free scan**.

```
SOUN AL HOSN CYBERSECURITY — Soun Runner
============================================

<label> report for: <client>
Company / Domain / Scope / Generated / Operator

ENGAGEMENT            client, company, domain, scan type
SCAN RUN & MACHINE    target, profile, generated, operator,
                      Run-from host + IP (the machine it ran on),
                      hosts discovered, open services
NETWORK CONTEXT       public IP, ISP, organisation, ASN, gateway, location
FINDINGS              risk score, total, critical/high/medium/low
DISCOVERED HOSTS      one line per host (advanced only, capped at 40)
ATTACHED REPORTS      the file names

— footer with company contact line —
```

`_section()` rule: drop a row only if its value is `None` or an empty string. A
numeric `0` is **kept** ("Critical: 0" is meaningful).

## `_email_details(job)` — where the context comes from

- **Advanced** jobs carry a full `report_data` object → rich findings breakdown,
  host rows, generated time, operator, detected network context.
- **Free** jobs do **not** persist `report_data` → falls back to the job's own
  `stats` (hosts/ports/findings/critical) + a live `netinfo.detect()` for the
  machine/network context.

The "machine it ran from" (hostname + local IP) and live network context come
from `netinfo.detect()`, called at email time.

## Dependencies

**None added.** Uses only the Python standard library (`smtplib`, `email`,
`ssl`, `base64`). Deliberate — the app already runs on locked-down client
Windows machines, so adding a pip dependency was off the table.
