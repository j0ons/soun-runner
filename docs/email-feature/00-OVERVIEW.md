# Email-to-Soun — Feature Overview

> Session build record. Written so the whole feature could be rebuilt from
> scratch from these docs alone.
>
> **Built:** 29–30 June 2026 · Soun Runner v2 · Soun Al Hosn Cybersecurity LLC

---

## The problem

Soun Runner runs **on or near a client's network** (the engineer is usually
AnyDesk'd into a Windows machine on the client site). It scans, then writes
report files into a local `reports/` folder:

```
reports/<id>.pdf              (advanced assessment)
reports/<id>_client.pdf       (free — plain-language client report)
reports/<id>_engineer.pdf     (free — technical engineer report)
```

Those reports just **sat on whatever machine ran the scan**. There was no clean,
professional way to pull them back to the office. The engineer had to manually
copy files over AnyDesk.

## What we built

A feature to **email the finished reports to `Mohamed@sounalhosn.ae`**, in two
modes:

| Mode | Trigger | Behaviour |
|------|---------|-----------|
| **Automatic** | Every completed scan | Sends the report PDF(s) the moment the scan finishes — no clicks. |
| **Manual** | "✉ Email to Soun" button on the results page | Re-sends on demand. |

The email is **rich**: company, domain, the scan run, **the machine it ran from**
(hostname + IP), client-side network context (public IP, ISP, ASN, location),
the findings severity breakdown, and the list of discovered hosts — plus the PDFs
attached.

## The hard requirement that shaped the design

> "I'm going to install this on a **client machine** and I **won't have access
> to my Mac**. The password must travel with the app."

This killed the obvious approaches:

- ❌ Env vars in the launcher → engineer would have to type the password on every
  client machine.
- ❌ A git-ignored `config.local` → never reaches the client machine via
  `git pull` / the `.exe`.

The accepted solution: **bake the SMTP credentials into the app, obfuscated**, so
they ship with every install and need zero setup on-site. (`config.local` and env
vars still override, for flexibility.)

## Files in this feature

| File | Role |
|------|------|
| `app/modules/emailer.py` | **New.** Builds + sends the email (stdlib `smtplib`/`email`). Holds the baked-in obfuscated SMTP defaults. |
| `app/routes.py` | `POST /email/<job_id>` route, `_send_job_email`, `_auto_email`, `_email_details`, `_job_attachments`. Auto-email calls wired into the scan pipelines. |
| `app/__init__.py` | `load_local_config()` — loads `config.local` into the env on startup. |
| `app/templates/progress.html` | The "✉ Email to Soun" button + JS handler. |
| `config.local.example` | Committed template for the optional per-machine override file. |
| `.gitignore` | Ignores the real `config.local`. |
| `START-MAC.command` / `START-WINDOWS.bat` | Point at `config.local` (no creds in them anymore). |
| `README.md` | "Email the reports to Soun" user section. |

## Doc map

- [`01-ARCHITECTURE.md`](01-ARCHITECTURE.md) — how the pieces fit, data flow, the email body shape.
- [`02-CREDENTIALS-AND-SECURITY.md`](02-CREDENTIALS-AND-SECURITY.md) — the obfuscation scheme, the trade-off, **how to rotate the password**.
- [`03-BUILD-LOG.md`](03-BUILD-LOG.md) — chronological build record + every decision the user made.
- [`04-TESTING.md`](04-TESTING.md) — every test run and its result (incl. live sends).
- [`05-FUTURE-IDEAS.md`](05-FUTURE-IDEAS.md) — reviewed improvement ideas, ranked.
