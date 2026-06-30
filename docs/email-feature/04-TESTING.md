# Testing Record

Every test run during the build and its result. Live sends actually delivered to
`Mohamed@sounalhosn.ae`.

## Unit / integration (offline)

| Test | Result |
|------|--------|
| `py_compile` of `emailer.py`, `routes.py`, `__init__.py` | ✅ pass each iteration |
| Unconfigured → friendly error (no crash) | ✅ returns `{ok: False, message: "Email is not configured…"}` (pre-baked-in version) |
| Route registered (`/email/<job_id>`, POST only) | ✅ |
| `_job_attachments` picks both free PDFs | ✅ `[(Client report, …_client.pdf), (Engineer report, …_engineer.pdf)]` |
| Multipart ordering bug | ✅ caught (`set_content not valid on multipart`), fixed, re-verified |
| `_section` keeps numeric 0 | ✅ "Critical: 0" now shows |
| Advanced body render (full report_data) | ✅ all sections present |
| Free body render (stats only) | ✅ degrades cleanly, live netinfo captured |

## SMTP transport (local capture server)

A throwaway in-process SMTP server captured exactly what was transmitted:

| Check | Result |
|-------|--------|
| RCPT = `Mohamed@sounalhosn.ae` | ✅ |
| Subject / From / To correct | ✅ |
| Both PDF attachments received | ✅ |
| Body contains FINDINGS / host line / company | ✅ |
| AUTH + STARTTLS path exercised | ✅ |

## Live sends (real delivery)

| # | Scenario | Result |
|---|----------|--------|
| 1 | Direct `send_reports` with cPanel creds via env | ✅ delivered — *"Assessment report: Soun Runner — Email Test"* |
| 2 | **Auto-email** via the real running app: HTTP-driven free scan against `127.0.0.1` | ✅ log showed `→ Report emailed to Soun (…client.pdf, …engineer.pdf)`; delivered |
| 3 | Send using **only `config.local`** (no env vars) | ✅ delivered — proves config.local auto-load |
| 4 | Send using **only baked-in defaults** (config.local moved aside, env cleared) = **fresh client machine simulation** | ✅ delivered — *"CLIENT MACHINE Test (baked-in creds)"* |

Screenshot confirmation from the user's inbox showed the rich body rendering
correctly (company, "Run from host: Mohs-MacBook-2553.local", "Run from IP",
public IP / ISP / ASN / Dubai location, findings) with both PDFs attached.

## How to re-run the client-machine simulation

```bash
cd ~/Desktop/soun-runner-v2
mv config.local /tmp/config.local.bak          # hide local override
python3 - <<'PY'
import os
for k in list(os.environ):
    if k.startswith("SOUN_"): os.environ.pop(k, None)   # clear env
from app import create_app; create_app()
import app.modules.emailer as em
from pathlib import Path
print(em.send_reports(client_name="Sim Client", target="127.0.0.1", mode="advanced",
    attachments=[("Assessment report", Path("reports/05d99a83.pdf"))],
    details={"company":"Sim","findings":[("Critical",0)]}))
PY
mv /tmp/config.local.bak config.local          # restore
```

Expect: `{'ok': True, 'message': 'Emailed 1 file(s) to Mohamed@sounalhosn.ae.', …}`
