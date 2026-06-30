# Future Ideas & Review Notes

Reviewed improvement ideas, ranked by value-for-effort. None are required — the
feature is complete and shipping. These are the "what next" backlog.

## ✅ Done in the final review pass

- Re-email the **updated** report after the field checklist folds in (was
  sending only the pre-checklist version).
- cPanel-accurate auth-error message (was Gmail App Password advice).
- Docstring corrected (creds are baked-in defaults, not "required").

## 🥇 High value, low effort

### 1. Send-status pill on the results page
The auto-email currently only logs a terminal line. Add a small badge —
"📧 Emailed to Soun ✓" / "✉ Email failed — retry" — next to the report buttons,
driven by a `job["email_status"]` field surfaced in `/status/<job_id>`. The
manual button already exists as the retry path; just surface the state.

### 2. CC the client / second recipient
`SOUN_REPORT_TO` is a single address. Allow a comma-separated list, and/or a
per-scan "also send the client report to: \_\_\_" field on the form. The **client**
PDF is already client-safe; this turns the tool into the delivery channel to the
customer too, not just the office.

### 3. Sales-deck attachment on the free scan
A free scan is a lead-gen tool. Auto-attach the
`SoundRunner-Sales-Presentation.pdf` to the **client** email so the prospect gets
the findings *and* the pitch in one message. Strong commercial lever.

## 🥈 Medium value

### 4. Don't double-send on re-scan
A re-scan creates a new job and will email again (correct), but if the same
report is rebuilt twice quickly (checklist + severity override), Soun gets
multiple emails. Add a short dedupe: skip auto-email if an identical
(job_id, findings-count) was sent in the last N seconds.

### 5. Retry / queue on transient failure
If the client site has flaky internet, a send can fail. Today it logs and stops.
Add 2–3 retries with backoff, and/or write a `reports/_outbox/<id>.json` the
launcher flushes next time it has connectivity. Pairs well with the existing
Finish-&-Wipe export.

### 6. HTML email body (not just plain text)
Current body is plain text (renders fine, see screenshot). A lightly-styled HTML
body — Soun logo, severity color chips matching the report — would look more
premium for a security firm. Keep the plain-text part as the fallback.

## 🥉 Nice to have

### 7. Wire email into Finish-&-Wipe
The `/wipe` self-destruct already exports reports to the Desktop. Optionally
email them first (belt-and-braces) before deleting the app from the client box.

### 8. Delivery receipt back to the operator
After send, show the message-id / timestamp in the UI so the engineer has proof
it left the building before they disconnect AnyDesk.

### 9. Per-client subject tagging
Subject is `Soun Runner — <label> report: <client>`. Add an optional
engagement/ticket code (`[ENG-1234]`) for easier inbox filtering/threading as
volume grows.

## 🔒 Security follow-ups (tracked in 02-CREDENTIALS-AND-SECURITY.md)

- Confirm `j0ons/soun-runner` is a **private** repo.
- Consider rotating the `reports@` password once (it passed through the build
  chat). Rotation is a 4-step, ~2-minute process — see the credentials doc.
- Longer term, if the threat model tightens: fetch the password from a URL you
  control at runtime instead of baking it in (the option the user declined for
  now in favour of simplicity).
