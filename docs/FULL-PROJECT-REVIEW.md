# Soun Runner — Full Project Review (30 June 2026)

A whole-codebase review (scan engine + all 15 modules + routes + templates +
report output). Distinct from `docs/email-feature/` which covered only the email
feature. This is the prioritized backlog for the rest of the product.

> **Status key:** ✅ fixed this session · 🔲 backlog (user-approved direction) ·
> ⏸ noted, not scheduled

---

## A. Credibility bugs — make the tool look wrong to a paying client

These were the priority. All the low-risk ones are **fixed**.

| # | Bug | Where | Status |
|---|-----|-------|--------|
| A1 | **False "default credentials accepted" CRITICAL findings.** `requires_auth=needs_auth or True` defeated the gate; and a 404/500 response counted as "creds accepted." | `credtest.py:130`, `:69` | ✅ fixed — removed `or True`; only HTTP 200 counts as accepted (verified with unit test: 404/500/401 → not accepted). |
| A2 | **Runtime crash on the web-panel 401 path** — `urllib.error.HTTPError` used but `urllib.error` not imported. | `webscan.py:121` | ✅ fixed — added `import urllib.error`. |
| A3 | **`TRN: sounalhosn.ae`** — a UAE Tax Registration Number field filled with a domain name. | `report.html:1451` | ✅ fixed — replaced with the company contact line. |
| A4 | **Fragile copyright-year parse** `generated_at.split(',')[0].split(' ')[-1]` — breaks silently if the date format changes. | `report.html:1451`, `free_report.html:231` | ✅ fixed — removed the fragile parse from both. |
| A5 | **Bogus CVE lists** — NVD lookup is keyword-search, not version/CPE-matched, so it attaches CVEs that may not apply, under the header "Known CVEs." | `vuln_lookup.py`, `report.html:1071` | ✅ partial — header reworded to "Potential CVEs … confirm against the exact running version." Proper CPE matching is **B-tier** below. |
| A6 | **All internal HTTPS skipped for TLS checks** — `check_ssl` returns early for any IP target, so on an IP-addressed LAN (the primary use case) no TLS analysis happens. Sets an honest error (doesn't lie), so it's a *coverage gap* not a false statement → deferred. | `ssl_check.py:55` | 🔲 backlog (stronger scanning) |

---

## B. Stronger scanning (user wants this)

| # | Idea | Where | Notes |
|---|------|-------|-------|
| B1 | **Add MS17-010 / EternalBlue** + `smb-vuln-*` to the safe NSE set. The single highest-value LAN check, currently absent. | `deepprobe.py` | 🔲 |
| B2 | **Real CVE matching** — switch NVD lookup to CPE 2.3 + version-range, add `NVD_API_KEY` support, disk cache, and CISA **KEV** cross-reference to prioritize actually-exploited CVEs. | `vuln_lookup.py` | 🔲 (fixes A5 properly) |
| B3 | **SSL on IPs** — use an *unverified* context to always fetch the cert (so self-signed/expired certs are actually analyzed, not skipped), then evaluate trust separately; check SAN/hostname mismatch, <2048-bit RSA, SHA-1 sigs. | `ssl_check.py:55,60` | 🔲 (fixes A6) |
| B4 | **Linux fix scripts** — `fixgen` only emits Windows PowerShell even for Linux hosts, though `fixrun` already supports SSH/bash. Add iptables/nft/ufw, `systemctl disable`, sshd hardening. | `fixgen.py` | 🔲 |
| B5 | **Device classification** — fix `and/or` precedence bugs (`scanner.py:178,188`); iDRAC/iLO/BMC mislabeled "Windows Server"; request `-O` when privileged; add UDP top-ports (SNMP/DNS/IKE invisible today). | `scanner.py` | 🔲 |
| B6 | **DNS depth** — SPF >10-lookup permerror, DMARC `pct`/`sp`/`rua`, DNSSEC, AXFR zone-transfer, dangling-CNAME (subdomain takeover). | `dns_check.py` | 🔲 |
| B7 | **MSSQL/MySQL finding is unconditional** — reachability ≠ misconfig; gate it. SNMP finding should escalate to critical when sysDescr actually returns. | `deepprobe.py:227,265` | 🔲 |
| B8 | **Segmentation honesty** — the "VLAN isolation" matrix only tests from the operator's box; reframe the report wording or test host-to-host properly. `default,safe` never runs vuln scripts despite the "VULNERABLE" grep. | `validation_agent.py:114,166` | 🔲 |
| B9 | **netinfo /24 assumption** — read the real subnet mask; mis-scopes /23, /22, /16 networks. | `netinfo.py:146,203` | 🔲 |

---

## C. Premium report output (user wants this)

| # | Idea | Where | Notes |
|---|------|-------|-------|
| C1 | **Page numbers + per-page confidential footer** (Playwright `display_header_footer` + templates — currently disabled). | `pdf.py:153` | 🔲 |
| C2 | **True cover page** (page break), **table of contents**, **methodology / scope / engagement-dates / authorization** front matter. | `report.html` | 🔲 |
| C3 | **Finding IDs (F-001…) + CVSS vectors + evidence field + affected-hosts rollup** on the `Finding` dataclass — makes the report referenceable/audit-grade. | `report_builder.py:34` | 🔲 |
| C4 | **Port-list truncation** — host port lists silently cut to 18 (`report_builder.py:409`) and report table truncates too. Add a full-list appendix. | `report_builder.py:409`, `report.html` | 🔲 |
| C5 | **Exec/technical split** + effort-vs-impact "quick wins" matrix in the runbook; client-logo letterhead slot. | `report.html` | 🔲 |
| C6 | **CSV/JSON export** of findings for the client's ticketing system. | new | 🔲 |

---

## D. History, trends & client delivery (user wants this)

| # | Idea | Where | Notes |
|---|------|-------|-------|
| D1 | **Persist jobs in SQLite** — `_jobs` is an in-memory dict (`routes.py:30`); reports vanish after restart/wipe, no history. Unlocks D2/D3/D4. | `routes.py:30` | 🔲 (foundational) |
| D2 | **Per-client history + risk-score trend** across re-scans (re-scan diff machinery already exists). | depends on D1 | 🔲 |
| D3 | **Email the report to the CLIENT** (recipient field) and/or a tokenized read-only **client-portal** link per job. | `routes.py:915` | 🔲 |
| D4 | **Scheduled / recurring re-scans** (monthly proof-of-fix) with auto-email — `rescan_of` + `diff_scans` exist; needs a scheduler + D1. | new | 🔲 |

---

## E. Robustness / correctness (lower urgency)

| # | Issue | Where |
|---|-------|-------|
| E1 | `_jobs` grows unbounded (memory leak over a long session) — add TTL/eviction. | `routes.py:30` |
| E2 | No lock around shared `report_data.findings` mutation + same-file `{id}.html/.pdf` writes — checklist rebuild vs severity-override can race under the threaded server. | `routes.py:191,583` |
| E3 | `_rerender_advanced_report` swallows narrative-refresh errors silently then reports success → possible stale compliance/runbook. | `routes.py:206` |
| E4 | `_run_free_job` two-variant loop overwrites `pdf_error` inconsistently. | `routes.py:505` |
| E5 | Workspace opened mid-scan renders a blank page (no `status=='done'` guard). | `routes.py:110` |
| E6 | `fixrun` forces WinRM `ntlm` (domain Kerberos fails), accepts any SSH host key (TOFU MITM risk on the assessed network), doesn't scrub `key_text`. | `fixrun.py:201,147,45` |
| E7 | `engineer_modules` rates `pentest_authorized=no` as merely "info" — unauthorized active testing should be a hard governance flag. | `engineer_modules.py:100` |
| E8 | `fixgen.py:17` mojibake in source; Telnet rollback uses `TelnetClient` not `TelnetServer`. | `fixgen.py` |

---

## What was fixed this session (commit-ready)

- A1, A2, A3, A4, A5(partial) — see table A.
- Verified: `credtest` unit test (200→accepted; 404/500/401→rejected); all files compile.

## Recommended next batch (when you greenlight)

1. **B2 + B3 + A6** together (CVE matching + SSL coverage) — biggest scan-quality lift.
2. **C1 + C2** (page numbers + cover/TOC/methodology) — biggest "looks premium" lift, low risk.
3. **D1** (SQLite) — unlocks all of D. Foundational; do before D2-D4.
