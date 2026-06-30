# Soun Runner — Differentiation Strategy (new-to-market features)

> Output of a multi-agent analysis (30 June 2026): ground the tool's unique
> traits → map incumbents (Nessus/Qualys/Intruder/Pentera/RapidFire) + the
> GCC/NESA market → ideate from 5 strategic lenses → kill weak/derivative/
> infeasible ideas with 3 adversarial critics → synthesize. Only ideas that
> survived all three critics are below.
>
> Distinct from `FULL-PROJECT-REVIEW.md` (bug/quality backlog). This doc is about
> features **no competitor can structurally copy.**

---

## The thesis

Soun Runner should be **the disposable, bilingual, engineer-carried
assessment-and-remediation appliance that lives inside a GCC SME's LAN for
exactly one visit — and provably leaves nothing behind.**

Its uncopyable surface is everything that requires *being on-site, in Arabic,
hands on a console, with standing consent*:

- It sees the client's **real internal furniture** (`RECEPTION-PC`), not a NAT'd IP.
- It can **scan → price → fix-with-rollback → re-verify in one session.**
- It speaks to the **cheque-signer in correct Arabic about his own machines.**
- It **self-wipes with proof.**

A cloud scanner is architecturally locked out of all four: it observes from
outside, retains data offshore, can't execute a fix, and has no human in the
room. **The product is not the scan — it's on-site presence + Arabic + verified
disposability, sold as a flat-fee cash engagement, not a subscription.**

---

## The features that survived (ranked by build-ease × impact)

### 1. Fix-It-Now Live Remediation Quote — *Build: S · Claude: optional*
Scan completes → an itemized, **auto-priced** remediation quote appears on screen
during the visit ("12 fixable items, 9 we can apply now with rollback — sign
here") → one tap goes quote → live execution → re-scan proof.
- **Uncopyable because:** a SaaS scanner has no execution foothold — it can't run
  the fix, price the labour, or prove it landed in the same session.
- **Commercial:** closes in the room at peak fear; turns a "scan fee" into "scan +
  remediation." Highest deal-value lift in the set. Builds on existing
  `fixgen`/`fixrun`.

### 2. Arabic Attacker-Walkthrough ("ماذا بعد؟") — *Build: S–M · Claude: yes*
Feed real findings + actual internal hostnames to Claude → narrate one concrete
kill-chain in plain Arabic: "An attacker reaches RECEPTION-PC via exposed RDP,
pivots over open SMB to ACCOUNTS-SRV, reaches your customer database — today, in
your office." Grounded by the existing curated Arabic phrase buckets so it stays
accurate.
- **Uncopyable because:** incumbents see a NAT'd public IP, never the internal
  furniture, and are English-only.
- **Commercial:** the line that converts a free scan into a signed cheque.

### 3. 10-Minute Boardroom Scan (live-fire demo) — *Build: S–M · Claude: optional*
A presentation mode: fast scan live on the meeting-room screen, findings render
as they land, ending in a real-time bilingual verdict — the owner watches his own
`RECEPTION-PC` go red.
- **Uncopyable because:** async cloud scanners route telemetry offsite over
  hours; no "watch your own furniture get owned in the room" moment.
- **Commercial:** compresses the sales cycle to a single visit.

### 4. Ballighni — WhatsApp Owner Briefing — *Build: S · Claude: optional*
At handover, generate a 3-bubble Arabic owner verdict ("فحصنا ٧ أجهزة، وجدنا ٣
مخاطر مرتفعة", correct numeral agreement) + a one-tap `wa.me` "fix it today" link,
on the channel GCC SMEs actually use.
- **Uncopyable because:** WhatsApp-first owner delivery is culturally native to
  the GCC and alien to US/EU vendors whose whole UX is a dashboard + email.
- **Commercial:** fuses lead-gen and handover on the region's highest-open-rate
  channel; near-zero build. *(Ship the `wa.me` deep-link only — the WhatsApp
  Cloud API is a backend and breaks the no-cloud constraint.)*

### 5. ⭐ Sovereign / Zero-Footprint Mode + signed disposal receipt — *Build: S · Claude: no* — **FLAGSHIP**
A pre-engagement toggle that gates off all outbound calls, holds data in-process
+ on the client's own Desktop, and runs `/wipe` **in front of the client** —
printing a signed "nothing left this building" receipt listing every artifact
exported and deleted.
- **Uncopyable because:** the SaaS business model *is* retaining client telemetry
  in a foreign cloud — they're structurally forbidden from truthfully issuing
  "your data never left and is now destroyed."
- **Commercial:** neutralises the #1 SME objection (data distrust) under PDPL/NCA
  residency anxiety; unlocks the high-trust cohort (clinics, law firms, family
  offices, government suppliers, OT/air-gapped sites) that cloud players can't
  reach at all.
- **⚠️ Prerequisite (honesty):** the air-gap claim is **currently false** —
  `netinfo.py`/`topology.py` call `ip-api.com` and `vuln_lookup.py` calls NIST
  NVD. This mode must actually kill those calls (accept degraded enrichment) or
  the code disproves the pitch.

### 6. The Certificate (bilingual NESA-mapped proof-of-fix) — *Build: S–M · Claude: optional*
One signed-artifact primitive: a bilingual (Arabic-primary, RTL) before/after
proof-of-fix tied to the existing `diff_scans`, mapped to **official Arabic NESA
control text** (not just IDs), issued by the named on-site engineer with a
tamper-evident hash. Serves as the tender/auditor "we got assessed" artifact and
the insurer-grade proof-of-remediation.
- **Uncopyable because:** no execution foothold to prove a fix on this host;
  English-only; incumbents map to ISO/PCI IDs, never canonical Arabic NESA
  wording an Emirati auditor reads verbatim.
- **Commercial:** sells the *outcome* not the scan — clears a tender checkbox /
  lowers a premium, and manufactures a second annual "re-seal" visit.
- **Build note:** SHA-256 is stdlib; *real* signatures need a crypto lib
  (`cryptography`/`pynacl`) added — not currently bundled.

### 7. Drift Report — cross-visit same-client diff — *Build: S–M · Claude: optional*
On visit #2/#3, load last year's exported report (a file the engineer carries)
and lead with "since June 2025: 2 fixed, 1 regressed (SMB re-opened on
FINANCE-PC), 3 new devices — including an unmanaged TP-Link someone plugged in."
Rogue-device detection falls out of MAC-set differencing.
- **Uncopyable because:** SaaS does drift via a resident agent + cloud retention;
  Soun does it agentless from two carried local files — the residency-safe
  version of continuous monitoring.
- **Commercial:** manufactures the annual re-visit **without a subscription** —
  recurring revenue that doesn't break the "nothing left behind" brand.

---

## Honest reality check (so we don't oversell)

- **Genuinely novel / no shipping equivalent:** the Arabic attacker-walkthrough
  naming the client's *own internal hosts*; the WhatsApp Arabic owner briefing as
  a security deliverable; official Arabic NESA control-text in the certificate.
  These rest on the Arabic-curation + layer-2 LAN visibility combo nobody else has.
- **Novel as a combination, not as primitives:** Sovereign Mode (disposable
  scanners and signed receipts both exist; a *positioned* "scanner that provably
  self-destructs on a client box" does not). Fix-It-Now (enterprise BAS does
  scan→fix→verify at $100k+; nothing does it at the SME tier, in-room, auto-priced).
  The moat is **packaging + market**, not a new algorithm.
- **Merely rare — pitch on *how*, not as inventions:** Drift Report (everyone
  does year-over-year diffing; the new bit is agentless). The Certificate
  (crowded in the West — Picus, HITRUST, Travelers; the Arabic + NESA-first +
  on-site-execution angle is the differentiator).
- **Cut as fantasy/contradiction:** anything cohort/benchmark-based
  (neighbourhood baseline, industry posture score) has an un-winnable cold-start
  for a single-operator shop — don't promise it to early clients. Leave-behind
  re-scan stubs were correctly killed — they break the brand.
- **Two infra truths to state plainly:** (1) the build is **not air-gapped
  today** — three modules phone out; Sovereign Mode must gate them. (2) **No
  crypto library is bundled**, so true signatures need a new dependency, and any
  license/white-label gate is honour-system without a backend.

---

## Recommended sequencing

1. **Sovereign Mode kill-switch** (flagship; also a real correctness fix — the
   air-gap claim must be true). Small build.
2. **Fix-It-Now quote** + **Arabic attacker-walkthrough** — the two biggest
   deal-closers, both build on existing `fixgen`/`fixrun` + `arabic.py`.
3. **WhatsApp briefing** — near-zero build, high cultural fit.
4. **The Certificate** + **Drift Report** — the recurring-revenue engine, once
   persistence (SQLite, from the other backlog) lands.
