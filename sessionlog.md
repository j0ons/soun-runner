# Soun Runner v2 — Session Log

**Company:** Soun Al Hosn Cybersecurity LLC  
**Owner:** Mohamed Shanan (mohamed.shanan9@gmail.com)  
**Last updated:** 4 June 2026  

## DEPLOYMENT WRAP-UP (4 June 2026) — READY TO USE

Tool is feature-complete and ships with launchers + README. Ready for client use.

**Added:**
- `README.md` — full usage guide: operator usage (free vs advanced), AnyDesk client-host setup (one-time Python+Nmap install, then double-click launcher), the workspace, field checklist, where reports save, maintenance/troubleshooting, password change.
- `START-WINDOWS.bat` — one-click Windows launcher: checks Python, auto-installs pip packages, checks Nmap, launches + opens browser. Engineer just double-clicks.
- `START-MAC.command` — same for Mac (sets DYLD_LIBRARY_PATH for WeasyPrint). Tested working (HTTP 200).

**Deployment model (decided):** Everything happens via **AnyDesk**. Engineer remotes into a client machine on the client's network; client installs Python + Nmap once (5 min), then double-clicks START-WINDOWS.bat per scan. Fallback: run from engineer's own laptop on the client network.

**Final smoke test (4 Jun):** Landing 200, free form 200, advanced gated (302→200 after Tmppassword), wrong pw rejected. Free scan → both client+engineer reports + 2 PDFs (200). Mac launcher boots the server. All syntax OK.

**Still open (future):** fold workspace triage/manual-findings into the report render; optional PyInstaller .exe so client needs zero installs.

## FINAL QA PASS (3 June 2026) — pre-deployment

Bug review done. Fixed before deployment:
1. **Concurrency — shared temp XML** (HIGH): scans used fixed-name temp files; concurrent scans corrupted each other. Fixed: `run_scan_streaming(job_id=...)` → unique filenames; deepprobe/agent use `threading.get_ident()`.
2. **Re-scan snapshot aliasing** (HIGH): `findings_snapshot` aliased the live findings list; checklist rebuild mutated it and corrupted the re-scan diff baseline. Fixed: snapshot immutable `SimpleNamespace(host,port,title,risk)` copies.
3. **Stale exec summary after checklist rebuild** (MED): rebuild had a no-op `executive_summary` line. Fixed: recompute via `_executive_summary(cached)`.
4. **SMB guest-detection** (MINOR): redundant `"guest" in low` clause removed.

**PDF cleaned & verified:** cover was showing a "?" box (emoji) + risk-box overlapping the brand line. Fixed: logo → CSS "S" badge; print CSS stacks cover vertically; section-header emoji hidden in print; break-inside:avoid on cards. Verified visually — 30-page PDF, clean cover, correct data, professional. Production run: 36 findings, 683KB PDF, zero temp-file leftovers.

Status: **READY. Work starts tomorrow.** Next build item: Windows EXE (PyInstaller).


---

## Company Overview

Soun Al Hosn Cybersecurity LLC is a Dubai-based cybersecurity firm. Tagline: "We Secure, You Grow."  
Website: https://sounalhosn.ae  
Phone: +971 52 203 4204  
Email: info@sounalhosn.ae  

**Services offered (on paper):** Network Security, Endpoint Protection, Cloud Security, Data Recovery, Server Security, CCTV/physical security.  
**Tech vendor partners:** Fortinet, Palo Alto Networks, Cisco, Kaspersky, Sophos, Synology, CrowdStrike.  
**Mohamed's personal certs:** Cisco CCNA/CCNP/CyberOps.  

---

## The Real Business Situation (as of June 2026)

- The company has made **zero cybersecurity revenue** in its entire first year.
- All actual revenue came from **CCTV installs and small IT jobs** (Synology backup, networking, POS systems).
- Average deal size: **AED 3,000–10,000** per job.
- Mohamed tried upselling existing clients to managed services — **it did not work**.
- Team size: **Mohamed only + 1 remote helper** (cannot afford more).
- Two large open quotes still pending: **Skyview Arabia** (IT & network infra) and **Residency Visa Screening Center** (IT & network infra). Both 50/50 chance of closing.
- The company name "Cybersecurity LLC" does not reflect what the business actually does day-to-day.

**Actual projects completed (from !Projects folder):**  
CCTV: B22, Baba Ghanouj, Bin Tarish car wash, Galaxy Stones, Vertex Showroom, Salute.ae, Dr. Khaled, Mirdif Villa, JVT Villa, Abdulmajed Sharjah Villa, ADWA Building Materials, Hallat Al Khairat Snacks, Horse Farm al Ruwayyah, Rim Art, MTA Building Material, xPeditor (DAFZA), Wattan Ramadan, Al-Mazen Trading.  
Synology backup: MTA Building Material (invoiced/done), Cyberpalm Solutions, Gulf Express Logistics, Smart Selection.  
IT infra: AWR Al Dhaid, Residency Visa Screening Center, Skyview Arabia, Ostario Mario @ Circle Mall.  
Other: Ektifa POS, website hosting/domain renewal for Wattan Ramadan.  

---

## Restructure Strategy Agreed

### Phase 1 — Stabilize (already tried, did not work)
Attempted upselling existing clients to a monthly managed security package. Clients said no. This path is closed for now.

### Phase 2 — First Cybersecurity Wins (current focus)
Three parallel tracks:

**Track 1: Use Soun Runner as a free assessment tool**  
- Run a free network assessment for 2–3 willing SME contacts who have a real office network.
- Deliver the executive report.
- Sell remediation from the findings.
- This is the exact workflow the tool is built for: free scan → paid fix.

**Track 2: Close Skyview Arabia and Residency Visa Center**  
- Both are IT & network infra jobs — a natural bridge into cybersecurity.
- If either closes, propose an ongoing managed service on top of the installation.

**Track 3: Get Fortinet NSE 4 certification**  
- Cisco CCNA is good but Fortinet dominates the UAE SME firewall market.
- NSE 4 (FortiGate) takes 1–2 months self-study, opens doors to selling and configuring FortiGate firewalls.
- Most valuable cert investment right now.

### Phase 3 — Build the Pipeline (6–12 months)
- 5–10 SME clients on recurring managed services.
- 2–3 real cybersecurity contracts closed.
- Pitch: "We already protect your cameras and backup — let us protect your network too."
- Target: restaurants, retail chains, trading companies — same client types already in the portfolio.

### What NOT to do
- Do not build more software instead of selling.
- Do not chase government or enterprise contracts (too slow, requires connections).
- Do not rebrand or redesign the website (waste of time right now).
- Do not hire staff until recurring revenue is established.

**One number to track:** Monthly Recurring Revenue (MRR). Goal: AED 10,000/month to stabilize. AED 25,000/month to hire.

---

## Soun Runner v1 — Why It Failed

- Built over 18 phases, 190 tests, full enterprise architecture.
- **The core problem:** All Windows endpoint collection requires PowerShell running on the target machine with WinRM pre-enabled. At real SME client sites, WinRM is never pre-enabled. So the tool discovered hosts via Nmap but couldn't collect endpoint data from any of them — producing a "discovery-only" report with nothing meaningful in it.
- The report PDF looked broken (full of "skipped", "not configured", "discovery-only" labels) even though the tool was technically working.
- Over-engineered for a use case that doesn't exist yet (enterprise multi-host WinRM collection).
- Decision: **start clean with a focused, honest tool**.

---

## Soun Runner v2 — What Was Built

**Location:** `/Users/mohamedshanan/Desktop/soun-runner-v2/`  
**Repo (v1, for reference):** `git@github.com:j0ons/Sounrunner.git`

### What it does (real, no fake)
1. **Network discovery** — Nmap finds all live hosts and open ports on the target subnet.
2. **Service classification** — 27 dangerous port definitions (RDP, SMB, Telnet, FTP, databases, admin panels, etc.) each with risk level (critical/high/medium/low) and plain-English explanation.
3. **DNS/Email security** — SPF, DMARC, MX checks for the client's domain using live DNS queries.
4. **Report** — professional dark-themed HTML report + PDF. Client-facing, honest, includes CTA to hire Soun Al Hosn.

### What it does NOT do (by design, clearly stated in report)
- No authenticated endpoint access (no WinRM, no PowerShell remoting).
- No exploit or vulnerability confirmation.
- Report clearly says: "network-layer exposure assessment, not a full penetration test."

### Architecture
```
main.py                         ← entry point, opens browser at localhost:5757
app/
  __init__.py                   ← Flask app factory
  routes.py                     ← all routes, background job runner (threading)
  modules/
    scanner.py                  ← Nmap subprocess wrapper, XML parser, 27 port risk definitions
    dns_check.py                ← SPF / DMARC / MX via dnspython
    report_builder.py           ← assembles ScanResult + DnsResult into ReportData
  templates/
    index.html                  ← launch form (dark UI, scan profile pills)
    progress.html               ← live log via polling /status/<job_id>
    report.html                 ← full client report (dark theme, print-ready)
reports/                        ← generated HTML and PDF files saved here
requirements.txt
```

### Stack
- Python 3.13
- Flask 3.x (local web server)
- dnspython (DNS/email checks)
- WeasyPrint (PDF generation)
- python-nmap (nmap subprocess wrapper)
- Jinja2 (templating)

### Scan profiles
| Profile  | Ports        | Speed  | Use case             |
|----------|-------------|--------|----------------------|
| Quick    | Top 100      | ~1 min | Demo / quick look    |
| Standard | Top 500      | ~3 min | Default client scan  |
| Thorough | Top 1000     | ~8 min | Deeper assessment    |

### How to run (development / Mac testing)
```bash
brew install nmap          # one-time, Mac only
cd ~/Desktop/soun-runner-v2
pip3 install -r requirements.txt
python3 main.py
# Browser opens at http://127.0.0.1:5757
```

### How Mohamed's remote guy uses it at a client site
1. Remote into one Windows workstation at the client.
2. Run `python main.py` (or eventually `SounRunner.exe`).
3. Browser opens automatically.
4. Fill in: Client Name, Domain, Subnet.
5. Click Run — live log shows progress.
6. Download HTML + PDF when done.
7. Send PDF to client, sell remediation.

### Real findings discovered during this session
- `sounalhosn.ae` DMARC policy is `p=none` — only monitors, does not block spoofing. Should be upgraded to `p=quarantine` or `p=reject`. This is a real finding on your own domain.

---

## Home Lab (for testing)
- Proxmox server with multiple VMs: Ubuntu, Windows, CT containers.
- Connected to a full enterprise network.
- Use this to run live scans and validate report output before using on real clients.

---

## File Locations on Mac
| What | Path |
|------|------|
| Soun Runner v2 | `/Users/mohamedshanan/Desktop/soun-runner-v2/` |
| Soun Runner v1 (old) | `/Users/mohamedshanan/Library/CloudStorage/SynologyDrive-TwoWay/Soun Al-Hosn Cybersecurity LLC/Automation/soun-runner/` |
| Company files (Synology) | `/Users/mohamedshanan/Library/CloudStorage/SynologyDrive-TwoWay/Soun Al-Hosn Cybersecurity LLC/` |
| Client projects | `…/Soun Al-Hosn Cybersecurity LLC/!Projects/` |
| Business Plan 2025 | `…/Business Plan 2025/` |
| Business Plan 2026 / Feasibility | `…/Business Plan 2026/`, `…/Feasibility Study/` |
| Marketing / Digital Sales Kit | `…/Marketing/Soun_Al_Hosn_Digital_Sales_Kit_Aug2025/` |

**Note:** Synology NAS files often return "Stale NFS file handle" when the drive is not fully synced. Open the files locally in Finder first to force a cache sync, then they become readable.

---

## Soun Runner v3 Feature Upgrade — 2 June 2026

### New Modules Added
- **`ssl_check.py`** — stdlib-only SSL/TLS certificate analysis: expiry, self-signed detection, weak protocol (TLS 1.0/1.1), weak cipher suites
- **`vuln_lookup.py`** — NIST NVD API CVE lookup by product/version, CVSS scoring, in-memory cache, rate-limit compliant

### Upgraded Features
- **`scanner.py`** — Service dataclass now has `cves: list` field for CVE attach
- **`report_builder.py`** — Full rewrite: `HostRow` dataclass, `risk_score` (0-100), engineer notes generator, SSL/CVE integration in findings, all 34 port recommendations fully expanded with copy-paste CLI commands
- **`routes.py`** — New `check_ssl` and `check_cves` checkboxes, recent scans sidebar, full pipeline wiring

### New UI (complete redesign)
- `index.html` — Hero section, stats bar, dark professional design matching Soun Al Hosn brand, assessment tier descriptions, recent scans sidebar
- `progress.html` — Step indicators (Network Scan → CVE Lookup → Email Security → SSL/TLS → Report), color-coded live log
- `report.html` — Full commercial-grade layout: cover with risk score bar (0-100), 5 summary stat cards, collapsible findings, CVE table per finding, SSL section, Engineer Notes section (private), scope note, CTA

### Confirmed Working — Live Lab Test (10.0.180.0/24)
- **3 hosts found, 14 open ports, Risk Score 71/100 — High**
- **SMB on 10.0.180.1** (Critical — Samba), **VNC on 10.0.180.154** (Critical — Dell iDRAC), SSH on iDRAC
- **CVE-2015-6564** (CVSS 7.0 High) matched to OpenSSH 7.0
- **DMARC p=none** on sounalhosn.ae correctly flagged
- **SSL pass** on sounalhosn.ae (TLS 1.3, cert valid 187 days)
- **Engineer notes**: follow-up items for SMB credential test + SMBv1 check
- PDF: 569KB, renders correctly

## Soun Runner v3 — Premium Engine Upgrade (2 June 2026)

Built to justify AED 10,000/scan pricing. Soun/hacking aesthetic, not AI-marketing.

### New Modules (all Python stdlib — no new pip deps)
- **`netinfo.py`** — auto-detects subnet, gateway, public IP, ISP, ASN, geo. Correctly IDs du / AS15802 / Dubai. Form auto-fills subnet.
- **`topology.py`** — traceroute LAN → ISP edge → internet. Hops enriched with reverse-DNS + ASN/ISP/geo. Traces to 1.1.1.1 so the real ISP edge hop is revealed (du edge 94.206.158.36).

### Scanner Upgrade
- **`run_scan_streaming()`** — two-stage (discovery → service enum), streams genuine nmap output live.
- **`classify_device()`** — device-type fingerprinting: Router, Firewall, Windows Server, NAS, Camera, Printer, DB, Hypervisor, VoIP. iDRAC/iLO → Server. Gateway flagged.

### Report Sections Added
- Internet Perimeter & ISP Exposure (public IP, ISP, ASN, geo)
- Network Path topology visual (hop-by-hop with role labels)
- Attack Path Analysis (ransomware/RDP, lateral/SMB, breach/DB, takeover/VNC, BEC/DMARC) + mitigations
- Asset Inventory with device icons + classification

### UI — Full Hacker-Terminal Redesign
- Dark green-on-black monospace, scanlines, grid background, terminal chrome
- Console shows live auto-recon strip + re-detect button
- progress.html: real-time streaming terminal, phase steps, live stat counters (hosts/ports/findings/critical)

### Honest Scope Boundary
Maps client's internal network + path to ISP edge. Does NOT scan the ISP's own infrastructure (not legal/possible). Maps the perimeter: public IP, ISP, ASN, route, internal exposure.

### Verified in Lab (10.0.180.0/24)
Risk 71/100 Critical · 3 hosts classified · 14 ports · SMB+VNC critical · ISP edge mapped · attack paths fired · PDF ~560KB all sections render.

## Next Steps

1. **Windows EXE** — PyInstaller packaging so client machine needs no Python (top priority for field deployment)
2. **Sell first AED 10k scan** — Tool is commercially ready. Target the 2–3 contacts with real office networks.
3. **Fix your own domain** — Upgrade `sounalhosn.ae` DMARC from `p=none` to `p=quarantine`
4. **Close Skyview Arabia** — Follow up on that quote
5. **Fortinet NSE 4** — nse.fortinet.com, free self-study
