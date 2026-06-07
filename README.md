# Soun Runner

**Private network security assessment tool — Soun Al Hosn Cybersecurity LLC.**

Soun Runner is an internal tool used by Soun Al Hosn engineers to assess a
client's network, find security exposures, and produce professional reports.
It has two modes:

| Mode | Who | What it does |
|------|-----|--------------|
| **Free Scan** | Lead generation | Quick scan — finds devices + exposed services. Produces two reports (a plain-language **client** report and a **engineer** report). Designed to win the paid job. |
| **Advanced** | Paid engagements | Full assessment — deep probing, validation agent, compliance mapping (NESA/ISO/PCI), remediation runbook, engineer workspace. **Password protected.** |

> This is a **private, Soun-only tool.** It is not for clients to use directly.

---

## 1. Quick start

### Fresh Windows machine (client site, incl. via AnyDesk) — ONE command

Open **Command Prompt** (cmd) and paste this single line. It works whether you
land in cmd or PowerShell — no need to think about which shell you're in:

```
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/j0ons/soun-runner/main/SETUP-AND-RUN.ps1 | iex"
```

It installs everything (VC++ runtime, Python, Git, Nmap, Chromium), fetches the
app, prints a verification summary, and launches it. Re-running it later just
updates to the latest version (git pull).

> If you've copied the repo to the machine, you can instead double-click
> **`SETUP.bat`** — same thing.

### Already set up (Python present) — just launch
- **Windows:** double-click **`START-WINDOWS.bat`**
- **Mac (your testing):** double-click **`START-MAC.command`** (first time:
  right-click → Open)

Either way, a browser opens at **http://127.0.0.1:5757**.

**The Advanced password is:** `Tmppassword`

---

## 2. Running it on a client's machine (via AnyDesk)

The client machine does **not** need any coding tools — but it does need two
free programs installed **once**. The engineer does this over AnyDesk.

### One-time setup on the client machine (≈5 minutes)

1. **AnyDesk** into the client machine (must be on the client's office network).
2. Install **Python** (one time):
   - Go to https://www.python.org/downloads/ → download the latest Windows installer.
   - Run it. **Tick "Add Python to PATH"** on the first screen, then "Install Now".
3. Install **Nmap** (one time):
   - Go to https://nmap.org/download → download the Windows installer (Npcap is included).
   - Run it with all default options.
4. Copy the **`soun-runner-v2`** folder to the machine (drag it over AnyDesk,
   or from a USB stick). Put it somewhere simple like the Desktop.

### Every scan after that

1. AnyDesk into the client machine.
2. Open the `soun-runner-v2` folder → **double-click `START-WINDOWS.bat`**.
   - It auto-installs the Python packages the first time (needs internet, ~1 min).
   - The browser opens automatically.
3. Run your scan (see section 3).
4. Download the report PDF, then disconnect.

> **Tip:** If the client machine can't install software, run Soun Runner from
> **your own laptop** instead — just make sure your laptop is plugged into the
> client's network (or on their Wi-Fi) so it can see their devices.

---

## 3. How to run a scan

### Free scan (lead-in)
1. On the landing page, click **Start Free Scan**.
2. Enter a name (optional) and the **target** (auto-filled with the detected
   network, e.g. `10.0.180.0/24`).
3. Click **Run Free Scan**. Watch the live progress.
4. When done you get **two reports**:
   - **Client Report** — plain language, for the business owner. Hand this over.
   - **Engineer Report** — technical, with fix steps. For your records / the proposal.
5. Download both PDFs.

### Advanced scan (paid engagement)
1. On the landing page, choose **Advanced** and enter the password.
2. The console auto-detects the network. The **target** is pre-filled; click a
   suggested routed subnet to add it if the client has more than one network.
3. Choose scan depth: **Basic / Standard / Advanced**.
4. Tick the modules you want (deep probing, web panels, validation agent,
   SSL/email, CVE lookup, compliance). Defaults are sensible.
   - The two **intrusive** modules (default-credential test, resilience probe)
     only run if you tick them **and** confirm written authorization.
5. Click **Execute Assessment** and watch the live terminal.
6. When done you can:
   - **Open Report** — the full assessment (view in browser or download PDF).
   - **Engineer Workspace** — live, hands-on tools (see section 4).
   - **Checklist** — the on-site field assessment (backup, firewall, VLAN, pentest notes).

---

## 4. Engineer Workspace (Advanced only)

After an advanced scan, open **Engineer Workspace** to investigate hands-on:

- **Pick any discovered host** on the left.
- **Run live actions** against it: re-scan ports, inspect SMB, grab a web
  banner, check TLS, run the full safe script set, test reachability, trace the
  route. Results appear instantly.
- **Triage findings** on the right: mark each as Confirmed / False positive /
  Accepted risk / Fixed.
- **Add manual findings** you noticed during the engagement.

Actions are **scope-locked** — you can only act on hosts discovered in this
assessment. Everything is read-only and safe to run on a live network.

---

## 5. The field checklist

The checklist captures the things a tool can't measure — backup readiness,
firewall configuration, VLAN isolation, and penetration notes. Open it from the
scan's action bar, answer the questions on-site (Yes / No / N/A), and your "No"
answers automatically become findings in the report.

---

## 6. Where reports are saved

All generated reports are stored in the **`reports/`** folder inside
`soun-runner-v2`, named by job ID:

```
reports/
  <id>.html / <id>.pdf            (advanced report)
  <id>_client.html / .pdf         (free - client report)
  <id>_engineer.html / .pdf       (free - engineer report)
```

You can also download them directly from the browser after a scan.

---

## 7. Maintenance & troubleshooting

**Change the Advanced password**
Set an environment variable before launching:
- Windows: edit `START-WINDOWS.bat` and add a line near the top:
  `set SOUN_ADVANCED_PASSWORD=YourNewPassword`
- Mac: edit `START-MAC.command` and add:
  `export SOUN_ADVANCED_PASSWORD=YourNewPassword`
If you don't change it, the password stays `Tmppassword`.

**"Nmap not found"**
Install Nmap (https://nmap.org/download) and restart the launcher. Scans need it.

**PDF not generated / "PDF skipped"**
The HTML report still works — download that instead. On Mac, PDF needs the
Homebrew libraries (`brew install pango gdk-pixbuf libffi`); the launcher sets
the path automatically.

**"No hosts found"**
Check the target subnet is correct. The machine running Soun Runner must be on
the **same network** as the devices you're scanning. Re-detect the network with
the ⟳ button on the console.

**Some devices missing**
Soun Runner already uses an aggressive discovery method that finds devices
which block ping (Windows PCs, etc.). If a whole network segment is missing, the
devices are probably on a **different subnet** — use the routed-subnet
suggestions on the console, or add the other subnet to the target manually
(space-separated, e.g. `10.0.180.0/24 10.0.160.0/24`).

**To stop the tool**
Close the launcher window (or press Ctrl+C in it).

---

## 8. What it needs to run

- **Python 3.10+** (one-time install on the host)
- **Nmap** (one-time install on the host)
- Python packages in `requirements.txt` (installed automatically by the launcher):
  Flask, Jinja2, dnspython, WeasyPrint
- Everything else (network detection, ISP/ASN lookup, CVE lookup, SSL checks,
  topology) uses Python's built-in libraries — no extra installs.

---

*Soun Al Hosn Cybersecurity LLC · Dubai, UAE · info@sounalhosn.ae · +971 52 203 4204*
