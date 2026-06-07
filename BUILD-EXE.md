# Building & Deploying SounRunner.exe

A single Windows executable with **Chromium baked in** — no Python, no pip, no
internet needed on the client. You build it **once** on a Windows machine, then
carry it to every client.

> **Why a build machine?** A Windows `.exe` can only be built on Windows
> (PyInstaller can't cross-compile from macOS). Build it once on any persistent
> Windows PC or VM — **not** in Windows Sandbox, which wipes on close.

---

## Part 1 — Build it once (on a Windows machine)

**Prerequisites on the build machine:**
- Python 3.10+ → `winget install Python.Python.3.12`
- Internet (to download deps + Chromium, one time)

**Steps:**
1. Get the project onto the Windows machine (clone or copy the folder):
   ```
   git clone https://github.com/j0ons/soun-runner.git
   cd soun-runner
   ```
2. Run the builder:
   ```
   build-exe.bat
   ```
   It creates a clean venv, installs everything, downloads Chromium **into the
   package**, and runs PyInstaller.
3. Result: **`dist\SounRunner.exe`** (~200–300 MB — Chromium is inside it).

That's the only file you need to carry. Copy it somewhere safe (USB stick,
your laptop, cloud).

---

## Part 2 — The client deployment folder

nmap is the **one** thing that can't be baked in — it's a native scanner that
needs the Npcap driver + admin. So your portable kit is **two files**:

```
SounRunner-Kit\
├─ SounRunner.exe          <- the app (Chromium inside, built in Part 1)
└─ nmap-setup.exe          <- nmap installer, download once from nmap.org/download
```

Download the nmap installer once from <https://nmap.org/download> (the
"Latest stable self-installer") and keep it in the kit.

---

## Part 3 — At each client (the repeatable process)

1. Copy the **SounRunner-Kit** folder to the client machine (or run from USB).
2. Install nmap (first time on that machine only):
   - Run `nmap-setup.exe` → accept defaults → **let it install Npcap** when asked.
3. Double-click **`SounRunner.exe`**.
   - A console window opens and shows: `PDF engine: chromium (playwright)`
   - Your browser opens at `http://127.0.0.1:5757`.
4. Run the scan. Reports (HTML + PDF) generate automatically.
5. When done, use the **Finish & Wipe** button in the app to remove all traces
   (keeps the `reports\` folder). See "Self-wipe" below.

> **No internet?** Fine — everything needed is in the .exe and nmap installer.
> **No admin rights?** nmap/Npcap needs admin to install. If you can't install
> it, the scan won't run (the app will tell you), but the PDF engine still works.

---

## How the pieces work

- **Chromium (PDF engine):** built with `PLAYWRIGHT_BROWSERS_PATH=0`, which puts
  the browser *inside* the playwright package; PyInstaller bundles it; at runtime
  `app/modules/pdf.py` points Playwright at the bundled copy. Zero install.
- **Templates / static / logo:** bundled and resolved via `resource_path()` in
  `app/__init__.py` (handles the frozen `sys._MEIPASS` path).
- **nmap:** located at runtime by `find_nmap()` — checks PATH and
  `C:\Program Files\Nmap\nmap.exe`. Hence the one-time installer in the kit.
- **WeasyPrint:** excluded from the .exe — Chromium is the engine. (It remains a
  fallback only in source runs.)

---

## Self-wipe (private-app cleanup)

SounRunner is a private assessment tool — you don't leave it behind on a client
machine. After a scan, the app offers a **Finish & Wipe** action that:

- saves/keeps the generated **reports** (copied to a `SounRunner-Reports` folder
  on the Desktop),
- deletes the working files, temp data, and the app itself,
- closes the server.

Take the reports with you; nothing else remains.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| `PDF engine: none` in console | Chromium didn't bundle. Rebuild; ensure `set PLAYWRIGHT_BROWSERS_PATH=0` ran before `playwright install chromium` (build-exe.bat does this). |
| "PDF not available" with a reason | The page now shows *why*. Usually nmap-unrelated; follow the on-screen hint. |
| Scan error: "Nmap is not installed" | Install `nmap-setup.exe` on that client (Part 3, step 2). |
| Antivirus flags the .exe | PyInstaller bundles trip some AV heuristics. Sign the .exe, or whitelist it. Expected for unsigned self-contained Python apps. |
| Build fails on Chromium download | No/blocked internet on the build machine. Retry on an open network. |
