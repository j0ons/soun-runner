# ============================================================================
#  SounRunner - one-shot setup & run for a Windows machine (incl. via AnyDesk).
#
#  Installs everything (VC++ runtime, Python, Git, Nmap), clones the repo,
#  installs deps + Chromium, VERIFIES the whole chain, then launches the app.
#
#  HOW TO RUN (PowerShell as Administrator):
#     irm https://raw.githubusercontent.com/j0ons/soun-runner/main/SETUP-AND-RUN.ps1 | iex
#  ...or from a local copy:  powershell -ExecutionPolicy Bypass -File SETUP-AND-RUN.ps1
#
#  NOTE: ASCII-only on purpose so it parses identically on Windows PowerShell 5.1
#  (the client default) and PowerShell 7, with or without a byte-order mark.
# ============================================================================

# Do NOT use 'Stop' globally: native tools (pip, playwright) write warnings to
# stderr, which under Stop can abort the whole script on PS 5.1 even on success.
# We check failures explicitly instead.
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"   # faster, quieter downloads
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }  # older hosts: ignore

$script:FAILS = @()

function Say($msg, $color = "Cyan") { Write-Host "`n>>> $msg" -ForegroundColor $color }
function Warn($msg) { Write-Host "    $msg" -ForegroundColor Yellow }
function Good($msg) { Write-Host "    $msg" -ForegroundColor Green }
function Have($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

function Update-SessionPath {
    $m = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $u = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$m;$u"
}

# Robust download with retries; verifies the file is non-trivial (not an HTML
# error page). Returns $true/$false instead of throwing.
function Get-File($url, $out) {
    for ($i = 1; $i -le 4; $i++) {
        try {
            Write-Host "    downloading ($i/4): $url"
            Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -ErrorAction Stop
            if ((Test-Path $out) -and (Get-Item $out).Length -gt 100000) { return $true }
            Warn "file looked too small, retrying"
        } catch {
            Warn ("download error: " + $_.Exception.Message)
            Start-Sleep 3
        }
    }
    return $false
}

# --- Pre-flight ------------------------------------------------------------
Say "Soun Runner setup - pre-flight checks"

# Admin?
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if ($isAdmin) { Good "Running as Administrator." }
else { Warn "NOT running as Administrator - installers may fail. Re-open PowerShell as Admin if anything below errors." }

# Internet?
try {
    $null = Invoke-WebRequest -Uri "https://raw.githubusercontent.com" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
    Good "Internet reachable."
} catch {
    Warn "Could not reach the internet. Downloads will fail on a locked-down network."
}

$work = Join-Path $env:USERPROFILE "Desktop"
if (-not (Test-Path $work)) { $work = $env:USERPROFILE }
Set-Location $work
$dl = Join-Path $work "_sr_installers"
New-Item -ItemType Directory -Force -Path $dl | Out-Null

# --- 0. Visual C++ runtime (fixes greenlet/Playwright DLL load) ------------
Say "Installing Microsoft Visual C++ runtime (needed by Playwright) ..."
$vc = Join-Path $dl "vc_redist.x64.exe"
if (Get-File "https://aka.ms/vs/17/release/vc_redist.x64.exe" $vc) {
    Start-Process -FilePath $vc -ArgumentList "/install","/quiet","/norestart" -Wait
    Good "VC++ runtime installed (or already present)."
} else {
    Warn "VC++ runtime download failed - PDFs may not work until it is installed."
    $script:FAILS += "VC++ runtime"
}

# --- 1. Python -------------------------------------------------------------
Update-SessionPath
if (-not (Have python)) {
    Say "Installing Python 3.12 ..."
    $py = Join-Path $dl "python-setup.exe"
    if (Get-File "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" $py) {
        Start-Process -FilePath $py -ArgumentList "/quiet","InstallAllUsers=1","PrependPath=1","Include_pip=1" -Wait
        Update-SessionPath
    } else { $script:FAILS += "Python download" }
} else { Say "Python already present." Green }

# Resolve a python.exe full path (don't trust bare 'python' on PATH).
$python = $null
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if ($pyCmd) { $python = $pyCmd.Source }
if (-not $python) {
    foreach ($p in "C:\Program Files\Python312\python.exe",
                   "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
                   "C:\Program Files\Python313\python.exe") {
        if (Test-Path $p) { $python = $p; break }
    }
}
if (-not $python) {
    Write-Host "`nFATAL: Python is not installed and could not be located." -ForegroundColor Red
    Write-Host "Open a NEW PowerShell (Admin) and re-run the one-liner." -ForegroundColor Red
    return
}
Good "Using python: $python"

# --- 2. Git (full-path resolve; portable MinGit if missing) ----------------
Update-SessionPath
$git = $null
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) { $git = $gitCmd.Source }
if (-not $git) {
    Say "Installing Git (portable MinGit) ..."
    $gitZip = Join-Path $dl "mingit.zip"
    if (Get-File "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/MinGit-2.47.1-64-bit.zip" $gitZip) {
        $gitDir = Join-Path $work "_sr_git"
        if (Test-Path $gitDir) { Remove-Item $gitDir -Recurse -Force }
        Expand-Archive -Path $gitZip -DestinationPath $gitDir -Force
        $gc = Get-ChildItem -Path $gitDir -Filter git.exe -Recurse -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -match '\\cmd\\git\.exe$' } | Select-Object -First 1
        if (-not $gc) { $gc = Get-ChildItem -Path $gitDir -Filter git.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 }
        if ($gc) { $git = $gc.FullName; $env:Path = "$(Split-Path $git);$env:Path" }
    }
}
if (-not $git) {
    Write-Host "`nFATAL: Git could not be installed/located - cannot fetch the app." -ForegroundColor Red
    return
}
Good "Using git: $git"

# --- 3. Nmap -----------------------------------------------------------------
# IMPORTANT: Nmap's installer REFUSES to install silently (/S) unless Npcap is
# already present ("Silent installation of Nmap requires the Npcap packet
# capturing software"). And the FREE Npcap installer has no silent mode either.
# But Soun Runner only does unprivileged TCP-connect scans, which do NOT need
# Npcap at all. So: try silent only if Npcap already exists; otherwise open the
# interactive installer and tell the operator they can UNCHECK Npcap (one quick
# click-through). This is the reliable path on a fresh machine.
function Find-Nmap {
    foreach ($p in "C:\Program Files (x86)\Nmap\nmap.exe","C:\Program Files\Nmap\nmap.exe") {
        if (Test-Path $p) { return $p }
    }
    return $null
}
$npcapPresent = (Test-Path "C:\Program Files\Npcap") -or (Test-Path "C:\Windows\System32\Npcap") -or (Test-Path "C:\Windows\System32\wpcap.dll")
$nmapExe = Find-Nmap
if (-not $nmapExe) {
    Say "Installing Nmap ..."
    $nm = Join-Path $dl "nmap-setup.exe"
    if (Get-File "https://nmap.org/dist/nmap-7.95-setup.exe" $nm) {
        if ($npcapPresent) {
            Write-Host "    Npcap present - attempting silent install (/S) ..."
            Start-Process -FilePath $nm -ArgumentList "/S" -Wait
            foreach ($t in 1..15) { $nmapExe = Find-Nmap; if ($nmapExe) { break }; Start-Sleep 1 }
        }
        if (-not $nmapExe) {
            Write-Host ""
            Write-Host "  ===========================================================" -ForegroundColor Yellow
            Write-Host "   ACTION NEEDED: the Nmap installer window is opening." -ForegroundColor Yellow
            Write-Host "   Click 'I Agree' / 'Next' through the screens, then 'Install'." -ForegroundColor Yellow
            Write-Host "   TIP: on the components screen you may UNCHECK 'Npcap' -" -ForegroundColor Yellow
            Write-Host "        Soun Runner does not need it. Then finish the wizard." -ForegroundColor Yellow
            Write-Host "  ===========================================================" -ForegroundColor Yellow
            Write-Host ""
            Start-Process -FilePath $nm
            Write-Host "    waiting for Nmap to finish installing (up to 5 min) ..."
            foreach ($t in 1..300) { $nmapExe = Find-Nmap; if ($nmapExe) { break }; Start-Sleep 1 }
        }
    }
}
if ($nmapExe) {
    Good "Nmap ready: $nmapExe"
    $env:Path = "$(Split-Path $nmapExe);$env:Path"
} else {
    Warn "Nmap not available - scanning will not work until it is installed (PDF/reports still work)."
    $script:FAILS += "Nmap"
}

# --- 4. Get the project ----------------------------------------------------
$proj = Join-Path $work "soun-runner"
if (Test-Path (Join-Path $proj ".git")) {
    Say "Updating existing soun-runner (git pull) ..."
    Set-Location $proj
    & $git pull
} else {
    Say "Cloning soun-runner from GitHub ..."
    if (Test-Path $proj) { Remove-Item $proj -Recurse -Force }
    & $git clone https://github.com/j0ons/soun-runner.git $proj
    Set-Location $proj
}
if (-not (Test-Path (Join-Path $proj "main.py"))) {
    Write-Host "`nFATAL: clone/pull failed - main.py not found in $proj." -ForegroundColor Red
    return
}
Good "Project ready: $proj"

# Drop an UPDATE.bat that knows where git + python live, so updating later
# never hits "git not recognized". Double-click it (or run from cmd) to pull
# the latest code and relaunch.
try {
    $updateBat = @"
@echo off
title Soun Runner - Update ^& Run
cd /d "%~dp0"
echo Updating Soun Runner from GitHub...
"$git" pull
echo.
echo Starting Soun Runner...
"$python" main.py
pause
"@
    Set-Content -Path (Join-Path $proj "UPDATE.bat") -Value $updateBat -Encoding ASCII
    Good "Created UPDATE.bat (double-click it later to update + run)."
} catch { }

# --- 5. Python deps + Chromium --------------------------------------------
Say "Installing Python dependencies ..."
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt

Say "Installing Chromium for the PDF engine (~120 MB, one-time) ..."
$chromeOk = $false
for ($i = 1; $i -le 3; $i++) {
    Write-Host "    playwright install chromium ($i/3) ..."
    & $python -m playwright install chromium
    $check = & $python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop(); print('PWOK')" 2>&1
    if ($check -match "PWOK") { $chromeOk = $true; break }
    Warn "Chromium not ready yet (attempt $i) - retrying ..."
    Start-Sleep 3
}
if ($chromeOk) { Good "PDF engine verified: Chromium launches." }
else { Warn "Chromium could not be verified - PDFs may be unavailable (HTML reports still work)."; $script:FAILS += "Chromium/PDF" }

# --- 6. Final verification summary -----------------------------------------
Say "Verification summary"
$pyOk    = [bool]$python -and (Test-Path $python)
$gitOk   = [bool]$git
$nmapOk  = [bool]$nmapExe
$projOk  = Test-Path (Join-Path $proj "main.py")
function Mark($ok) { if ($ok) { "  [ OK ]" } else { "  [FAIL]" } }
Write-Host ((Mark $pyOk)    + " Python")            -ForegroundColor ($(if($pyOk){"Green"}else{"Red"}))
Write-Host ((Mark $gitOk)   + " Git")               -ForegroundColor ($(if($gitOk){"Green"}else{"Red"}))
Write-Host ((Mark $nmapOk)  + " Nmap (scanning)")   -ForegroundColor ($(if($nmapOk){"Green"}else{"Yellow"}))
Write-Host ((Mark $chromeOk)+ " Chromium (PDF)")    -ForegroundColor ($(if($chromeOk){"Green"}else{"Yellow"}))
Write-Host ((Mark $projOk)  + " App files")         -ForegroundColor ($(if($projOk){"Green"}else{"Red"}))

if (-not ($pyOk -and $projOk)) {
    Write-Host "`nCannot start: Python or app files are missing. Fix the [FAIL] items above and re-run." -ForegroundColor Red
    return
}
if ($script:FAILS.Count -gt 0) {
    Warn ("Non-fatal issues: " + ($script:FAILS -join ", ") + ". The app will still start.")
}

# --- 7. Run ----------------------------------------------------------------
Say "Starting SounRunner - your browser will open at http://127.0.0.1:5757" Green
Say "Leave this window open. Press Ctrl+C here to stop the app." Yellow
& $python main.py
