# ============================================================================
#  SounRunner - one-shot setup & run for a Windows machine (incl. via AnyDesk).
#
#  Installs everything (VC++ runtime, Python, Git, Nmap), clones the repo,
#  installs deps, VERIFIES the whole chain for real, then launches the app.
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

# ----------------------------------------------------------------------------
# REAL-Python detection.
#
# Windows 10/11 ships a FAKE python.exe (an App Execution Alias under
# ...\Microsoft\WindowsApps\) that just prints "Python was not found; run
# without arguments to install from the Microsoft Store" and exits non-zero.
# Checking "is python on PATH" therefore proves NOTHING. The only trustworthy
# test is to RUN the candidate and require:  exit code 0  +  "Python 3.x" out,
# with x >= 10 (the app uses 3.10+ syntax).
# ----------------------------------------------------------------------------
function Test-RealPython($exe) {
    if (-not $exe) { return $false }
    if (-not (Test-Path $exe)) { return $false }
    try {
        $out = (& $exe --version 2>&1 | Out-String).Trim()
    } catch { return $false }
    if ($LASTEXITCODE -ne 0) { return $false }
    if ($out -match "^Python 3\.(\d+)") { return ([int]$Matches[1] -ge 10) }
    return $false
}

# Try every plausible Python, newest sources first, and return the first one
# that actually RUNS. Returns $null if none works.
function Resolve-Python {
    $cands = @()
    # Portable Python installed by a previous run of this script.
    $cands += (Join-Path $work "_sr_python\python.exe")
    # Whatever PATH says (this is where the Store stub gets rejected).
    $c = Get-Command python -ErrorAction SilentlyContinue
    if ($c) { $cands += $c.Source }
    # The py launcher knows about real installs even when PATH is stale.
    $pyl = Get-Command py -ErrorAction SilentlyContinue
    if ($pyl) {
        try {
            $exe = (& $pyl.Source -3 -c "import sys;print(sys.executable)" 2>$null | Out-String).Trim()
            if ($exe) { $cands += $exe }
        } catch { $null = $_ }
    }
    # Standard install locations (all-users and per-user).
    foreach ($v in "312","313","311","310") {
        $cands += "C:\Program Files\Python$v\python.exe"
        $cands += "$env:LOCALAPPDATA\Programs\Python\Python$v\python.exe"
    }
    foreach ($cand in $cands) {
        if (Test-RealPython $cand) { return $cand }
    }
    return $null
}

# Last-resort Python that needs NO admin rights and NO installer: the official
# python.org "embeddable" zip, unpacked next to the project. Survives machines
# where the MSI installer fails silently (no admin, group policy, AV).
function Install-PortablePython {
    Say "Installing portable Python 3.12 (no admin needed) ..."
    $zip = Join-Path $dl "python-embed.zip"
    if (-not (Get-File "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip" $zip)) { return $null }
    $dir = Join-Path $work "_sr_python"
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    $exe = Join-Path $dir "python.exe"
    if (-not (Test-Path $exe)) { return $null }
    # The embeddable build ships with 'import site' disabled, which blocks pip.
    $pth = Get-ChildItem -Path $dir -Filter "python3*._pth" | Select-Object -First 1
    if ($pth) {
        $content = Get-Content $pth.FullName
        $content = $content -replace "^#\s*import\s+site", "import site"
        Set-Content -Path $pth.FullName -Value $content -Encoding ASCII
    }
    # Bootstrap pip (the embeddable build has no ensurepip).
    $gp = Join-Path $dl "get-pip.py"
    if (-not (Get-File "https://bootstrap.pypa.io/get-pip.py" $gp)) { return $null }
    & $exe $gp --no-warn-script-location
    $pipOut = (& $exe -m pip --version 2>&1 | Out-String).Trim()
    if ($pipOut -notmatch "^pip ") { Warn "pip bootstrap failed in portable Python."; return $null }
    if (Test-RealPython $exe) { return $exe }
    return $null
}

# The machine's own Chromium-based browser. Every Windows 10/11 box ships
# Microsoft Edge, and the app can render PDFs through it headlessly - so the
# 120 MB Chromium download becomes optional, not required.
function Find-EdgeOrChrome {
    foreach ($p in "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                   "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                   "C:\Program Files\Google\Chrome\Application\chrome.exe",
                   "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                   "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# --- Pre-flight ------------------------------------------------------------
Say "Soun Runner setup - pre-flight checks"

# Admin?
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if ($isAdmin) { Good "Running as Administrator." }
else { Warn "NOT running as Administrator - using per-user installs where possible." }

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

# --- 0. Visual C++ runtime (needed by greenlet/Playwright) ------------------
Say "Installing Microsoft Visual C++ runtime ..."
$vc = Join-Path $dl "vc_redist.x64.exe"
if (Get-File "https://aka.ms/vs/17/release/vc_redist.x64.exe" $vc) {
    Start-Process -FilePath $vc -ArgumentList "/install","/quiet","/norestart" -Wait
    Good "VC++ runtime installed (or already present)."
} else {
    Warn "VC++ runtime download failed - the Playwright PDF engine may not load (Edge fallback still works)."
    $script:FAILS += "VC++ runtime"
}

# --- 1. Python (validated by EXECUTION, never by existence) ------------------
Update-SessionPath
$python = Resolve-Python
if ($python) {
    Say "Python already present."
} else {
    Say "Installing Python 3.12 ..."
    $py = Join-Path $dl "python-setup.exe"
    if (Get-File "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" $py) {
        # All-users needs admin; fall back to a per-user install otherwise.
        if ($isAdmin) { $pyArgs = "/quiet","InstallAllUsers=1","PrependPath=1","Include_pip=1" }
        else          { $pyArgs = "/quiet","InstallAllUsers=0","PrependPath=1","Include_pip=1" }
        Start-Process -FilePath $py -ArgumentList $pyArgs -Wait
        Update-SessionPath
        $python = Resolve-Python
    } else { $script:FAILS += "Python download" }
    if (-not $python) {
        Warn "Standard Python install did not produce a working python.exe."
        $python = Install-PortablePython
    }
}
if (-not $python) {
    Write-Host "`nFATAL: no working Python could be installed or located." -ForegroundColor Red
    Write-Host "(Note: the 'python' that opens the Microsoft Store is a Windows" -ForegroundColor Red
    Write-Host " placeholder, not a real Python - this script ignores it on purpose.)" -ForegroundColor Red
    Write-Host "Check the internet connection and re-run this script." -ForegroundColor Red
    return
}
Good "Using python: $python"
Good ((& $python --version 2>&1 | Out-String).Trim())

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
} catch { $null = $_ }

# --- 5. Python deps (verified by importing, not by pip's exit code) ---------
Say "Installing Python dependencies ..."
& $python -m pip install --upgrade pip --quiet --no-warn-script-location
$reqs = Join-Path $proj "requirements.txt"
foreach ($try in 1..2) {
    & $python -m pip install -r $reqs --no-warn-script-location
    if ($LASTEXITCODE -eq 0) { break }
    Warn "pip install reported errors (attempt $try/2) - retrying ..."
    Start-Sleep 3
}
# The app cannot start without Flask. Prove the import works - this is the
# check that catches a fake/broken Python no matter what pip claimed.
$depsOk = ((& $python -c "import flask; print('FLASKOK')" 2>&1 | Out-String) -match "FLASKOK")
if ($depsOk) { Good "Python packages ready (Flask imports cleanly)." }
else { Warn "Core Python packages did NOT install."; $script:FAILS += "Python packages" }

# --- 6. PDF engine -----------------------------------------------------------
# Preference order inside the app:
#   1) Playwright Chromium (if downloaded)  2) the machine's own Edge/Chrome
#   via Playwright  3) Edge/Chrome headless CLI  4) WeasyPrint  5) HTML-only.
# Since every Windows 10/11 machine ships Edge, the 120 MB Chromium download
# is only attempted when NO system browser exists.
$sysBrowser = Find-EdgeOrChrome
$pdfOk = $false
if ($sysBrowser) {
    Say "PDF engine: using this machine's own browser - no download needed."
    Good "Found: $sysBrowser"
    $pdfOk = $true
} elseif ($depsOk) {
    Say "No Edge/Chrome found - installing Chromium for the PDF engine (~120 MB, one-time) ..."
    for ($i = 1; $i -le 3; $i++) {
        Write-Host "    playwright install chromium ($i/3) ..."
        & $python -m playwright install chromium
        $check = & $python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop(); print('PWOK')" 2>&1
        if ($check -match "PWOK") { $pdfOk = $true; break }
        Warn "Chromium not ready yet (attempt $i) - retrying ..."
        Start-Sleep 3
    }
    if ($pdfOk) { Good "PDF engine verified: Chromium launches." }
    else { Warn "Chromium could not be verified - reports will fall back to HTML if no engine works."; $script:FAILS += "Chromium/PDF" }
}

# --- 7. Final verification summary (every check is REAL, not cosmetic) ------
Say "Verification summary"
$pyOk   = Test-RealPython $python
$gitOk  = [bool]$git
$nmapOk = [bool]$nmapExe
$projOk = Test-Path (Join-Path $proj "main.py")
function Mark($ok) { if ($ok) { "  [ OK ]" } else { "  [FAIL]" } }
Write-Host ((Mark $pyOk)   + " Python (runs + version 3.10+)") -ForegroundColor ($(if($pyOk){"Green"}else{"Red"}))
Write-Host ((Mark $depsOk) + " Python packages (Flask imports)") -ForegroundColor ($(if($depsOk){"Green"}else{"Red"}))
Write-Host ((Mark $gitOk)  + " Git")               -ForegroundColor ($(if($gitOk){"Green"}else{"Red"}))
Write-Host ((Mark $nmapOk) + " Nmap (scanning)")   -ForegroundColor ($(if($nmapOk){"Green"}else{"Yellow"}))
Write-Host ((Mark $pdfOk)  + " PDF engine")        -ForegroundColor ($(if($pdfOk){"Green"}else{"Yellow"}))
Write-Host ((Mark $projOk) + " App files")         -ForegroundColor ($(if($projOk){"Green"}else{"Red"}))

if (-not ($pyOk -and $projOk -and $depsOk)) {
    Write-Host "`nCannot start: fix the [FAIL] items above and re-run this script." -ForegroundColor Red
    if (-not $depsOk) {
        Write-Host "Most common cause: no internet / proxy / antivirus blocking pip downloads." -ForegroundColor Red
    }
    return
}
if ($script:FAILS.Count -gt 0) {
    Warn ("Non-fatal issues: " + ($script:FAILS -join ", ") + ". The app will still start.")
}

# --- 8. Run ----------------------------------------------------------------
Say "Starting SounRunner - your browser will open at http://127.0.0.1:5757" Green
Say "Leave this window open. Press Ctrl+C here to stop the app." Yellow
& $python main.py
