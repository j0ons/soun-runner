# ============================================================================
#  SounRunner — one-shot setup & run for a fresh Windows machine / Sandbox
#
#  Downloads + installs everything (Python, Nmap, Git), clones the repo,
#  installs deps + Chromium, and launches the app. No copy-pasting.
#
#  HOW TO RUN (in PowerShell as Administrator):
#     irm https://raw.githubusercontent.com/j0ons/soun-runner/main/SETUP-AND-RUN.ps1 | iex
#  ...or if you already have the file:  powershell -ep Bypass -File SETUP-AND-RUN.ps1
# ============================================================================

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Say($msg, $color = "Cyan") { Write-Host "`n>>> $msg" -ForegroundColor $color }
function Have($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# Robust download with retries (sandbox network can be flaky)
function Get-File($url, $out) {
    for ($i = 1; $i -le 3; $i++) {
        try {
            Write-Host "    downloading ($i/3): $url"
            Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
            if ((Test-Path $out) -and (Get-Item $out).Length -gt 100000) { return $true }
        } catch { Write-Host "    retry: $($_.Exception.Message)" -ForegroundColor Yellow; Start-Sleep 2 }
    }
    throw "Failed to download $url after 3 tries."
}

$work = Join-Path $env:USERPROFILE "Desktop"
Set-Location $work
$dl = Join-Path $work "_sr_installers"
New-Item -ItemType Directory -Force -Path $dl | Out-Null

# Make freshly-installed tools usable in THIS session without reopening.
function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user    = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}

# --- 1. Python -------------------------------------------------------------
Refresh-Path
if (-not (Have python)) {
    Say "Installing Python 3.12 ..."
    $py = Join-Path $dl "python-setup.exe"
    Get-File "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" $py
    Start-Process -FilePath $py -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait
    Refresh-Path
} else { Say "Python already present." Green }

# Resolve a python executable even if PATH is stubborn
$python = "python"
if (-not (Have python)) {
    $cand = "C:\Program Files\Python312\python.exe","$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    $python = $cand | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $python) { throw "Python install did not land. Reopen PowerShell and re-run." }
}

# --- 2. Git ----------------------------------------------------------------
Refresh-Path
if (-not (Have git)) {
    Say "Installing Git ..."
    # Portable, stable URL (MinGit) — no installer wizard.
    $gitZip = Join-Path $dl "mingit.zip"
    Get-File "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/MinGit-2.47.1-64-bit.zip" $gitZip
    $gitDir = Join-Path $work "_sr_git"
    if (Test-Path $gitDir) { Remove-Item $gitDir -Recurse -Force }
    Expand-Archive -Path $gitZip -DestinationPath $gitDir -Force
    $env:Path = "$gitDir\cmd;$env:Path"
} else { Say "Git already present." Green }

$git = "git"
if (-not (Have git)) {
    $gc = Get-ChildItem -Path (Join-Path $work "_sr_git") -Filter git.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($gc) { $git = $gc.FullName } else { throw "Git not found after install." }
}

# --- 3. Nmap (background; user clicks through Npcap) ------------------------
if (-not (Test-Path "C:\Program Files (x86)\Nmap\nmap.exe") -and -not (Test-Path "C:\Program Files\Nmap\nmap.exe")) {
    Say "Downloading Nmap installer (a wizard will open — accept Npcap) ..."
    $nm = Join-Path $dl "nmap-setup.exe"
    try { Get-File "https://nmap.org/dist/nmap-7.95-setup.exe" $nm; Start-Process $nm } catch {
        Write-Host "    Nmap download failed — install it later from nmap.org. Scans need it." -ForegroundColor Yellow
    }
} else { Say "Nmap already present." Green }

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

# --- 5. Python deps + Chromium --------------------------------------------
Say "Installing Python dependencies ..."
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt

Say "Downloading Chromium for PDF engine (~120 MB, one-time) ..."
& $python -m playwright install chromium

# --- 6. Run ----------------------------------------------------------------
Say "Starting SounRunner ...  (browser opens at http://127.0.0.1:5757)" Green
Say "Leave this window open. Press Ctrl+C here to stop the app." Yellow
& $python main.py
