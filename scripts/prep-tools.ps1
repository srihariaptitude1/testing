param(
  [switch]$Force,
  [string]$GnuPgRoot
)

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
  $here = Split-Path -Parent $PSCommandPath
  return (Resolve-Path (Join-Path $here "..")).Path
}

function Ensure-Dir([string]$p) {
  if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

function Copy-Tree([string]$src, [string]$dst) {
  Ensure-Dir $dst
  # robocopy is most reliable for big trees on Windows
  $null = robocopy $src $dst /MIR /NFL /NDL /NJH /NJS /NP
  # robocopy returns non-zero codes even on success; accept <= 7
  if ($LASTEXITCODE -gt 7) { throw "robocopy failed ($LASTEXITCODE) from $src to $dst" }
}

function Install-GnuPg-Official([string]$targetDir) {
  Ensure-Dir $targetDir

  $indexUrl = "https://gnupg.org/ftp/gcrypt/binary/"
  $html = (Invoke-WebRequest -Uri $indexUrl -UseBasicParsing).Content

  $rx = [regex]'gnupg-w32-(\d+\.\d+\.\d+)_([0-9]{8})\.exe'
  $matches = $rx.Matches($html)
  if ($matches.Count -lt 1) { throw "Could not find gnupg-w32 installer in $indexUrl" }

  $latest = $matches | Sort-Object { $_.Groups[2].Value } -Descending | Select-Object -First 1
  $fileName = $latest.Value
  $downloadUrl = "$indexUrl$fileName"

  $installer = Join-Path $env:TEMP $fileName
  Invoke-WebRequest -Uri $downloadUrl -OutFile $installer

  Start-Process -FilePath $installer -ArgumentList "/S", "/D=$targetDir" -Wait -NoNewWindow
  return $targetDir
}

$repoRoot = Get-RepoRoot

$resourcesRoot = Join-Path $repoRoot "resources"
$binRoot       = Join-Path $resourcesRoot "bin"
$gitDst        = Join-Path $binRoot "git"
$gpgDst        = Join-Path $binRoot "gnupg"
$pythonDst     = Join-Path $resourcesRoot "python"

Ensure-Dir $resourcesRoot
Ensure-Dir $binRoot

# --------------------------
# Git (copy from installed Git for Windows)
# --------------------------
$gitCmd = (Get-Command git -ErrorAction SilentlyContinue)
if (-not $gitCmd) { throw "git not found on PATH. Install Git before running prep-tools." }

$gitExe = $gitCmd.Source
# Typically: C:\Program Files\Git\cmd\git.exe
$gitRoot = (Resolve-Path (Join-Path (Split-Path $gitExe -Parent) "..")).Path

if ($Force -and (Test-Path $gitDst)) { Remove-Item -Recurse -Force $gitDst }
Copy-Tree $gitRoot $gitDst

# --------------------------
# Python (bundle the actual Python installation used for build)
# --------------------------
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { throw "python not found on PATH. Install Python before running prep-tools." }

$pythonRoot = $env:pythonLocation
if ([string]::IsNullOrWhiteSpace($pythonRoot)) {
  $pythonRoot = (Split-Path $py.Source -Parent)
}
$pythonRoot = (Resolve-Path $pythonRoot).Path

if ($Force -and (Test-Path $pythonDst)) { Remove-Item -Recurse -Force $pythonDst }
Copy-Tree $pythonRoot $pythonDst

# --------------------------
# GnuPG (MUST be native official installer; avoid MSYS/cygwin gpg)
# --------------------------
if ([string]::IsNullOrWhiteSpace($GnuPgRoot)) {
  if (-not [string]::IsNullOrWhiteSpace($env:WHO_GNUPG_ROOT)) {
    $GnuPgRoot = $env:WHO_GNUPG_ROOT
  } else {
    $cacheDir = Join-Path $repoRoot ".cache\gnupg"
    if ($Force -and (Test-Path $cacheDir)) { Remove-Item -Recurse -Force $cacheDir }
    $GnuPgRoot = Install-GnuPg-Official -targetDir $cacheDir
  }
}

$GnuPgRoot = (Resolve-Path $GnuPgRoot).Path
if (!(Test-Path (Join-Path $GnuPgRoot "bin\gpg.exe"))) {
  throw "Native GnuPG not found at: $GnuPgRoot\bin\gpg.exe"
}

if ($Force -and (Test-Path $gpgDst)) { Remove-Item -Recurse -Force $gpgDst }
Copy-Tree $GnuPgRoot $gpgDst

# Ensure expected layout: resources/bin/gnupg/bin/gpg.exe
if (!(Test-Path (Join-Path $gpgDst "bin\gpg.exe"))) { throw "GnuPG copy failed: missing $gpgDst\bin\gpg.exe" }
if (!(Test-Path (Join-Path $gpgDst "bin\gpgconf.exe"))) { throw "GnuPG copy failed: missing $gpgDst\bin\gpgconf.exe" }

# --------------------------
# Icons (runtime)
# --------------------------
$iconsDir = Join-Path $resourcesRoot "icons"
Ensure-Dir $iconsDir
if (Test-Path (Join-Path $repoRoot "assets\icons")) {
  Copy-Item -Recurse -Force (Join-Path $repoRoot "assets\icons\*") $iconsDir -ErrorAction SilentlyContinue
}

Write-Host "Bundled Git     -> $gitDst"
Write-Host "Bundled Python  -> $pythonDst"
Write-Host "Bundled GnuPG   -> $gpgDst"
Write-Host "Icons folder    -> $iconsDir"
