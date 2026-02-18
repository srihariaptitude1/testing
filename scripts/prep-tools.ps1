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
    $null = robocopy $src $dst /MIR /NFL /NDL /NJH /NJS /NP
    if ($LASTEXITCODE -gt 7) { throw "robocopy failed ($LASTEXITCODE) from $src to $dst" }
}

$repoRoot = Get-RepoRoot
$resourcesRoot = Join-Path $repoRoot "resources"
$binRoot       = Join-Path $resourcesRoot "bin"
$gpgDst        = Join-Path $binRoot "gnupg"

Ensure-Dir $resourcesRoot
Ensure-Dir $binRoot

# --------------------------
# GnuPG Logic
# --------------------------
# If GnuPgRoot isn't passed, check for the default install path on GitHub Windows Runners
if ([string]::IsNullOrWhiteSpace($GnuPgRoot)) {
    $defaultInstallPath = "C:\Program Files (x86)\gnupg"
    if (Test-Path $defaultInstallPath) {
        $GnuPgRoot = $defaultInstallPath
    } else {
        throw "GnuPG not found. Ensure it is installed in the workflow."
    }
}

$GnuPgRoot = (Resolve-Path $GnuPgRoot).Path
if (!(Test-Path (Join-Path $GnuPgRoot "bin\gpg.exe"))) {
    throw "Native GnuPG not found at: $GnuPgRoot\bin\gpg.exe"
}

if ($Force -and (Test-Path $gpgDst)) { Remove-Item -Recurse -Force $gpgDst }
Copy-Tree $GnuPgRoot $gpgDst

Write-Host "Bundled GnuPG -> $gpgDst"
