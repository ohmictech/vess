[CmdletBinding()]
param(
    [string]$Output = "dist\vess.exe",
    [switch]$DebugBuild
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
$ProfileName = "release"
$ProfileArgs = @("--release")

if ($DebugBuild) {
    $ProfileName = "debug"
    $ProfileArgs = @()
}

Push-Location $Root
try {
    cargo build -p vess-cli --bin vess @ProfileArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }

    $ExeName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "vess.exe" } else { "vess" }
    $Built = Join-Path $Root "target\$ProfileName\$ExeName"
    if (-not (Test-Path $Built)) {
        throw "built executable not found at $Built"
    }

    if ([System.IO.Path]::IsPathRooted($Output)) {
        $OutPath = $Output
    } else {
        $OutPath = Join-Path $Root $Output
    }

    $OutDir = Split-Path -Parent $OutPath
    if ($OutDir) {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    }

    Copy-Item -Force $Built $OutPath
    Write-Host "Built interactive Vess executable:"
    Write-Host "  $OutPath"
    Write-Host "Run it with no arguments, or double-click it, to open the interactive CLI."
} finally {
    Pop-Location
}