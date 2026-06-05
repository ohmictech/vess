#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build Vess CLI binary for the current platform.
.DESCRIPTION
    Builds vess-cli in release mode and copies the binary to dist/.
    Uses cargo's --locked flag to ensure Cargo.lock is respected
    for reproducible builds.
.PARAMETER Debug
    Build the debug profile instead of release.
.PARAMETER NoCopy
    Skip copying the binary to dist/.
.EXAMPLE
    .\scripts\build-vess.ps1
    .\scripts\build-vess.ps1 -Debug
#>
param(
    [switch]$Debug,
    [switch]$NoCopy
)

$ErrorActionPreference = "Stop"

$Profile = if ($Debug) { "dev" } else { "release" }
$ProfileFlag = if ($Debug) { "" } else { "--release" }

Write-Host "Building vess-cli ($Profile profile)..." -ForegroundColor Cyan

# Build with --locked to ensure Cargo.lock is respected
cargo build $ProfileFlag --locked -p vess-cli

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

if (-not $NoCopy) {
    $TargetDir = if ($Debug) { "debug" } else { "release" }
    $Source = "target\$TargetDir\vess-cli.exe"
    $DistDir = "dist"
    $null = New-Item -ItemType Directory -Force -Path $DistDir
    Copy-Item $Source "dist\vess.exe" -Force
    Write-Host "Binary copied to dist\vess.exe" -ForegroundColor Green
}

Write-Host "Build complete." -ForegroundColor Green
