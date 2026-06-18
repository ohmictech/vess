#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build and deploy Vess to an Android device via USB.

.DESCRIPTION
    One-command build-and-install for Vess Android:
      1. Cross-compile the Rust native library (aarch64) via cargo-ndk
      2. Generate Kotlin UniFFI bindings
      3. Build the APK with Gradle
      4. Install to a USB-connected Android device via adb

.PARAMETER Mode
    debug    Build debug APK only (default)
    install  Build debug APK + install to device
    release  Build release APK only
    run      Build debug APK + install + launch

.EXAMPLE
    .\deploy-android.ps1           # Build debug APK
    .\deploy-android.ps1 install   # Build + install to phone
    .\deploy-android.ps1 run       # Build + install + launch
    .\deploy-android.ps1 release   # Build release APK

.NOTES
    Prerequisites (one-time setup):
      rustup target add aarch64-linux-android
      cargo install cargo-ndk
      Install Android SDK + NDK (Android Studio recommended)
      Set ANDROID_HOME (or ANDROID_SDK_ROOT) environment variable
      Enable USB Debugging on the phone
#>

param(
    [ValidateSet("debug", "install", "release", "run")]
    [string]$Mode = "install"
)

$ErrorActionPreference = "Continue"

# ---- Paths ---------------------------------------------------------
$RepoRoot   = Resolve-Path "$PSScriptRoot\.."
$AndroidDir = "$PSScriptRoot"
$MobileDir  = "$RepoRoot\vess-mobile"
$JniLibsDir = "$AndroidDir\app\src\main\jniLibs\aarch64-linux-android"
$GradleCmd  = if (Test-Path "$AndroidDir\gradlew.bat") { "$AndroidDir\gradlew.bat" } else { "$AndroidDir\gradlew" }
$PackageId  = "org.vess.core"
$Activity   = "$PackageId/.MainActivity"

$IsRelease  = $Mode -eq "release"
$DoInstall  = $Mode -eq "install" -or $Mode -eq "run"
$DoLaunch   = $Mode -eq "run"
$BuildDir   = if ($IsRelease) { "release" } else { "debug" }
$CargoFlags = if ($IsRelease) { "--release" } else { "" }
$GradleTask = if ($IsRelease) { "assembleRelease" } else { "assembleDebug" }
$ApkPath    = if ($IsRelease) {
    "$AndroidDir\app\build\outputs\apk\release\app-release.apk"
} else {
    "$AndroidDir\app\build\outputs\apk\debug\app-debug.apk"
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Vess Android - Deploy Script"             -ForegroundColor Cyan
Write-Host "  Mode: $Mode"                                -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ---- Check prerequisites -------------------------------------------
Write-Host "[check] Verifying prerequisites..." -ForegroundColor Yellow

$missing = @()

# adb
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    $missing += "adb (Android Debug Bridge - part of Android SDK Platform-Tools)"
}

# cargo / rustup
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $missing += "cargo (Rust toolchain - https://rustup.rs)"
}

# cargo-ndk (check by trying to run it)
$cargoNdkOk = $false
try {
    $null = & cargo ndk --version 2>&1
    $cargoNdkOk = ($LASTEXITCODE -eq 0)
} catch {
    $cargoNdkOk = $false
}
if (-not $cargoNdkOk) {
    $missing += "cargo-ndk (run: cargo install cargo-ndk)"
}

# Java (for Gradle)
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    $missing += "Java 17+ (needed for Gradle)"
}

# Android SDK
$sdkRoot = $env:ANDROID_HOME, $env:ANDROID_SDK_ROOT | Where-Object { $_ } | Select-Object -First 1
if (-not $sdkRoot) {
    $sdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
}
if (-not (Test-Path "$sdkRoot")) {
    $missing += "Android SDK (set ANDROID_HOME or install Android Studio)"
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "ERROR: Missing prerequisites:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "One-time setup:" -ForegroundColor Yellow
    Write-Host "  1. Install Rust:        https://rustup.rs"
    Write-Host "  2. Add Android target:   rustup target add aarch64-linux-android"
    Write-Host "  3. Install cargo-ndk:    cargo install cargo-ndk"
    Write-Host "  4. Install Android Studio (for SDK + NDK)"
    Write-Host "  5. Set ANDROID_HOME environment variable"
    Write-Host "  6. Enable USB Debugging on your phone"
    exit 1
}

Write-Host "  adb:        $(adb version 2>&1 | Select-Object -First 1)"
Write-Host "  cargo:      $(cargo --version 2>&1)"
Write-Host "  java:       $(java --version 2>&1 | Select-Object -First 1)"
Write-Host "  ANDROID_HOME: $sdkRoot"

# Auto-detect NDK
$ndkHome = $env:ANDROID_NDK_HOME
if (-not $ndkHome) {
    $ndkDirs = Get-ChildItem "$sdkRoot\ndk" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    if ($ndkDirs) {
        $ndkHome = $ndkDirs[0].FullName
    }
}
if ($ndkHome) {
    $env:ANDROID_NDK_HOME = $ndkHome
    Write-Host "  ANDROID_NDK_HOME: $ndkHome"
} else {
    Write-Host "  ANDROID_NDK_HOME: NOT FOUND" -ForegroundColor Red
    Write-Host ""
    Write-Host "ERROR: Android NDK not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Install via Android Studio:" -ForegroundColor Yellow
    Write-Host "    1. Open Android Studio"
    Write-Host "    2. File -> Settings -> Languages & Frameworks -> Android SDK -> SDK Tools"
    Write-Host "    3. Check 'NDK (Side by side)' and click Apply"
    Write-Host ""
    Write-Host "  Or via command line (if cmdline-tools is installed):" -ForegroundColor Yellow
    Write-Host "    sdkmanager --install 'ndk;27.0.12077973'" -ForegroundColor Yellow
    Write-Host "    (install cmdline-tools first via Android Studio if missing)" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# ---- Generate gradlew if missing (first run only) ------------------
if (-not (Test-Path $GradleCmd)) {
    Write-Host "[setup] Bootstrapping Gradle wrapper..." -ForegroundColor Yellow
    Write-Host "  The gradlew.bat script will auto-download gradle-wrapper.jar on first use." -ForegroundColor Yellow
    Write-Host "  If this fails, open the project in Android Studio once to auto-generate gradlew." -ForegroundColor Yellow
    Write-Host ""
}

# ---- Step 1: Native library ----------------------------------------
Write-Host "=== [1/4] Building native library (aarch64) ===" -ForegroundColor Cyan

# Ensure Android target is installed (suppress all output)
$null = rustup target add aarch64-linux-android 2>&1

# Create jniLibs directory
if (-not (Test-Path $JniLibsDir)) {
    New-Item -ItemType Directory -Path $JniLibsDir -Force | Out-Null
}

# Go to repo root for cargo ndk (workspace-level)
Push-Location $RepoRoot
try {
    $ndkArgs = @(
        "ndk", "-t", "aarch64-linux-android",
        "-o", "vess-android/app/src/main/jniLibs",
        "build"
    )
    if ($IsRelease) { $ndkArgs += "--release" }
    $ndkArgs += "-p", "vess-mobile"

    & cargo @ndkArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Native build failed." -ForegroundColor Red
        Write-Host "Is cargo-ndk installed?  cargo install cargo-ndk" -ForegroundColor Yellow
        Write-Host "Is NDK 26+ installed?    Check Android Studio -> SDK Manager -> SDK Tools -> NDK" -ForegroundColor Yellow
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "  Native library built." -ForegroundColor Green
Write-Host ""

# ---- Step 2: Kotlin UniFFI bindings --------------------------------
Write-Host "=== [2/4] Generating Kotlin bindings ===" -ForegroundColor Cyan

$LibPath = "$RepoRoot\target\aarch64-linux-android\$BuildDir\libvess_core.so"
if (Test-Path $LibPath) {
    Push-Location $RepoRoot
    try {
        & cargo run -p vess-mobile --bin uniffi-bindgen -- generate `
            --library $LibPath `
            --language kotlin `
            --out-dir "$AndroidDir\app\src\main\java" 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  WARNING: Kotlin bindings generation failed - using existing bindings." -ForegroundColor Yellow
        } else {
            Write-Host "  Kotlin bindings generated." -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "  WARNING: $LibPath not found - using existing bindings." -ForegroundColor Yellow
}
Write-Host ""

# ---- Step 3: Gradle APK build --------------------------------------
Write-Host "=== [3/4] Building APK (Gradle) ===" -ForegroundColor Cyan

Push-Location $AndroidDir
try {
    $env:ANDROID_HOME = $sdkRoot
    & $GradleCmd $GradleTask
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Gradle build failed." -ForegroundColor Red
        Write-Host "  - Check that Java 17+ is installed"
        Write-Host "  - Check that ANDROID_HOME points to a valid Android SDK"
        Write-Host "  - Try opening in Android Studio first to download missing SDK components"
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "  APK built." -ForegroundColor Green
Write-Host ""

# ---- Check APK exists ----------------------------------------------
if (-not (Test-Path $ApkPath)) {
    Write-Host "ERROR: APK not found at $ApkPath" -ForegroundColor Red
    exit 1
}

$apkSize = [math]::Round((Get-Item $ApkPath).Length / 1MB, 1)
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  APK: $ApkPath"                           -ForegroundColor White
Write-Host "  Size: $apkSize MB"                         -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ---- Step 4: Install to device -------------------------------------
if (-not $DoInstall) {
    Write-Host "Done. APK built successfully." -ForegroundColor Green
    exit 0
}

Write-Host "=== [4/4] Installing to device ===" -ForegroundColor Cyan

# Check for connected device
$devices = adb devices 2>$null | Select-String "device$" | Where-Object { $_ -notmatch "List of devices" }
if (-not $devices) {
    Write-Host ""
    Write-Host "ERROR: No device connected." -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Plug in phone via USB"
    Write-Host "  2. Enable USB Debugging (Settings → Developer Options)"
    Write-Host "  3. Check connection:  adb devices"
    Write-Host "  4. If unauthorized, tap 'Allow' on phone when prompt appears"
    Write-Host "  5. Wi-Fi alternative:  adb connect <phone-ip>:5555"
    exit 1
}

Write-Host "  Device found: $($devices -replace '\s+device.*','')" -ForegroundColor Green

# Uninstall old version (ignore errors if not installed)
Write-Host "  Uninstalling previous version..."
adb uninstall $PackageId 2>$null

# Install
Write-Host "  Installing APK..."
adb install -r $ApkPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Install failed." -ForegroundColor Red
    Write-Host "  Try: adb install -r -d $ApkPath  (allow downgrade)" -ForegroundColor Yellow
    exit 1
}

Write-Host "  Installed!" -ForegroundColor Green

# Launch if requested
if ($DoLaunch) {
    Write-Host "  Launching..."
    adb shell am start -n $Activity 2>$null
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Deployed to device!"                        -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
