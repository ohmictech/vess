@echo off
REM Build and deploy Vess to Android device/emulator.
REM Usage:
REM   .\build-android.bat              Build debug APK
REM   .\build-android.bat install      Build + install to connected device
REM   .\build-android.bat release      Build release APK
REM   .\build-android.bat run          Build + install + launch on device

setlocal
set MODE=%1
if "%MODE%"=="" set MODE=debug

echo ============================================
echo  Vess Android
echo ============================================

REM ── Native library ──────────────────────────────────────────
echo.
echo [1/3] Building native library (aarch64)...

rustup target add aarch64-linux-android 2>nul

if not exist "app\src\main\jniLibs\aarch64-linux-android" (
    mkdir "app\src\main\jniLibs\aarch64-linux-android"
)

set CARGO_FLAGS=
set GRADLE_TASK=assembleDebug
set APK_PATH=app\build\outputs\apk\debug\app-debug.apk

if "%MODE%"=="release" (
    set CARGO_FLAGS=--release
    set GRADLE_TASK=assembleRelease
    set APK_PATH=app\build\outputs\apk\release\app-release.apk
)

cargo ndk -t aarch64-linux-android -o app/src/main/jniLibs build %CARGO_FLAGS% -p vess-mobile
if %ERRORLEVEL% neq 0 (
    echo ERROR: Native build failed. Is cargo-ndk installed? ^(cargo install cargo-ndk^)
    exit /b 1
)

REM ── Kotlin bindings ─────────────────────────────────────────
echo [2/3] Generating Kotlin bindings...

set BUILD_DIR=debug
if "%MODE%"=="release" set BUILD_DIR=release

set LIB_PATH=..\vess-mobile\target\aarch64-linux-android\%BUILD_DIR%\libvess_core.so
if exist "%LIB_PATH%" (
    cargo run -p vess-mobile --bin uniffi-bindgen -- generate --library "%LIB_PATH%" --language kotlin --out-dir app\src\main\java 2>nul
    if %ERRORLEVEL% neq 0 (
        echo WARNING: Kotlin bindings generation failed ^(continuing with existing^)
    )
) else (
    echo WARNING: %LIB_PATH% not found - using existing bindings
)

REM ── Gradle APK build ────────────────────────────────────────
echo [3/3] Building APK with Gradle...
call gradlew %GRADLE_TASK%
if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Gradle build failed.
    echo Make sure you have Java 17+ and Android SDK installed.
    echo Run: gradlew wrapper   ^(if gradlew is missing^)
    exit /b 1
)

echo.
echo ============================================
echo  APK: %APK_PATH%
echo ============================================

REM ── Install to device (if requested) ────────────────────────
if "%MODE%"=="install" goto :do_install
if "%MODE%"=="run" goto :do_install
goto :done

:do_install
echo.
echo Installing to device...
adb devices 2>nul | findstr "device$" >nul
if %ERRORLEVEL% neq 0 (
    echo No device connected. Options:
    echo   1. Plug in phone via USB with USB Debugging enabled
    echo   2. Start emulator: emulator -avd Pixel_4
    echo   3. Connect via Wi-Fi: adb connect ^<phone-ip^>:5555
    exit /b 1
)

echo Uninstalling old version...
adb uninstall org.vess.core 2>nul

echo Installing...
adb install -r "%APK_PATH%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Install failed
    exit /b 1
)

if "%MODE%"=="run" (
    echo Launching...
    adb shell am start -n org.vess.core/.MainActivity
)

echo.
echo ============================================
echo  Installed on device!
echo ============================================
goto :done

:done
endlocal
