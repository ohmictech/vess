# Vess Android

Android platform wrapper for the Vess protocol.

The shared Rust FFI lives in [`../vess-mobile`](../vess-mobile) — this
crate contains only Android-specific code: Gradle build scripts, Kotlin
wrappers, and the Android app shell.

## Directory Layout

```
vess-android/
├── kotlin/org/vess/core/
│   ├── vess_core.kt     # Auto-generated UniFFI bindings (from vess-mobile)
│   └── VessCore.kt      # JNA loader + convenience wrappers
├── build-android.bat     # Cross-compile script using cargo-ndk
├── app/                  # Android app (Android Studio project)
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/org/vess/core/
│       └── jniLibs/      # .so files from cargo-ndk
└── README.md
```

## Building

1. Build the shared Rust library:
   ```bash
   cd ../vess-mobile
   cargo ndk -t aarch64-linux-android -o ../vess-android/app/src/main/jniLibs build --release
   ```

2. Generate Kotlin bindings:
   ```bash
   cd ../vess-mobile
   cargo run --bin uniffi-bindgen -- generate \
       --library target/aarch64-linux-android/release/libvess_core.so \
       --language kotlin \
       --out-dir ../vess-android/app/src/main/java
   ```

3. Open in Android Studio and build the APK.
