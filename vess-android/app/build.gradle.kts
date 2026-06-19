plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.vess.core"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.vess.core"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    // Coroutines for service lifecycle
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // JNA for native library loading (Rust FFI)
    implementation("net.java.dev.jna:jna:5.16.0@aar")

    // Biometric authentication
    implementation("androidx.biometric:biometric:1.1.0")

    // Security (EncryptedSharedPreferences)
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Core KTX
    implementation("androidx.core:core-ktx:1.15.0")

    // AppCompat (required for BiometricPrompt with FragmentActivity)
    implementation("androidx.appcompat:appcompat:1.7.0")
}
