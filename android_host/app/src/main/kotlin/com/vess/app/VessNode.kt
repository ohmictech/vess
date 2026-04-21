package com.vess.app

/**
 * Kotlin-side JNI bridge to the Rust `vess-android` cdylib.
 *
 * Each `external fun` here corresponds to a `#[no_mangle] pub extern "system" fn`
 * in vess-android/src/lib.rs.  The native library must be compiled for the device
 * ABI and placed in jniLibs/ before building the APK (see app/build.gradle).
 */
object VessNode {

    init {
        System.loadLibrary("vess_android")
    }

    /** Start the Vess node, persisting state under [dataDir]. Returns true on success. */
    external fun nativeStartNode(dataDir: String): Boolean

    /** Gracefully shut down the running node. */
    external fun nativeStopNode()

    /** Public node ID (hex), or empty string when not running. */
    external fun nativeGetNodeId(): String

    /** Wallet balance in whole VESS units, or 0 when no wallet is loaded. */
    external fun nativeGetBalance(): Long

    /** Number of connected peers, or -1 when the node is not running. */
    external fun nativeGetPeerCount(): Int
}
