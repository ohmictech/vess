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

    // ── Node lifecycle ─────────────────────────────────────────────────────

    /** Start the Vess node, persisting state under [dataDir]. Returns true on success. */
    external fun nativeStartNode(dataDir: String): Boolean

    /** Gracefully shut down the running node. */
    external fun nativeStopNode()

    // ── Basic stats ────────────────────────────────────────────────────────

    /** Public node ID (hex), or empty string when not running. */
    external fun nativeGetNodeId(): String

    /** Wallet balance in whole VESS units, or 0 when no wallet is loaded. */
    external fun nativeGetBalance(): Long

    /** Number of connected peers, or -1 when the node is not running. */
    external fun nativeGetPeerCount(): Int

    // ── RPC bridge ────────────────────────────────────────────────────────
    //
    // Most CLI operations (balance, send, notifications, tag-lookup, …) are
    // handled by the embedded node's local RPC server.  nativeRpc forwards a
    // raw JSON request string and returns the raw JSON response string.
    // Use VessRpc (Kotlin) to construct/parse the messages instead of calling
    // this directly.

    /**
     * Make a synchronous JSON-RPC call to the local artery node.
     * [port] is typically 9400.  Returns a JSON object as a String.
     * MUST be called from a background thread — blocks until the response
     * arrives or times out.
     */
    external fun nativeRpc(port: Int, requestJson: String): String

    // ── Wallet operations ──────────────────────────────────────────────────

    /**
     * Create a new wallet for [tag] under [dataDir].
     * Derives keys, computes Argon2id tag PoW (~10 s), registers the tag.
     * Returns `{"ok":true,"recovery_phrase":"word1 word2 …PIN"}` or
     * `{"ok":false,"error":"…"}`.
     * MUST be called from a background thread (long-running).
     */
    external fun nativeWalletInit(dataDir: String, tag: String): String

    /**
     * Recover a wallet from [words] (space-separated BIP39) and [pin].
     * Fetches the bill manifest from the network and reconstructs the billfold.
     * Returns `{"ok":true,"recovered_bills":N,"balance":N}` or error.
     * MUST be called from a background thread (network + Argon2id).
     */
    external fun nativeWalletRecover(dataDir: String, words: String, pin: String): String

    // ── Mining ─────────────────────────────────────────────────────────────

    /**
     * Run one mint iteration (VM step + difficulty check) under [dataDir].
     * Returns `{"ok":true,"hit":bool,"solves":N,"attempts":N}` or error.
     * Call this in a tight loop on a background thread; check `hit` to know
     * when a solve occurred.  The session is persisted to disk automatically.
     */
    external fun nativeMintStep(dataDir: String): String

    /**
     * Aggregate accumulated solves into bills and broadcast OwnershipGenesis
     * via the local RPC server on [rpcPort].
     * Returns `{"ok":true,"bills":N,"balance":N}` or error.
     * MUST be called from a background thread.
     */
    external fun nativeMintFinalize(dataDir: String, rpcPort: Int): String
}

