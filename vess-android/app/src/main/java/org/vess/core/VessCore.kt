package org.vess.core

import com.sun.jna.Native

/**
 * Convenience wrapper around the auto-generated UniFFI bindings.
 * Handles JNA native library loading and provides idiomatic Kotlin API.
 */
object VessCore {
    private var loaded = false

    /** Load the native library. Safe to call multiple times. */
    fun init() {
        if (!loaded) {
            System.loadLibrary("vess_core")
            loaded = true
        }
    }

    /** Create a new wallet with a VessTag. Returns recovery phrase + address. */
    @Throws(VessException::class)
    fun createWallet(tag: String, walletName: String, password: String): WalletInfo {
        init()
        return org.vess.core.createWallet(tag, walletName, password)
    }

    /** Recover a wallet from a 12-word BIP39 recovery phrase. */
    @Throws(VessException::class)
    fun recoverWallet(phraseWords: String, walletName: String, password: String): WalletInfo {
        init()
        return org.vess.core.recoverWallet(phraseWords, walletName, password)
    }

    /** Start the Vess node. Returns immediately; node runs in background thread. */
    @Throws(VessException::class)
    fun startNode(config: NodeConfig): NodeStatus {
        init()
        return org.vess.core.startNode(config)
    }

    /** Request graceful shutdown of the running node. */
    @Throws(VessException::class)
    fun stopNode() {
        init()
        org.vess.core.stopNode()
    }

    fun isNodeRunning(): Boolean {
        init()
        return org.vess.core.isNodeRunning()
    }

    @Throws(VessException::class)
    fun getBalance(): Balance {
        init()
        return org.vess.core.getBalance()
    }

    @Throws(VessException::class)
    fun sendPayment(amount: ULong, recipient: String, memo: String?): PaymentResult {
        init()
        return org.vess.core.sendPayment(amount, recipient, memo)
    }

    @Throws(VessException::class)
    fun getNotifications(): List<Notification> {
        init()
        return org.vess.core.getNotifications()
    }

    @Throws(VessException::class)
    fun lookupTag(tag: String): TagInfo {
        init()
        return org.vess.core.lookupTag(tag)
    }

    @Throws(VessException::class)
    fun registerTag(tag: String) {
        init()
        org.vess.core.registerTag(tag)
    }

    @Throws(VessException::class)
    fun getStatus(): NodeStatus {
        init()
        return org.vess.core.getStatus()
    }

    @Throws(VessException::class)
    fun getStealthAddress(): String {
        init()
        return org.vess.core.getStealthAddress()
    }
}
