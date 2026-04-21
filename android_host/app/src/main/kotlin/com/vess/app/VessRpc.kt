package com.vess.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Thin Kotlin wrapper around the Rust [VessNode.nativeRpc] JNI call.
 *
 * All methods are suspend functions that run on [Dispatchers.IO] so they can
 * be called from any coroutine scope without blocking the main thread.
 */
object VessRpc {

    const val DEFAULT_PORT = 9400

    // ── Low-level ─────────────────────────────────────────────────────────

    /** Make a raw JSON-RPC call. Returns the parsed response object. */
    suspend fun call(port: Int = DEFAULT_PORT, method: String, extras: Map<String, Any> = emptyMap()): JSONObject =
        withContext(Dispatchers.IO) {
            val req = JSONObject().apply {
                put("method", method)
                extras.forEach { (k, v) -> put(k, v) }
            }
            val raw = VessNode.nativeRpc(port, req.toString())
            runCatching { JSONObject(raw) }.getOrElse { JSONObject().put("error", "invalid json: $raw") }
        }

    // ── Typed helpers ─────────────────────────────────────────────────────

    suspend fun balance(port: Int = DEFAULT_PORT): JSONObject = call(port, "balance")

    suspend fun nodeInfo(port: Int = DEFAULT_PORT): JSONObject = call(port, "node_info")

    suspend fun notifications(port: Int = DEFAULT_PORT, max: Int = 64): JSONObject =
        call(port, "notifications", mapOf("max" to max))

    suspend fun tagLookup(port: Int = DEFAULT_PORT, tag: String): JSONObject =
        call(port, "tag_lookup", mapOf("tag" to tag))

    suspend fun send(port: Int = DEFAULT_PORT, amount: Long, recipient: String, memo: String? = null): JSONObject =
        call(port, "send", buildMap {
            put("amount", amount)
            put("recipient", recipient)
            if (memo != null) put("memo", memo)
        })

    suspend fun sendDirect(port: Int = DEFAULT_PORT, amount: Long, recipient: String, nodeId: String): JSONObject =
        call(port, "send_direct", mapOf("amount" to amount, "recipient" to recipient, "node_id" to nodeId))

    suspend fun walletUnlock(port: Int = DEFAULT_PORT, password: String): JSONObject =
        call(port, "wallet_unlock", mapOf("password" to password))

    suspend fun walletLock(port: Int = DEFAULT_PORT): JSONObject = call(port, "wallet_lock")

    suspend fun walletSetPassword(port: Int = DEFAULT_PORT, currentPassword: String, newPassword: String): JSONObject =
        call(port, "wallet_set_password", mapOf("current_password" to currentPassword, "new_password" to newPassword))

    suspend fun tagRegister(port: Int = DEFAULT_PORT, tag: String): JSONObject =
        // Full tag registration is orchestrated in Rust (PoW + signing).
        // This RPC variant is for when the signed payload is already prepared.
        call(port, "tag_register", mapOf("tag" to tag))
}
