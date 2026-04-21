package com.vess.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Parses text commands and dispatches to [VessRpc] or [VessNode] JNI calls.
 *
 * [emit] is called on the main thread with each line of output (including
 * prompts and error messages).  Mirrors the vess-cli command surface.
 */
class CliDispatcher(
    private val scope: CoroutineScope,
    private val dataDir: String,
    private val rpcPort: Int = VessRpc.DEFAULT_PORT,
    private val emit: (String) -> Unit,
) {

    private var mintJob: Job? = null

    /** Handle a command line typed by the user. Returns immediately; output arrives via [emit]. */
    fun dispatch(line: String) {
        val parts = line.trim().split("\\s+".toRegex()).filter { it.isNotEmpty() }
        if (parts.isEmpty()) return
        val cmd = parts[0].lowercase()
        val args = parts.drop(1)

        scope.launch {
            try {
                route(cmd, args)
            } catch (e: Exception) {
                out("error: ${e.message}")
            }
        }
    }

    // ── Router ─────────────────────────────────────────────────────────────

    private suspend fun route(cmd: String, args: List<String>) {
        when (cmd) {
            "help", "?" -> cmdHelp()
            "status"    -> cmdStatus()
            "balance"   -> cmdBalance()
            "node-id",
            "nodeid"    -> out(VessNode.nativeGetNodeId().ifEmpty { "(node not running)" })
            "peers"     -> out("Peers: ${VessNode.nativeGetPeerCount()}")
            "node-info",
            "nodeinfo"  -> cmdNodeInfo()
            "send"      -> cmdSend(args)
            "send-direct",
            "senddirect"-> cmdSendDirect(args)
            "notifications",
            "notifs"    -> cmdNotifications(args)
            "tag-lookup",
            "taglookup" -> cmdTagLookup(args)
            "register-tag",
            "registertag" -> cmdRegisterTag(args)
            "wallet-unlock",
            "unlock"    -> cmdWalletUnlock(args)
            "wallet-lock",
            "lock"      -> cmdWalletLock()
            "set-password",
            "setpassword" -> cmdSetPassword(args)
            "init"      -> cmdInit(args)
            "recover"   -> cmdRecover(args)
            "mint"      -> cmdMint(args)
            "mint-finalize",
            "finalize"  -> cmdMintFinalize()
            "mint-status",
            "mintstatus"-> out("Use `mint --status` (run a mint step first)")
            "clear"     -> out("\u001b[2J") // caller may handle this specially
            else        -> out("Unknown command '$cmd'. Type 'help' for a list.")
        }
    }

    // ── Commands ───────────────────────────────────────────────────────────

    private fun cmdHelp() {
        out("""
Commands:
  status                     Node + wallet overview
  balance                    Wallet balance and breakdown
  node-id                    Show this node's public ID
  peers                      Show connected peer count
  node-info                  Full node statistics
  send <amount> <recipient>  Send VESS to +tag or address
  send-direct <amount> <recipient> <node-id>
                             Direct payment bypassing mesh
  notifications [max]        Drain queued wallet notifications
  tag-lookup <tag>           Resolve a +tag to a stealth address
  register-tag <tag>         Register and (auto-)harden a +tag
  init <tag>                 Create a new wallet with <tag>
  recover <words…> --pin <pin>
                             Recover wallet from recovery phrase
  mint                       Start mining in the background
  mint-finalize              Aggregate solves → bills + register
  wallet-unlock <password>   Unlock the embedded wallet
  wallet-lock                Lock the embedded wallet
  set-password <old> <new>   Change wallet fast-unlock password
  help                       Show this message
""".trimIndent())
    }

    private suspend fun cmdStatus() {
        val nodeId = VessNode.nativeGetNodeId()
        val peers  = VessNode.nativeGetPeerCount()
        val bal    = VessNode.nativeGetBalance()
        out("Node:    ${if (nodeId.isNotEmpty()) "online" else "offline"}")
        if (nodeId.isNotEmpty()) out("Node ID: $nodeId")
        out("Peers:   ${if (peers >= 0) peers.toString() else "—"}")
        out("Balance: $bal VESS")
    }

    private suspend fun cmdBalance() {
        val r = VessRpc.balance(rpcPort)
        if (r.optBoolean("ok")) {
            out("Balance: ${r.optLong("balance")} VESS  (${r.optLong("bill_count")} bills)")
        } else {
            out("error: ${r.optString("error", "rpc failed")}")
        }
    }

    private suspend fun cmdNodeInfo() {
        val r = VessRpc.nodeInfo(rpcPort)
        prettyPrint(r)
    }

    private suspend fun cmdSend(args: List<String>) {
        if (args.size < 2) { out("Usage: send <amount> <recipient> [memo]"); return }
        val amount = args[0].toLongOrNull() ?: run { out("amount must be a number"); return }
        val recipient = args[1]
        val memo = if (args.size >= 3) args.drop(2).joinToString(" ") else null
        out("Sending $amount VESS to $recipient…")
        val r = VessRpc.send(rpcPort, amount, recipient, memo)
        if (r.optBoolean("ok")) {
            out("Sent!  Payment ID: ${r.optString("payment_id")}")
            out("Balance: ${r.optLong("remaining_balance")} VESS")
        } else {
            out("error: ${r.optString("error", "send failed")}")
        }
    }

    private suspend fun cmdSendDirect(args: List<String>) {
        if (args.size < 3) { out("Usage: send-direct <amount> <recipient> <node-id>"); return }
        val amount = args[0].toLongOrNull() ?: run { out("amount must be a number"); return }
        val r = VessRpc.sendDirect(rpcPort, amount, args[1], args[2])
        if (r.optBoolean("ok")) {
            out("Direct payment accepted!  Payment ID: ${r.optString("payment_id")}")
        } else {
            out("error: ${r.optString("error", "send failed")}")
        }
    }

    private suspend fun cmdNotifications(args: List<String>) {
        val max = args.firstOrNull()?.toIntOrNull() ?: 64
        val r = VessRpc.notifications(rpcPort, max)
        val notes = r.optJSONArray("notifications")
        if (notes == null || notes.length() == 0) {
            out("No notifications.")
            return
        }
        repeat(notes.length()) { i ->
            val n = notes.getJSONObject(i)
            out("[${n.optString("kind")}] ${n.optString("message")}  (id: ${n.optString("payment_id")})")
        }
    }

    private suspend fun cmdTagLookup(args: List<String>) {
        if (args.isEmpty()) { out("Usage: tag-lookup <tag>"); return }
        val r = VessRpc.tagLookup(rpcPort, args[0])
        prettyPrint(r)
    }

    private suspend fun cmdRegisterTag(args: List<String>) {
        if (args.isEmpty()) { out("Usage: register-tag <tag>"); return }
        out("Computing Argon2id PoW — this takes ~10 s and 2 GiB RAM…")
        val r = VessRpc.tagRegister(rpcPort, args[0])
        if (r.optBoolean("ok")) {
            out("Tag ${args[0]} registered.  Hardened: ${r.optBoolean("hardened")}")
        } else {
            out("error: ${r.optString("error", "tag registration failed")}")
        }
    }

    private suspend fun cmdWalletUnlock(args: List<String>) {
        if (args.isEmpty()) { out("Usage: wallet-unlock <password>"); return }
        val r = VessRpc.walletUnlock(rpcPort, args[0])
        out(if (r.optBoolean("ok")) "Wallet unlocked." else "error: ${r.optString("error")}")
    }

    private suspend fun cmdWalletLock() {
        val r = VessRpc.walletLock(rpcPort)
        out(if (r.optBoolean("ok")) "Wallet locked." else "error: ${r.optString("error")}")
    }

    private suspend fun cmdSetPassword(args: List<String>) {
        if (args.size < 2) { out("Usage: set-password <current> <new>"); return }
        val r = VessRpc.walletSetPassword(rpcPort, args[0], args[1])
        out(if (r.optBoolean("ok")) "Password updated." else "error: ${r.optString("error")}")
    }

    private suspend fun cmdInit(args: List<String>) {
        if (args.isEmpty()) { out("Usage: init <tag>"); return }
        out("Initialising wallet for +${args[0]}…")
        out("(Computing Argon2id PoW — ~10 s, 2 GiB RAM)")
        val json = withContext(Dispatchers.IO) { VessNode.nativeWalletInit(dataDir, args[0]) }
        val r = JSONObject(json)
        if (r.optBoolean("ok")) {
            out("Wallet created!")
            out("Recovery phrase: ${r.optString("recovery_phrase")}")
            out("WRITE THIS DOWN — it is the only way to recover your wallet.")
        } else {
            out("error: ${r.optString("error")}")
        }
    }

    private suspend fun cmdRecover(args: List<String>) {
        // recover word1 word2 word3 word4 word5 --pin 12345
        val pinIdx = args.indexOfFirst { it == "--pin" }
        if (pinIdx < 0 || pinIdx + 1 >= args.size) {
            out("Usage: recover <word1> <word2> <word3> <word4> <word5> --pin <5-digit-pin>")
            return
        }
        val words = args.subList(0, pinIdx).joinToString(" ")
        val pin   = args[pinIdx + 1]
        out("Recovering wallet… (fetching manifest from network)")
        val json = withContext(Dispatchers.IO) { VessNode.nativeWalletRecover(dataDir, words, pin) }
        val r = JSONObject(json)
        if (r.optBoolean("ok")) {
            out("Recovered ${r.optInt("recovered_bills")} bills.  Balance: ${r.optLong("balance")} VESS")
        } else {
            out("error: ${r.optString("error")}")
        }
    }

    private fun cmdMint(args: List<String>) {
        if (mintJob?.isActive == true) {
            out("Mining already running.  Use 'mint-finalize' to stop and aggregate.")
            return
        }
        out("Mining started (1 solve = 1 VESS).  Run 'mint-finalize' to stop + aggregate.")
        mintJob = scope.launch(Dispatchers.IO) {
            var solves = 0
            var attempts = 0L
            while (isActive) {
                val json = VessNode.nativeMintStep(dataDir)
                val r = runCatching { JSONObject(json) }.getOrNull() ?: break
                if (!r.optBoolean("ok")) {
                    withContext(Dispatchers.Main) { out("Mint error: ${r.optString("error")}") }
                    break
                }
                attempts = r.optLong("attempts")
                val newSolves = r.optInt("solves")
                if (newSolves > solves) {
                    solves = newSolves
                    withContext(Dispatchers.Main) { out("Solve #$solves found! ($attempts attempts)") }
                }
            }
        }
    }

    private suspend fun cmdMintFinalize() {
        mintJob?.cancel()
        mintJob = null
        out("Aggregating solves into bills…")
        val json = withContext(Dispatchers.IO) { VessNode.nativeMintFinalize(dataDir, rpcPort) }
        val r = JSONObject(json)
        if (r.optBoolean("ok")) {
            out("Minted ${r.optInt("bills")} bill(s).  Balance: ${r.optLong("balance")} VESS")
        } else {
            out("error: ${r.optString("error")}")
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun out(msg: String) {
        // Always dispatch to main thread so callers don't need to worry.
        android.os.Handler(android.os.Looper.getMainLooper()).post { emit(msg) }
    }

    private fun prettyPrint(obj: JSONObject) {
        // Print each top-level key as a line.
        obj.keys().forEach { key ->
            out("$key: ${obj.get(key)}")
        }
    }
}
