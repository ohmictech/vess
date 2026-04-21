package com.vess.app

import android.os.Bundle
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope

/**
 * Full-screen terminal activity providing a vess-cli-equivalent interface.
 *
 * Output scrolls upward like a traditional terminal.  The user types a command
 * in the bottom input field and presses Enter/Send to execute it.
 *
 * Commands are dispatched by [CliDispatcher] which routes to [VessRpc] or
 * [VessNode] JNI calls accordingly.
 */
class TerminalActivity : AppCompatActivity() {

    private lateinit var tvOutput: TextView
    private lateinit var svOutput: ScrollView
    private lateinit var etInput: EditText

    private lateinit var cli: CliDispatcher

    private val outputBuffer = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_terminal)
        supportActionBar?.title = getString(R.string.title_terminal)

        tvOutput = findViewById(R.id.tvTerminalOutput)
        svOutput = findViewById(R.id.svTerminalScroll)
        etInput  = findViewById(R.id.etTerminalInput)

        cli = CliDispatcher(
            scope    = lifecycleScope,
            dataDir  = filesDir.absolutePath,
            rpcPort  = VessRpc.DEFAULT_PORT,
            emit     = ::appendLine,
        )

        etInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEND ||
                actionId == EditorInfo.IME_ACTION_DONE ||
                actionId == EditorInfo.IME_NULL
            ) {
                submitInput()
                true
            } else {
                false
            }
        }

        // Print welcome banner on first launch.
        if (savedInstanceState == null) {
            appendLine("Vess CLI  —  type 'help' for a list of commands")
            appendLine("Node: ${if (VessNode.nativeGetPeerCount() >= 0) "online" else "offline"}")
            appendLine("")
        } else {
            // Restore buffer after rotation.
            outputBuffer.append(savedInstanceState.getString(KEY_BUFFER, ""))
            tvOutput.text = outputBuffer.toString()
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_BUFFER, outputBuffer.toString())
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun submitInput() {
        val text = etInput.text.toString().trim()
        etInput.text.clear()
        if (text.isEmpty()) return

        appendLine("> $text")   // echo command
        if (text == "clear") {
            outputBuffer.clear()
            tvOutput.text = ""
            return
        }
        cli.dispatch(text)
    }

    private fun appendLine(line: String) {
        outputBuffer.appendLine(line)
        tvOutput.text = outputBuffer.toString()
        // Scroll to bottom after layout pass.
        svOutput.post { svOutput.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    companion object {
        private const val KEY_BUFFER = "terminal_buffer"
    }
}
