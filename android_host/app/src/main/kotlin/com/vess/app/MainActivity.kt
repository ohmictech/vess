package com.vess.app

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
class MainActivity : AppCompatActivity() {

    private lateinit var tvNodeId: TextView
    private lateinit var tvBalance: TextView
    private lateinit var tvPeers: TextView
    private lateinit var btnToggle: Button

    private var service: VessService? = null
    private var serviceBound = false

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = (binder as VessService.LocalBinder).service()
            serviceBound = true
            btnToggle.text = getString(R.string.btn_stop)
        }
        override fun onServiceDisconnected(name: ComponentName) {
            service = null
            serviceBound = false
            btnToggle.text = getString(R.string.btn_start)
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshStats()
            handler.postDelayed(this, 2_000)
        }
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvNodeId  = findViewById(R.id.tvNodeId)
        tvBalance = findViewById(R.id.tvBalance)
        tvPeers   = findViewById(R.id.tvPeers)
        btnToggle = findViewById(R.id.btnToggle)

        btnToggle.setOnClickListener {
            if (serviceBound) stopNode() else startNode()
        }

        findViewById<Button>(R.id.btnTerminal).setOnClickListener {
            startActivity(Intent(this, TerminalActivity::class.java))
        }

        requestNotificationPermission()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refreshRunnable)
    }

    override fun onPause() {
        handler.removeCallbacks(refreshRunnable)
        super.onPause()
    }

    override fun onStop() {
        if (serviceBound) {
            unbindService(connection)
            serviceBound = false
        }
        super.onStop()
    }

    // ── Node control ───────────────────────────────────────────────────────

    private fun startNode() {
        val intent = Intent(this, VessService::class.java)
        ContextCompat.startForegroundService(this, intent)
        bindService(intent, connection, BIND_AUTO_CREATE)
    }

    private fun stopNode() {
        if (serviceBound) {
            unbindService(connection)
            serviceBound = false
        }
        stopService(Intent(this, VessService::class.java))
        btnToggle.text = getString(R.string.btn_start)
        refreshStats()
    }

    // ── Stats refresh ──────────────────────────────────────────────────────

    private fun refreshStats() {
        tvNodeId.text  = getString(R.string.label_node_id,  VessNode.nativeGetNodeId().ifEmpty { "—" })
        tvBalance.text = getString(R.string.label_balance,  VessNode.nativeGetBalance())
        tvPeers.text   = getString(R.string.label_peers,    VessNode.nativeGetPeerCount())
    }

    // ── Permissions ────────────────────────────────────────────────────────

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
    }
}
