package com.vess.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * Foreground service that keeps the Vess node alive while the app is in the background.
 *
 * Start it from MainActivity (or on boot via a BroadcastReceiver) and bind to it
 * from any Activity that needs live stats.
 */
class VessService : Service() {

    inner class LocalBinder : Binder() {
        fun service(): VessService = this@VessService
    }

    private val binder = LocalBinder()

    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIFICATION_ID, buildNotification())
        VessNode.nativeStartNode(filesDir.absolutePath)
    }

    override fun onDestroy() {
        VessNode.nativeStopNode()
        super.onDestroy()
    }

    override fun onBind(intent: Intent): IBinder = binder

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val CHANNEL_ID = "vess_node"
        const val NOTIFICATION_ID = 1
    }
}
