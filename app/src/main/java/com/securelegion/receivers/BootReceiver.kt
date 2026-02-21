package com.securelegion.receivers

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securelegion.LockActivity
import com.securelegion.R
import com.securelegion.crypto.KeyManager
import com.securelegion.services.TorService
import com.securelegion.workers.MessageRetryWorker

/**
 * Boot receiver - starts TorService and background workers after device boot
 *
 * This ensures:
 * 1. TorService restarts automatically after reboot
 * 2. Message retry worker is scheduled
 * 3. User can receive messages without opening the app
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
        private const val BOOT_NOTIFICATION_ID = 9901
        private const val CHANNEL_ID = "boot_restart_channel"
    }

    override fun onReceive(context: Context, intent: Intent) {
        // SECURITY: Validate intent action to prevent malicious broadcasts
        val action = intent.action
        if (action == null) {
            Log.w(TAG, "Ignoring broadcast with null action")
            return
        }

        // Only accept legitimate boot broadcast actions
        val validActions = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            "android.intent.action.QUICKBOOT_POWERON"
        )

        if (action !in validActions) {
            Log.w(TAG, "Ignoring invalid intent action: $action")
            return
        }

        // SECURITY: Verify this is a system broadcast, not from a malicious app
        // System broadcasts have no extras or only system-specific extras
        if (intent.extras != null && !intent.extras!!.isEmpty) {
            Log.w(TAG, "Ignoring broadcast with unexpected extras (potential spoofing)")
            return
        }

        Log.i(TAG, "Device boot completed - initializing Secure Legion services")

        try {
            // Only start services if account is initialized
            val keyManager = KeyManager.getInstance(context)
            if (!keyManager.isInitialized()) {
                Log.d(TAG, "No account initialized - skipping service startup")
                return
            }

            Log.i(TAG, "Account found - starting background services")

            // Show a visible notification that the app is restarting
            showBootNotification(context)

            // 1. Start TorService (foreground service)
            val torIntent = Intent(context, TorService::class.java)
            torIntent.action = TorService.ACTION_START_TOR
            context.startForegroundService(torIntent)
            Log.i(TAG, "TorService started")

            // 2. Schedule MessageRetryWorker (periodic background task)
            MessageRetryWorker.schedule(context)
            Log.i(TAG, "MessageRetryWorker scheduled")

            Log.i(TAG, "All background services initialized successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start services on boot", e)
        }
    }

    private fun showBootNotification(context: Context) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Create channel if needed
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Service Restart",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Notifies when Secure Legion restarts after device reboot"
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
            }
            notificationManager.createNotificationChannel(channel)
        }

        val tapIntent = Intent(context, LockActivity::class.java).apply {
            putExtra("TARGET_ACTIVITY", "MainActivity")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context, 0, tapIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_logo)
            .setContentTitle("Secure Legion")
            .setContentText("Reconnecting to the Tor network...")
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()

        notificationManager.notify(BOOT_NOTIFICATION_ID, notification)
    }
}
