package com.securelegion.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
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
}
