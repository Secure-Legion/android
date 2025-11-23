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
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) {
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
            Log.i(TAG, "✓ TorService started")

            // 2. Schedule MessageRetryWorker (periodic background task)
            MessageRetryWorker.schedule(context)
            Log.i(TAG, "✓ MessageRetryWorker scheduled")

            Log.i(TAG, "All background services initialized successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start services on boot", e)
        }
    }
}
