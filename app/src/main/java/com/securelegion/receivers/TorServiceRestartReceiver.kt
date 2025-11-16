package com.securelegion.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.securelegion.services.TorService

/**
 * BroadcastReceiver that restarts TorService via AlarmManager
 *
 * This provides redundancy beyond START_STICKY for devices with
 * aggressive battery optimization (Xiaomi, Huawei, Oppo, etc.)
 */
class TorServiceRestartReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "TorServiceRestart"
    }

    override fun onReceive(context: Context, intent: Intent) {
        Log.i(TAG, "AlarmManager triggered - checking TorService status")

        // Check if service is actually running
        if (!TorService.isRunning()) {
            Log.w(TAG, "TorService not running - restarting now")
            try {
                TorService.start(context)
                Log.i(TAG, "TorService restarted successfully via AlarmManager")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to restart TorService", e)
            }
        } else {
            Log.d(TAG, "TorService already running - no action needed")
        }
    }
}
