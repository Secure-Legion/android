package com.securelegion.receivers

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.securelegion.SecureRuntime

/**
 * Triggers post-unlock initialization when the user unlocks the device for the
 * first time after boot, in cases where the app process is alive but no Activity
 * has been started yet (e.g., woken by JobScheduler/WorkManager/GCM during
 * pre-unlock direct-boot).
 *
 * Without this, headless wake paths would leave [SecureRuntime] uninitialized
 * until the user manually opens the app. With this, Tor auto-start kicks in the
 * moment the device is unlocked.
 *
 * Registered in AndroidManifest.xml. Runs in main process. Idempotent via
 * [SecureRuntime.initializeAfterUnlock]'s flag guards.
 */
class UnlockReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "UnlockReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_USER_UNLOCKED == intent.action) {
            Log.i(TAG, "User unlocked — triggering SecureRuntime init")
            SecureRuntime.initializeAfterUnlock(context)
        }
    }
}
