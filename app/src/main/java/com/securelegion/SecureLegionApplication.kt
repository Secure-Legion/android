package com.securelegion

import android.app.Activity
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Application class for Secure Legion
 *
 * Handles:
 * - Tor network initialization on app startup
 * - Global app-level initialization
 * - App lifecycle tracking for auto-lock on background
 */
class SecureLegionApplication : Application() {

    companion object {
        private const val TAG = "SecureLegionApp"

        // Notification channel IDs
        const val CHANNEL_ID_CALLS = "voice_calls"

        // Track if app is in background
        private var isInBackground = false

        // Track current foreground activity
        private var currentActivity: Activity? = null

        // IPtProxy removed — Arti handles Tor in-process
    }

    override fun onCreate() {
        // super FIRST — no logic before super.onCreate() because anything that touches
        // Credential Encrypted (CE) storage in pre-super space crashes during direct-boot
        // (Android calls Application.onCreate before the user has unlocked).
        // Theme mode application moved to BaseActivity.applyThemeFromPrefs().
        super.onCreate()

        // CRITICAL: Check if we're in the main process. Skip ALL init in non-main processes.
        val processName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getProcessName()
        } else {
            try {
                val pid = android.os.Process.myPid()
                val am = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
                am.runningAppProcesses?.find { it.pid == pid }?.processName
            } catch (e: Exception) { null }
        }
        if (processName != null && processName != packageName) {
            Log.d(TAG, "Skipping initialization in non-main process: $processName")
            return
        }

        Log.d(TAG, "Application starting (boot-safe phase)...")

        // BOOT-SAFE ONLY in this method. No SharedPreferences, no KeyManager, no Tor,
        // no IPFS, no DB, no filesDir reads. Anything CE-encrypted is deferred to
        // SecureRuntime.initializeAfterUnlock(), invoked from the first entry-point
        // Activity (BaseActivity / Splash / Lock) AND from UnlockReceiver on
        // ACTION_USER_UNLOCKED for headless/background wake paths.
        createNotificationChannels()
        registerLifecycleObserver()

        // If the user is already unlocked at process attach (warm app open, not boot
        // wake), run the post-unlock init right now — saves the activity ~one tick.
        if (androidx.core.os.UserManagerCompat.isUserUnlocked(this)) {
            SecureRuntime.initializeAfterUnlock(this)
        } else {
            Log.i(TAG, "User locked — deferring sensitive init until ACTION_USER_UNLOCKED or first activity")
        }
    }

    /**
     * Register lifecycle observer to lock app when backgrounded
     * DISABLED: We now only use inactivity timer in BaseActivity, not immediate lock on background
     */
    private fun registerLifecycleObserver() {
        // DISABLED: Don't lock immediately when app backgrounds
        // Only use the inactivity timer in BaseActivity (lock after X minutes of no interaction)
        /*
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                // App went to background
                Log.w(TAG, "App went to background - locking")
                isInBackground = true
            }

            override fun onStart(owner: LifecycleOwner) {
                // App came to foreground
                if (isInBackground) {
                    Log.w(TAG, "App returned to foreground - redirecting to lock screen")
                    isInBackground = false

                    // Get current activity and redirect to lock screen
                    val activity = currentActivity
                    if (activity != null && activity !is LockActivity && activity !is SplashActivity) {
                        Log.w(TAG, "Current activity: ${activity.javaClass.simpleName} - launching LockActivity")
                        val intent = Intent(activity, LockActivity::class.java)
                        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                        activity.startActivity(intent)
                        activity.finish()
                    }
                }
            }
        })
        */

        // Track current foreground activity
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                activity.requestedOrientation = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
                activity.window.setFlags(
                    android.view.WindowManager.LayoutParams.FLAG_SECURE,
                    android.view.WindowManager.LayoutParams.FLAG_SECURE
                )
            }
            override fun onActivityStarted(activity: Activity) {}

            override fun onActivityResumed(activity: Activity) {
                currentActivity = activity
                Log.d(TAG, "Activity resumed: ${activity.javaClass.simpleName}")
            }

            override fun onActivityPaused(activity: Activity) {
                if (currentActivity == activity) {
                    Log.d(TAG, "Activity paused: ${activity.javaClass.simpleName}")
                }
            }

            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}

            override fun onActivityDestroyed(activity: Activity) {
                if (currentActivity == activity) {
                    currentActivity = null
                }
            }
        })

        Log.d(TAG, "Lifecycle observer registered for auto-lock")
    }

    /**
     * Create notification channels for Android 8.0+
     */
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(NotificationManager::class.java)

            // Voice calls notification channel
            val callsChannel = NotificationChannel(
                CHANNEL_ID_CALLS,
                "Voice Calls",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications for incoming calls and missed calls"
                enableVibration(true)
                setShowBadge(true)
            }

            notificationManager.createNotificationChannel(callsChannel)
            Log.d(TAG, "Notification channels created")
        }
    }

}
