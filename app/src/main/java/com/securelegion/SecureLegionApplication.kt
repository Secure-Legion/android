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
import com.securelegion.crypto.TorManager
import IPtProxy.Controller
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

        // IPtProxy controller for pluggable transports (shared across app)
        lateinit var iptProxyController: Controller
            private set
    }

    override fun onCreate() {
        super.onCreate()

        // CRITICAL: Check if we're in the main process
        // When GP TorService runs in android:process=":tor", Android creates a new
        // SecureLegionApplication instance in that process. We must skip ALL initialization
        // in non-main processes to avoid: conflicting IPtProxy ports, duplicate Tor startup,
        // duplicate IPFS init, and potential exit(1) from Go/native runtime conflicts.
        val processName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getProcessName()
        } else {
            // Fallback for API 27
            try {
                val pid = android.os.Process.myPid()
                val am = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
                am.runningAppProcesses?.find { it.pid == pid }?.processName
            } catch (e: Exception) {
                null
            }
        }
        if (processName != null && processName != packageName) {
            Log.d(TAG, "Skipping initialization in non-main process: $processName")
            return
        }

        Log.d(TAG, "Application starting...")

        // Create notification channels
        createNotificationChannels()

        // Initialize IPtProxy controller for pluggable transports
        // This MUST be done before any bridge configuration
        try {
            val ptStateDir = File(cacheDir, "pt_state")
            ptStateDir.mkdirs()
            iptProxyController = Controller(ptStateDir.absolutePath, true, false, "INFO", null)
            Log.d(TAG, "IPtProxy Controller initialized at: ${ptStateDir.absolutePath}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize IPtProxy Controller", e)
        }

        // Register lifecycle observer for auto-lock on background
        registerLifecycleObserver()

        // Initialize Tor network
        // Skip auto-start on first launch so user can configure bridges first
        // Skip auto-start if we recently shut down (restart storm suppression)
        try {
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            if (keyManager.isInitialized()) {
                // Check for restart storm: if last shutdown was within 30s, skip auto-start
                // SplashActivity will handle Tor init when user opens the app
                val shutdownFile = File(filesDir, "tor/last_shutdown_time")
                val recentShutdown = try {
                    if (shutdownFile.exists()) {
                        val lastShutdown = shutdownFile.readText().trim().toLongOrNull() ?: 0L
                        val elapsed = System.currentTimeMillis() - lastShutdown
                        elapsed in 1..30_000
                    } else false
                } catch (e: Exception) { false }

                if (recentShutdown) {
                    Log.w(TAG, "Tor shutdown was within last 30s - suppressing auto-start to prevent restart storm")
                } else {
                    Log.d(TAG, "Existing account - auto-starting Tor...")
                    initializeTor()
                    Log.d(TAG, "Tor initialization started")
                }
            } else {
                Log.i(TAG, "First-time setup - skipping Tor auto-start (user will press Start)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Tor", e)
        }

        // Initialize IPFS Manager for auto-pinning mesh (v5 architecture)
        try {
            Log.d(TAG, "Initializing IPFS Manager...")
            CoroutineScope(Dispatchers.IO).launch {
                val ipfsManager = com.securelegion.services.IPFSManager.getInstance(this@SecureLegionApplication)
                val result = ipfsManager.initialize()
                if (result.isSuccess) {
                    Log.i(TAG, "IPFS Manager initialized successfully")
                } else {
                    Log.e(TAG, "IPFS Manager initialization failed: ${result.exceptionOrNull()?.message}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize IPFS Manager", e)
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
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
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

    private fun initializeTor() {
        val torManager = TorManager.getInstance(this)

        // Initialize Tor asynchronously (this takes a few seconds)
        torManager.initializeAsync { success, onionAddress ->
            if (success && onionAddress != null) {
                Log.i(TAG, "Tor initialized successfully")
                Log.i(TAG, "Our .onion address initialized")
            } else {
                Log.e(TAG, "Tor initialization failed!")
            }
        }
    }
}
