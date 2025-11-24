package com.securelegion

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.securelegion.crypto.TorManager
import IPtProxy.Controller
import java.io.File

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

        Log.d(TAG, "Application starting...")

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
        try {
            Log.d(TAG, "About to initialize Tor...")
            initializeTor()
            Log.d(TAG, "Tor initialization started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Tor", e)
        }
    }

    /**
     * Register lifecycle observer to lock app when backgrounded
     */
    private fun registerLifecycleObserver() {
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

    private fun initializeTor() {
        val torManager = TorManager.getInstance(this)

        // Initialize Tor asynchronously (this takes a few seconds)
        torManager.initializeAsync { success, onionAddress ->
            if (success && onionAddress != null) {
                Log.i(TAG, "Tor initialized successfully")
                Log.i(TAG, "Our .onion address: $onionAddress")
            } else {
                Log.e(TAG, "Tor initialization failed!")
            }
        }
    }
}
