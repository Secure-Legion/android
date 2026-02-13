package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.utils.BadgeUtils

/**
 * Base activity for all activities that include bottom navigation
 * Automatically updates the friend request badge on resume
 * Implements auto-lock timer functionality
 */
abstract class BaseActivity : AppCompatActivity() {

    companion object {
        private const val PREF_LAST_PAUSE_TIME = "last_pause_timestamp"
        private const val PREFS_NAME = "app_lifecycle"
        private const val TAG = "BaseActivity"

        // Shared flag to track if we're navigating within the app
        @Volatile
        private var isNavigatingWithinApp = false
    }

    private val autoLockHandler = Handler(Looper.getMainLooper())
    private var autoLockRunnable: Runnable? = null
    private var isLaunchingActivity = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording app-wide
        // TODO: Re-enable FLAG_SECURE after demo recording
        // window.setFlags(
        //     WindowManager.LayoutParams.FLAG_SECURE,
        //     WindowManager.LayoutParams.FLAG_SECURE
        // )
    }

    override fun onResume() {
        super.onResume()

        // Clear the within-app navigation flag
        isNavigatingWithinApp = false

        // Clear any old pause timestamp to prevent legacy lock behavior
        val lifecyclePrefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        lifecyclePrefs.edit().remove(PREF_LAST_PAUSE_TIME).apply()

        // DISABLED: Don't lock based on time away from app - only use inactivity timer
        // checkAutoLock()
        startAutoLockTimer()
        updateFriendRequestBadge()
    }

    override fun onPause() {
        super.onPause()
        cancelAutoLockTimer()

        // DISABLED: Don't record pause time - we only lock based on inactivity timer now
        // The app will only lock after X minutes of inactivity, not when switching apps

        // Reset flag
        isLaunchingActivity = false
    }

    override fun onDestroy() {
        super.onDestroy()
        cancelAutoLockTimer()
    }

    /**
     * Reset auto-lock timer on any user interaction (touch, scroll, type, etc.)
     * This ensures the timer only expires after X minutes of INACTIVITY
     */
    override fun onUserInteraction() {
        super.onUserInteraction()

        // Reset the timer whenever user interacts with the app
        startAutoLockTimer()
    }

    /**
     * Start auto-lock timer that will lock the app after configured timeout
     */
    private fun startAutoLockTimer() {
        // Don't start timer if we're on certain activities
        if (this is LockActivity ||
            this is CreateAccountActivity ||
            this is AccountCreatedActivity ||
            this is RestoreAccountActivity ||
            this is SplashActivity ||
            this is WelcomeActivity) {
            return
        }

        val securityPrefs = getSharedPreferences("security", MODE_PRIVATE)
        val autoLockTimeout = securityPrefs.getLong(
            AutoLockActivity.PREF_AUTO_LOCK_TIMEOUT,
            AutoLockActivity.DEFAULT_TIMEOUT
        )

        // If timeout is set to "Never", don't start timer
        if (autoLockTimeout == AutoLockActivity.TIMEOUT_NEVER) {
            return
        }

        // Cancel any existing timer
        val wasTimerRunning = autoLockRunnable != null
        cancelAutoLockTimer()

        // Create and schedule new timer
        autoLockRunnable = Runnable {
            Log.i(TAG, "Auto-lock timer expired after inactivity - locking app")
            lockApp()
        }

        autoLockHandler.postDelayed(autoLockRunnable!!, autoLockTimeout)

        if (wasTimerRunning) {
            Log.d(TAG, "Auto-lock timer RESET due to user activity: ${autoLockTimeout}ms")
        } else {
            Log.d(TAG, "Auto-lock timer started: ${autoLockTimeout}ms")
        }
    }

    /**
     * Cancel the auto-lock timer
     */
    private fun cancelAutoLockTimer() {
        autoLockRunnable?.let {
            autoLockHandler.removeCallbacks(it)
            autoLockRunnable = null
            Log.d(TAG, "Auto-lock timer cancelled")
        }
    }

    /**
     * Check if auto-lock should be triggered based on inactivity time
     * This is a safety check when returning from background
     */
    private fun checkAutoLock() {
        // Don't lock if we're already on the LockActivity
        if (this is LockActivity) {
            return
        }

        // Don't lock if we're on CreateAccountActivity or related account creation screens
        if (this is CreateAccountActivity ||
            this is AccountCreatedActivity ||
            this is RestoreAccountActivity ||
            this is SplashActivity ||
            this is WelcomeActivity) {
            return
        }

        val securityPrefs = getSharedPreferences("security", MODE_PRIVATE)
        val autoLockTimeout = securityPrefs.getLong(
            AutoLockActivity.PREF_AUTO_LOCK_TIMEOUT,
            AutoLockActivity.DEFAULT_TIMEOUT
        )

        // If timeout is set to "Never", skip auto-lock
        if (autoLockTimeout == AutoLockActivity.TIMEOUT_NEVER) {
            return
        }

        val lifecyclePrefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val lastPauseTime = lifecyclePrefs.getLong(PREF_LAST_PAUSE_TIME, 0L)

        // If we have a recorded pause time, check if timeout exceeded
        if (lastPauseTime > 0L) {
            val currentTime = System.currentTimeMillis()
            val elapsedTime = currentTime - lastPauseTime

            if (elapsedTime >= autoLockTimeout) {
                // Lock the app
                lockApp()
            }
        }
    }

    /**
     * Lock the app by navigating to LockActivity
     */
    private fun lockApp() {
        // Mark app as locked
        com.securelegion.utils.SessionManager.setLocked(this)
        Log.i(TAG, "App locked - session ended")

        val intent = Intent(this, LockActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }

    /**
     * Record the time when app goes to background
     */
    private fun recordPauseTime() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        prefs.edit().apply {
            putLong(PREF_LAST_PAUSE_TIME, System.currentTimeMillis())
            apply()
        }
    }

    /**
     * Update the friend request badge count on the Add Friend navigation icon
     * Automatically called in onResume()
     */
    private fun updateFriendRequestBadge() {
        val rootView = findViewById<View>(android.R.id.content)
        BadgeUtils.updateFriendRequestBadge(this, rootView)
    }

    /**
     * Override startActivity to mark that we're launching an activity within the app
     * This prevents auto-lock from triggering when returning from payment/photo activities
     */
    override fun startActivity(intent: Intent?) {
        intent?.let {
            // Check if this is an intent to another activity in our app
            if (it.component?.packageName == packageName) {
                isLaunchingActivity = true
                isNavigatingWithinApp = true
                Log.d(TAG, "Launching activity within app - pause time will not be recorded")
            }
        }
        super.startActivity(intent)
    }

    override fun startActivity(intent: Intent?, options: Bundle?) {
        intent?.let {
            // Check if this is an intent to another activity in our app
            if (it.component?.packageName == packageName) {
                isLaunchingActivity = true
                isNavigatingWithinApp = true
                Log.d(TAG, "Launching activity within app - pause time will not be recorded")
            }
        }
        super.startActivity(intent, options)
    }
}
