package com.securelegion

import android.content.Intent
import android.view.View
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
    }

    override fun onResume() {
        super.onResume()
        checkAutoLock()
        updateFriendRequestBadge()
    }

    override fun onPause() {
        super.onPause()
        recordPauseTime()
    }

    /**
     * Check if auto-lock should be triggered based on inactivity time
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
            this is SplashActivity) {
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
                val intent = Intent(this, LockActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                startActivity(intent)
                finish()
            }
        }
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
}
