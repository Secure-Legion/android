package com.securelegion.utils

import android.content.Context
import android.content.SharedPreferences

/**
 * SessionManager - Tracks whether the app is currently unlocked
 *
 * The app is considered "unlocked" when the user has successfully
 * entered their password in LockActivity and is using the app.
 *
 * The app is considered "locked" when:
 * - User hasn't unlocked yet (on LockActivity)
 * - Auto-lock timer expired
 * - User manually locked the app
 */
object SessionManager {
    private const val PREFS_NAME = "session"
    private const val KEY_IS_UNLOCKED = "is_unlocked"

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * Mark the app as unlocked (user successfully authenticated)
     */
    fun setUnlocked(context: Context) {
        getPrefs(context).edit()
            .putBoolean(KEY_IS_UNLOCKED, true)
            .apply()
    }

    /**
     * Mark the app as locked (user on lock screen or auto-lock triggered)
     */
    fun setLocked(context: Context) {
        getPrefs(context).edit()
            .putBoolean(KEY_IS_UNLOCKED, false)
            .apply()
    }

    /**
     * Check if the app is currently unlocked
     * Returns true if user has authenticated and is using the app
     */
    fun isUnlocked(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_IS_UNLOCKED, false)
    }

    /**
     * Check if the app is currently locked
     * Returns true if user needs to authenticate
     */
    fun isLocked(context: Context): Boolean {
        return !isUnlocked(context)
    }
}
