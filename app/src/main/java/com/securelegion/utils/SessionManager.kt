package com.securelegion.utils

import android.content.Context
import java.util.concurrent.atomic.AtomicBoolean

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
    // Never persist authentication state. A new process always starts locked,
    // and notification intents must route through the real unlock flow.
    private val unlocked = AtomicBoolean(false)

    /**
     * Mark the app as unlocked (user successfully authenticated)
     */
    fun setUnlocked(@Suppress("UNUSED_PARAMETER") context: Context) {
        unlocked.set(true)
    }

    /**
     * Mark the app as locked (user on lock screen or auto-lock triggered)
     */
    fun setLocked(@Suppress("UNUSED_PARAMETER") context: Context) {
        unlocked.set(false)
    }

    /**
     * Check if the app is currently unlocked
     * Returns true if user has authenticated and is using the app
     */
    fun isUnlocked(@Suppress("UNUSED_PARAMETER") context: Context): Boolean {
        return unlocked.get()
    }

    /**
     * Check if the app is currently locked
     * Returns true if user needs to authenticate
     */
    fun isLocked(context: Context): Boolean {
        return !isUnlocked(context)
    }
}
