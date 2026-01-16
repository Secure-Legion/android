package com.securelegion.utils

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import java.io.File

/**
 * Utility to detect if an account already exists on this device
 * Used before account import to prevent data collision
 */
object AccountDetector {
    private const val TAG = "AccountDetector"

    /**
     * Check if an account already exists on this device
     * Returns true if ANY of the following exist:
     * - KeyManager has stored seed phrase
     * - Database file exists
     * - Tor hidden service hostname file exists
     */
    fun accountExists(context: Context): Boolean {
        val keyManager = KeyManager.getInstance(context)

        // Check 1: KeyManager has seed phrase
        val hasSeedPhrase = try {
            val seedPhrase = keyManager.getSeedPhrase()
            seedPhrase != null && seedPhrase.isNotEmpty()
        } catch (e: Exception) {
            Log.d(TAG, "No seed phrase found: ${e.message}")
            false
        }

        // Check 2: Database exists
        val dbFile = context.getDatabasePath("secure_legion.db")
        val hasDatabase = dbFile.exists()

        // Check 3: Tor hidden service exists
        val hostnameFile = File(context.filesDir, "tor/hs/hostname")
        val hasHiddenService = hostnameFile.exists()

        val exists = hasSeedPhrase || hasDatabase || hasHiddenService
        Log.d(TAG, "Account exists check: seedPhrase=$hasSeedPhrase, database=$hasDatabase, hiddenService=$hasHiddenService -> $exists")

        return exists
    }

    /**
     * Get current account info for display (username, onion, PIN)
     * Returns null if account data is incomplete or inaccessible
     */
    fun getCurrentAccountInfo(context: Context): AccountInfo? {
        val keyManager = KeyManager.getInstance(context)
        return try {
            val username = keyManager.getUsername()
            val onion = keyManager.getMessagingOnion()
            val contactPin = keyManager.getContactPin()

            if (username != null && onion != null) {
                AccountInfo(
                    username = username,
                    onion = onion,
                    contactPin = contactPin ?: "Unknown"
                )
            } else {
                Log.d(TAG, "Account info incomplete: username=$username, onion=$onion")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get account info", e)
            null
        }
    }
}

/**
 * Basic account information for display purposes
 */
data class AccountInfo(
    val username: String,
    val onion: String,
    val contactPin: String
)
