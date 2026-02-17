package com.securelegion.utils

import android.content.Context
import android.content.SharedPreferences
import android.util.Log

/**
 * Migrate old single-ping storage format to new queue-based format
 */
object PendingPingMigration {
    private const val TAG = "PendingPingMigration"
    private const val MIGRATION_PREF_KEY = "pending_ping_migration_v1_done"

    /**
     * Migrate old pending ping storage to new queue format (one-time operation)
     */
    fun migrateIfNeeded(context: Context) {
        val prefs = context.getSharedPreferences("pending_pings", Context.MODE_PRIVATE)

        // Check if migration already done
        if (prefs.getBoolean(MIGRATION_PREF_KEY, false)) {
            return
        }

        Log.i(TAG, "Starting pending ping migration from old format to queue format...")

        try {
            val allKeys = prefs.all.keys
            val contactIds = mutableSetOf<Long>()

            // Find all contactIds that have old-format pings
            allKeys.forEach { key ->
                if (key.startsWith("ping_") && key.endsWith("_id")) {
                    // Extract contactId from "ping_123_id"
                    val parts = key.split("_")
                    if (parts.size == 3) {
                        val contactId = parts[1].toLongOrNull()
                        if (contactId != null) {
                            contactIds.add(contactId)
                        }
                    }
                }
            }

            Log.i(TAG, "Found ${contactIds.size} contacts with old-format pending pings")

            // Migrate each contact's pending ping
            contactIds.forEach { contactId ->
                migrateContactPing(prefs, contactId)
            }

            // Mark migration as complete
            prefs.edit().putBoolean(MIGRATION_PREF_KEY, true).apply()
            Log.i(TAG, "Migration complete")

        } catch (e: Exception) {
            Log.e(TAG, "Migration failed (non-critical)", e)
            // Mark as done anyway to avoid repeated failures
            prefs.edit().putBoolean(MIGRATION_PREF_KEY, true).apply()
        }
    }

    private fun migrateContactPing(prefs: SharedPreferences, contactId: Long) {
        try {
            // Read old format
            val pingId = prefs.getString("ping_${contactId}_id", null) ?: return
            val connectionId = prefs.getLong("ping_${contactId}_connection", -1L)
            val senderName = prefs.getString("ping_${contactId}_name", "Unknown") ?: "Unknown"
            val timestamp = prefs.getLong("ping_${contactId}_timestamp", System.currentTimeMillis())
            val encryptedPingData = prefs.getString("ping_${contactId}_data", null) ?: return
            val senderOnionAddress = prefs.getString("ping_${contactId}_onion", null) ?: return

            Log.d(TAG, "Migrating ping $pingId for contact $contactId")

            // Create PendingPing object
            val pendingPing = com.securelegion.models.PendingPing(
                pingId = pingId,
                connectionId = connectionId,
                senderName = senderName,
                timestamp = timestamp,
                encryptedPingData = encryptedPingData,
                senderOnionAddress = senderOnionAddress
            )

            // Add to queue (will handle deduplication)
            com.securelegion.models.PendingPing.addToQueue(prefs, contactId, pendingPing)

            // Clean up old keys
            prefs.edit().apply {
                remove("ping_${contactId}_id")
                remove("ping_${contactId}_connection")
                remove("ping_${contactId}_name")
                remove("ping_${contactId}_timestamp")
                remove("ping_${contactId}_data")
                remove("ping_${contactId}_onion")
                remove("ping_${contactId}_sender") // Legacy key
                apply()
            }

            Log.i(TAG, "Migrated ping $pingId for contact $contactId")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to migrate ping for contact $contactId", e)
        }
    }
}
