package com.securelegion.models

import org.json.JSONArray
import org.json.JSONObject

/**
 * State machine for pending ping downloads
 */
enum class PingState {
    PENDING, // Waiting to download (shows "Download" button)
    DOWNLOADING, // Fetching message via Tor from sender's .onion (shows "Downloading...")
    DECRYPTING, // Decrypting message blob with X25519 (shows "Decrypting...")
    READY // Fully processed, ready to swap to message atomically
}

/**
 * Represents a pending Ping waiting to be downloaded
 */
data class PendingPing(
    val pingId: String,
    val connectionId: Long,
    val senderName: String,
    val timestamp: Long,
    val encryptedPingData: String, // Base64 encoded encrypted ping wire bytes
    val senderOnionAddress: String,
    val state: PingState = PingState.PENDING // Current state in download pipeline
) {
    companion object {
        fun fromJson(json: String): PendingPing {
            val obj = JSONObject(json)

            // Parse state with backward compatibility (default to PENDING if not present)
            val stateStr = obj.optString("state", "PENDING")
            val state = try {
                PingState.valueOf(stateStr)
            } catch (e: IllegalArgumentException) {
                PingState.PENDING
            }

            return PendingPing(
                pingId = obj.getString("pingId"),
                connectionId = obj.getLong("connectionId"),
                senderName = obj.getString("senderName"),
                timestamp = obj.getLong("timestamp"),
                encryptedPingData = obj.getString("encryptedPingData"),
                senderOnionAddress = obj.getString("senderOnionAddress"),
                state = state
            )
        }

        /**
         * Load all pending pings for a contact from ping_inbox database (SOURCE OF TRUTH)
         * Falls back to SharedPreferences for backward compatibility during migration
         * @param database The SecureLegionDatabase instance
         * @param prefs SharedPreferences for fallback/cache
         * @param contactId The contact ID
         * @return List of pending pings (state < MSG_STORED)
         */
        suspend fun loadQueueFromDatabase(
            database: com.securelegion.database.SecureLegionDatabase,
            prefs: android.content.SharedPreferences,
            contactId: Long
        ): List<PendingPing> {
            return try {
                // PRIMARY SOURCE: ping_inbox table (durable, restart-safe)
                val pingInboxEntries = database.pingInboxDao().getPendingByContact(
                    contactId = contactId,
                    msgStoredState = com.securelegion.database.entities.PingInbox.STATE_MSG_STORED
                )

                if (pingInboxEntries.isEmpty()) {
                    // No pending pings in database - return empty
                    android.util.Log.d("PendingPing", "No pending pings in database for contact $contactId")
                    return emptyList()
                }

                android.util.Log.i("PendingPing", "Loaded ${pingInboxEntries.size} pending pings from database (source of truth)")

                // Convert ping_inbox entries to PendingPing objects
                // We need to reconstruct the full PendingPing from stored data
                val pendingPings = mutableListOf<PendingPing>()

                for (entry in pingInboxEntries) {
                    // Try to load full details from SharedPreferences cache first
                    val cachedQueue = loadQueueForContact(prefs, contactId)
                    val cached = cachedQueue.find { it.pingId == entry.pingId }

                    if (cached != null) {
                        // Use cached version (has all fields)
                        pendingPings.add(cached)
                        android.util.Log.d("PendingPing", "Using cached data for ping ${entry.pingId.take(8)}")
                    } else {
                        // Cache miss - reconstruct from what we have
                        // This can happen after app data clear or first launch after DB migration
                        android.util.Log.w("PendingPing", "Cache miss for ping ${entry.pingId.take(8)} - needs re-download")

                        // We can't fully reconstruct without the encrypted ping wire bytes,
                        // so we'll need to wait for sender to retry the PING
                        // For now, skip this entry (sender will retry and repopulate)
                    }
                }

                // Sync database state back to SharedPreferences cache
                saveQueueForContact(prefs, contactId, pendingPings, synchronous = true)

                pendingPings
            } catch (e: Exception) {
                android.util.Log.e("PendingPing", "Failed to load from database, falling back to SharedPreferences", e)
                // Fallback to SharedPreferences on error
                loadQueueForContact(prefs, contactId)
            }
        }

        /**
         * Load all pending pings for a contact from SharedPreferences (LEGACY/CACHE)
         * Use loadQueueFromDatabase() for restart-safe, database-backed loading
         */
        fun loadQueueForContact(prefs: android.content.SharedPreferences, contactId: Long): List<PendingPing> {
            val queueJson = prefs.getString("ping_queue_$contactId", null) ?: return emptyList()

            return try {
                val jsonArray = JSONArray(queueJson)
                val queue = mutableListOf<PendingPing>()

                for (i in 0 until jsonArray.length()) {
                    val pingJson = jsonArray.getString(i)
                    queue.add(fromJson(pingJson))
                }

                queue
            } catch (e: Exception) {
                android.util.Log.e("PendingPing", "Failed to load ping queue", e)
                emptyList()
            }
        }

        /**
         * Save all pending pings for a contact to SharedPreferences
         */
        fun saveQueueForContact(prefs: android.content.SharedPreferences, contactId: Long, queue: List<PendingPing>, synchronous: Boolean = false) {
            val jsonArray = JSONArray()
            queue.forEach { ping ->
                jsonArray.put(ping.toJson())
            }

            val editor = prefs.edit().putString("ping_queue_$contactId", jsonArray.toString())
            if (synchronous) {
                editor.commit() // Synchronous write for immediate consistency
            } else {
                editor.apply() // Async write for better performance
            }
        }

        /**
         * Add a pending ping to the queue for a contact
         */
        fun addToQueue(prefs: android.content.SharedPreferences, contactId: Long, ping: PendingPing) {
            val queue = loadQueueForContact(prefs, contactId).toMutableList()

            // Check if this ping already exists (deduplication by ping ID OR encrypted content)
            // This prevents ghost pings when sender retries with different ping IDs but same message
            if (queue.any { it.pingId == ping.pingId }) {
                android.util.Log.w("PendingPing", "Ping ${ping.pingId} already in queue - skipping")
                return
            }

            if (queue.any { it.encryptedPingData == ping.encryptedPingData }) {
                android.util.Log.w("PendingPing", "Ping ${ping.pingId.take(8)} has duplicate message content (sender retry) - skipping")
                return
            }

            queue.add(ping)
            saveQueueForContact(prefs, contactId, queue)
            android.util.Log.i("PendingPing", "Added ping ${ping.pingId} to queue (total: ${queue.size})")
        }

        /**
         * Update the state of a specific ping in the queue
         */
        fun updateState(prefs: android.content.SharedPreferences, contactId: Long, pingId: String, newState: PingState, synchronous: Boolean = true) {
            val queue = loadQueueForContact(prefs, contactId).toMutableList()
            val index = queue.indexOfFirst { it.pingId == pingId }
            if (index >= 0) {
                queue[index] = queue[index].copy(state = newState)
                saveQueueForContact(prefs, contactId, queue, synchronous)
                android.util.Log.i("PendingPing", "Updated ping $pingId state to $newState")
            } else {
                android.util.Log.w("PendingPing", "Ping $pingId not found in queue for state update")
            }
        }

        /**
         * Remove a specific ping from the queue
         */
        fun removeFromQueue(prefs: android.content.SharedPreferences, contactId: Long, pingId: String, synchronous: Boolean = false) {
            val queue = loadQueueForContact(prefs, contactId).toMutableList()
            queue.removeAll { it.pingId == pingId }
            saveQueueForContact(prefs, contactId, queue, synchronous)
            android.util.Log.i("PendingPing", "Removed ping $pingId from queue (remaining: ${queue.size})")
        }

        /**
         * Clear all pending pings for a contact
         */
        fun clearQueueForContact(prefs: android.content.SharedPreferences, contactId: Long) {
            prefs.edit().remove("ping_queue_$contactId").apply()
            android.util.Log.i("PendingPing", "Cleared all pending pings for contact $contactId")
        }
    }

    fun toJson(): String {
        return JSONObject().apply {
            put("pingId", pingId)
            put("connectionId", connectionId)
            put("senderName", senderName)
            put("timestamp", timestamp)
            put("encryptedPingData", encryptedPingData)
            put("senderOnionAddress", senderOnionAddress)
            put("state", state.name)
        }.toString()
    }
}
