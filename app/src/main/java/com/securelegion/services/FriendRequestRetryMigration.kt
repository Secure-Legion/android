package com.securelegion.services

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.PendingFriendRequest as PendingFriendRequestEntity
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * One-time, non-destructive migration from legacy SharedPreferences friend-request state
 * to Room retry records. This helper NEVER deletes legacy data.
 */
object FriendRequestRetryMigration {
    private const val TAG = "FriendReqMigration"
    private const val LEGACY_PREFS = "friend_requests"
    private const val LEGACY_KEY = "pending_requests_v2"
    private const val MAP_PREFS = "friend_request_retry_map"
    private const val MIGRATION_PREFS = "friend_request_migration"
    private const val DONE_KEY = "prefs_to_room_done_v1"
    private const val SNAPSHOT_KEY = "legacy_snapshot_v1"

    private val lock = Mutex()

    suspend fun runIfNeeded(context: Context) {
        lock.withLock {
            val migrationPrefs = context.getSharedPreferences(MIGRATION_PREFS, Context.MODE_PRIVATE)
            if (migrationPrefs.getBoolean(DONE_KEY, false)) return

            try {
                val legacyPrefs = context.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE)
                val legacySet = legacyPrefs.getStringSet(LEGACY_KEY, emptySet())?.toSet() ?: emptySet()

                // Safety snapshot of legacy payload before any DB writes.
                migrationPrefs.edit().putStringSet(SNAPSHOT_KEY, legacySet).apply()

                val keyManager = KeyManager.getInstance(context)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
                val dao = database.pendingFriendRequestDao()
                val mapPrefs = context.getSharedPreferences(MAP_PREFS, Context.MODE_PRIVATE)
                val now = System.currentTimeMillis()

                var inserted = 0
                var skipped = 0

                for (json in legacySet) {
                    val req = try {
                        com.securelegion.models.PendingFriendRequest.fromJson(json)
                    } catch (_: Exception) {
                        skipped++
                        continue
                    }

                    // Retry worker only handles outgoing phases.
                    if (req.direction != com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING) {
                        skipped++
                        continue
                    }

                    val recipientOnion = req.ipfsCid.trim()
                    if (recipientOnion.isEmpty()) {
                        skipped++
                        continue
                    }

                    // Dedup: preserve existing active row.
                    val existing = dao.getByRecipientOnion(recipientOnion)
                    if (existing != null && !existing.isCompleted && !existing.isFailed) {
                        if (req.id.isNotBlank()) {
                            mapPrefs.edit().putLong(req.id, existing.id).apply()
                        }
                        skipped++
                        continue
                    }

                    val payload = req.contactCardJson
                    val isPhase1Payload = payload?.let { looksLikePhase1Payload(it) } == true
                    val phase = if (isPhase1Payload) {
                        PendingFriendRequestEntity.PHASE_1_SENT
                    } else {
                        PendingFriendRequestEntity.PHASE_2_SENT
                    }

                    // Conservative migration: copy state, but don't force retries for legacy
                    // records that may be missing required retry material (like PIN/plaintext).
                    val entity = PendingFriendRequestEntity(
                        recipientOnion = recipientOnion,
                        phase = phase,
                        direction = PendingFriendRequestEntity.DIRECTION_OUTGOING,
                        needsRetry = false,
                        isCompleted = false,
                        isFailed = false,
                        nextRetryAt = 0L,
                        retryCount = 0,
                        phase1PayloadJson = if (isPhase1Payload) payload else null,
                        contactCardJson = payload,
                        createdAt = req.timestamp.takeIf { it > 0 } ?: now
                    )

                    val dbId = dao.insertRequest(entity)
                    if (req.id.isNotBlank()) {
                        mapPrefs.edit().putLong(req.id, dbId).apply()
                    }
                    inserted++
                }

                migrationPrefs.edit()
                    .putBoolean(DONE_KEY, true)
                    .putLong("completed_at_ms", now)
                    .putInt("inserted_count", inserted)
                    .putInt("skipped_count", skipped)
                    .apply()

                Log.i(TAG, "Legacy friend-request migration complete: inserted=$inserted, skipped=$skipped")
            } catch (e: Exception) {
                Log.e(TAG, "Legacy friend-request migration failed; will retry later", e)
            }
        }
    }

    private fun looksLikePhase1Payload(payload: String): Boolean {
        return try {
            val obj = org.json.JSONObject(payload)
            val phase = obj.optInt("phase", -1)
            phase == 1 || (obj.has("username") && obj.has("friend_request_onion") && obj.has("x25519_public_key"))
        } catch (_: Exception) {
            false
        }
    }
}
