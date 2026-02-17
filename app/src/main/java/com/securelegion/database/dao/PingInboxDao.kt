package com.securelegion.database.dao

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.PingInbox

data class PendingCountResult(
    @ColumnInfo(name = "contactId") val contactId: Long,
    @ColumnInfo(name = "cnt") val cnt: Int
)

/**
 * DAO for ping inbox state tracking
 *
 * Provides atomic operations for idempotent message delivery over Tor
 */
@Dao
interface PingInboxDao {

    /**
     * Insert a new ping (first seen)
     * Returns the number of rows inserted (1 if new, 0 if duplicate)
     *
     * Use IGNORE strategy so duplicates are safely ignored
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(pingInbox: PingInbox): Long

    /**
     * Get ping state by pingId
     */
    @Query("SELECT * FROM ping_inbox WHERE pingId = :pingId")
    suspend fun getByPingId(pingId: String): PingInbox?

    /**
     * Get all pending locks for a contact (not yet MSG_STORED)
     */
    @Query("SELECT * FROM ping_inbox WHERE contactId = :contactId AND state != :msgStoredState ORDER BY firstSeenAt ASC")
    suspend fun getPendingByContact(contactId: Long, msgStoredState: Int = PingInbox.STATE_MSG_STORED): List<PingInbox>

    /**
     * Get pings that need UI rendering for a contact.
     * Returns states that should show a row in chat:
     * PING_SEEN(0), PONG_SENT(1), DOWNLOAD_QUEUED(10), FAILED_TEMP(11), MANUAL_REQUIRED(12)
     * PONG_SENT included to handle stale entries after logout/login (shows lock icon so user can retry).
     * Excludes MSG_STORED(2) only — those have a real message row in chat.
     */
    @Query("""
        SELECT * FROM ping_inbox
        WHERE contactId = :contactId
        AND state IN (${PingInbox.STATE_PING_SEEN}, ${PingInbox.STATE_PONG_SENT}, ${PingInbox.STATE_DOWNLOAD_QUEUED}, ${PingInbox.STATE_FAILED_TEMP}, ${PingInbox.STATE_MANUAL_REQUIRED})
        ORDER BY firstSeenAt ASC
    """)
    suspend fun getRenderableByContact(contactId: Long): List<PingInbox>

    /**
     * Count pending locks for a contact (not yet MSG_STORED)
     * Uses != instead of state < 2 to handle new states (10, 11, 12) correctly
     */
    @Query("SELECT COUNT(*) FROM ping_inbox WHERE contactId = :contactId AND state != ${PingInbox.STATE_MSG_STORED}")
    suspend fun countPendingByContact(contactId: Long): Int

    /**
     * Count pending locks for ALL contacts in one query
     */
    @Query("SELECT contactId, COUNT(*) as cnt FROM ping_inbox WHERE state != ${PingInbox.STATE_MSG_STORED} GROUP BY contactId")
    suspend fun countPendingPerContact(): List<PendingCountResult>

    /**
     * Get all pending locks across all contacts
     */
    @Query("SELECT * FROM ping_inbox WHERE state != :msgStoredState ORDER BY firstSeenAt ASC")
    suspend fun getAllPending(msgStoredState: Int = PingInbox.STATE_MSG_STORED): List<PingInbox>

    /**
     * Update ping duplicate (received PING again)
     * Updates lastPingAt and attemptCount
     * Only updates if not already MSG_STORED (prevent regression)
     */
    @Query("""
        UPDATE ping_inbox
        SET lastPingAt = :timestamp,
            attemptCount = attemptCount + 1
        WHERE pingId = :pingId
        AND state != :msgStoredState
    """)
    suspend fun updatePingRetry(pingId: String, timestamp: Long, msgStoredState: Int = PingInbox.STATE_MSG_STORED): Int

    /**
     * Transition to PONG_SENT state (user authorized download or auto-download sent PONG)
     * Accepts from both manual path (PING_SEEN=0) and auto path (DOWNLOAD_QUEUED=10)
     * Clears downloadQueuedAt since we're past the claim phase
     */
    @Query("""
        UPDATE ping_inbox
        SET state = ${PingInbox.STATE_PONG_SENT},
            lastUpdatedAt = :timestamp,
            pongSentAt = :timestamp,
            downloadQueuedAt = NULL
        WHERE pingId = :pingId
        AND state IN (${PingInbox.STATE_PING_SEEN}, ${PingInbox.STATE_DOWNLOAD_QUEUED})
    """)
    suspend fun transitionToPongSent(pingId: String, timestamp: Long): Int

    /**
     * Transition to MSG_STORED state (message saved to DB)
     * MONOTONIC GUARD: Only transitions forward (state < MSG_STORED)
     * Clears downloadQueuedAt to prevent stale timestamps after success
     */
    @Query("""
        UPDATE ping_inbox
        SET state = :msgStoredState,
            lastUpdatedAt = :timestamp,
            msgAckedAt = :timestamp,
            downloadQueuedAt = NULL
        WHERE pingId = :pingId
        AND state < :msgStoredState
    """)
    suspend fun transitionToMsgStored(
        pingId: String,
        timestamp: Long,
        msgStoredState: Int = PingInbox.STATE_MSG_STORED
    ): Int

    /**
     * Update PING_ACK timestamp
     */
    @Query("UPDATE ping_inbox SET pingAckedAt = :timestamp WHERE pingId = :pingId")
    suspend fun updatePingAckTime(pingId: String, timestamp: Long): Int

    /**
     * Get ping wire bytes for download/resend
     * Returns Base64-encoded wire bytes or null if not found/cleared
     */
    @Query("SELECT pingWireBytesBase64 FROM ping_inbox WHERE pingId = :pingId LIMIT 1")
    suspend fun getPingWireBytes(pingId: String): String?

    /**
     * Update ping wire bytes (for resend or migration from SharedPrefs)
     * Also updates lastUpdatedAt timestamp
     */
    @Query("UPDATE ping_inbox SET pingWireBytesBase64 = :b64, lastUpdatedAt = :now WHERE pingId = :pingId")
    suspend fun updatePingWireBytes(pingId: String, b64: String, now: Long): Int

    /**
     * Clear ping wire bytes after successful download (reduce DB size)
     * Sets pingWireBytesBase64 to NULL after message is in messages table
     */
    @Query("UPDATE ping_inbox SET pingWireBytesBase64 = NULL, lastUpdatedAt = :now WHERE pingId = :pingId")
    suspend fun clearPingWireBytes(pingId: String, now: Long): Int

    /**
     * Check if ping exists
     */
    @Query("SELECT EXISTS(SELECT 1 FROM ping_inbox WHERE pingId = :pingId LIMIT 1)")
    suspend fun exists(pingId: String): Boolean

    // 
    // Manual download claim (user tapped lock icon)
    // 

    /**
     * Atomically claim a ping for manual download (user tapped lock icon).
     * Accepts PING_SEEN, MANUAL_REQUIRED, FAILED_TEMP, and PONG_SENT.
     * PONG_SENT included to handle stale state after logout/login (process died mid-download).
     * FAILED_TEMP included so user can manually retry from lock icon.
     * Returns 1 if claimed, 0 if already in DOWNLOAD_QUEUED or MSG_STORED.
     */
    @Query("""
        UPDATE ping_inbox
        SET state = ${PingInbox.STATE_DOWNLOAD_QUEUED},
            downloadQueuedAt = :now,
            lastUpdatedAt = :now
        WHERE pingId = :pingId
        AND state IN (${PingInbox.STATE_PING_SEEN}, ${PingInbox.STATE_MANUAL_REQUIRED}, ${PingInbox.STATE_FAILED_TEMP}, ${PingInbox.STATE_PONG_SENT})
    """)
    suspend fun claimForManualDownload(pingId: String, now: Long): Int

    // 
    // Auto-download claim methods (atomic DB-as-lock pattern)
    // 

    /**
     * Atomically claim a PING_SEEN for auto-download
     * Returns 1 if claimed, 0 if already claimed or in different state
     * Sets downloadQueuedAt for watchdog stuck-claim detection
     */
    @Query("""
        UPDATE ping_inbox
        SET state = ${PingInbox.STATE_DOWNLOAD_QUEUED},
            downloadQueuedAt = :now,
            lastUpdatedAt = :now
        WHERE pingId = :pingId
        AND state = ${PingInbox.STATE_PING_SEEN}
    """)
    suspend fun claimForAutoDownload(pingId: String, now: Long): Int

    /**
     * Reclaim a FAILED_TEMP ping for retry
     * Returns 1 if reclaimed, 0 if state changed since check
     * Resets downloadQueuedAt for fresh watchdog window
     */
    @Query("""
        UPDATE ping_inbox
        SET state = ${PingInbox.STATE_DOWNLOAD_QUEUED},
            downloadQueuedAt = :now,
            lastUpdatedAt = :now
        WHERE pingId = :pingId
        AND state = ${PingInbox.STATE_FAILED_TEMP}
    """)
    suspend fun reclaimForRetry(pingId: String, now: Long): Int

    /**
     * Reclaim a MANUAL_REQUIRED ping (user tapped lock icon to retry)
     * Returns 1 if reclaimed, 0 if state changed since check
     * Resets downloadQueuedAt for fresh watchdog window
     */
    @Query("""
        UPDATE ping_inbox
        SET state = ${PingInbox.STATE_DOWNLOAD_QUEUED},
            downloadQueuedAt = :now,
            lastUpdatedAt = :now
        WHERE pingId = :pingId
        AND state = ${PingInbox.STATE_MANUAL_REQUIRED}
    """)
    suspend fun reclaimFromManual(pingId: String, now: Long): Int

    /**
     * Atomic failure decision: DOWNLOAD_QUEUED/PONG_SENT → FAILED_TEMP or MANUAL_REQUIRED
     * Single SQL CASE avoids two-update race window
     * Clears downloadQueuedAt to prevent stale watchdog triggers
     * Increments attemptCount for retry tracking
     * Accepts PONG_SENT so timeout after pong-sent also resolves correctly
     * Returns 1 if updated, 0 if not in expected state
     */
    @Query("""
        UPDATE ping_inbox
        SET state = CASE
                WHEN attemptCount + 1 >= :maxRetries THEN ${PingInbox.STATE_MANUAL_REQUIRED}
                ELSE ${PingInbox.STATE_FAILED_TEMP}
            END,
            attemptCount = attemptCount + 1,
            downloadQueuedAt = NULL,
            lastUpdatedAt = :now
        WHERE pingId = :pingId
        AND state IN (${PingInbox.STATE_DOWNLOAD_QUEUED}, ${PingInbox.STATE_PONG_SENT})
    """)
    suspend fun failAutoDownload(pingId: String, now: Long, maxRetries: Int): Int

    /**
     * Get current state for a ping
     * Returns null if ping doesn't exist
     */
    @Query("SELECT state FROM ping_inbox WHERE pingId = :pingId")
    suspend fun getState(pingId: String): Int?

    /**
     * Get state and attempt count in a single round trip
     * Useful for failure gating decisions after failAutoDownload()
     */
    @Query("SELECT state, attemptCount FROM ping_inbox WHERE pingId = :pingId")
    suspend fun getStateAndAttempts(pingId: String): PingStateSnapshot?

    // 
    // Watchdog and retry worker methods
    // 

    /**
     * Release stuck DOWNLOAD_QUEUED claims (process died mid-download)
     * Smart release: if attempts near max → MANUAL_REQUIRED, else → FAILED_TEMP
     * Increments attemptCount to prevent infinite churn on persistent failures
     * Clears downloadQueuedAt so released rows aren't re-caught by watchdog
     */
    @Query("""
        UPDATE ping_inbox
        SET state = CASE
                WHEN attemptCount + 1 >= :maxRetries THEN ${PingInbox.STATE_MANUAL_REQUIRED}
                ELSE ${PingInbox.STATE_FAILED_TEMP}
            END,
            attemptCount = attemptCount + 1,
            downloadQueuedAt = NULL,
            lastUpdatedAt = :now
        WHERE state = ${PingInbox.STATE_DOWNLOAD_QUEUED}
        AND downloadQueuedAt < :stuckCutoff
    """)
    suspend fun releaseStuckClaims(stuckCutoff: Long, now: Long, maxRetries: Int): Int

    /**
     * Get FAILED_TEMP pings eligible for retry (ordered oldest first)
     * Call site must filter by trusted contacts before enqueuing
     */
    @Query("""
        SELECT * FROM ping_inbox
        WHERE state = ${PingInbox.STATE_FAILED_TEMP}
        ORDER BY lastUpdatedAt ASC
    """)
    suspend fun getRetryablePings(): List<PingInbox>

    /**
     * Get unclaimed PING_SEEN entries (cap-hit arrivals or missed by auto-download)
     * Call site MUST filter by trusted contacts before claiming (spam vector otherwise)
     */
    @Query("""
        SELECT * FROM ping_inbox
        WHERE state = ${PingInbox.STATE_PING_SEEN}
        ORDER BY firstSeenAt ASC
    """)
    suspend fun getUnclaimedPingSeen(): List<PingInbox>

    // 
    // Pressure cap methods (states 0 + 10 + 11 = total pending pressure)
    // 

    /**
     * Count global pending pressure across all contacts
     * Includes PING_SEEN (0) + DOWNLOAD_QUEUED (10) + FAILED_TEMP (11)
     * Does NOT include MANUAL_REQUIRED (12) — user already notified
     */
    @Query("""
        SELECT COUNT(*) FROM ping_inbox
        WHERE state IN (${PingInbox.STATE_PING_SEEN}, ${PingInbox.STATE_DOWNLOAD_QUEUED}, ${PingInbox.STATE_FAILED_TEMP})
    """)
    suspend fun countGlobalPending(): Int

    /**
     * Count pending pressure for a specific contact
     * Includes PING_SEEN (0) + DOWNLOAD_QUEUED (10) + FAILED_TEMP (11)
     */
    @Query("""
        SELECT COUNT(*) FROM ping_inbox
        WHERE contactId = :contactId
        AND state IN (${PingInbox.STATE_PING_SEEN}, ${PingInbox.STATE_DOWNLOAD_QUEUED}, ${PingInbox.STATE_FAILED_TEMP})
    """)
    suspend fun countPendingByContactAll(contactId: Long): Int

    // 
    // Cleanup methods
    // 

    /**
     * Delete old completed pings (cleanup)
     * Only deletes MSG_STORED entries older than cutoff
     */
    @Query("DELETE FROM ping_inbox WHERE state = :msgStoredState AND lastUpdatedAt < :cutoffTimestamp")
    suspend fun deleteOldCompleted(cutoffTimestamp: Long, msgStoredState: Int = PingInbox.STATE_MSG_STORED): Int

    /**
     * Delete abandoned PING_SEEN entries (user ignored lock icon forever)
     * Deletes PING_SEEN older than cutoff (e.g., 30 days)
     */
    @Query("DELETE FROM ping_inbox WHERE state = :pingSeenState AND firstSeenAt < :cutoffTimestamp")
    suspend fun deleteAbandonedPings(cutoffTimestamp: Long, pingSeenState: Int = PingInbox.STATE_PING_SEEN): Int

    /**
     * Delete stuck PONG_SENT entries (sender never delivered after PONG)
     * Deletes PONG_SENT older than cutoff (e.g., 7 days)
     */
    @Query("DELETE FROM ping_inbox WHERE state = :pongSentState AND lastUpdatedAt < :cutoffTimestamp")
    suspend fun deleteStuckPongs(cutoffTimestamp: Long, pongSentState: Int = PingInbox.STATE_PONG_SENT): Int

    /**
     * Delete specific ping by ID (testing/debugging)
     */
    @Query("DELETE FROM ping_inbox WHERE pingId = :pingId")
    suspend fun delete(pingId: String): Int

    /**
     * Delete all pings for a specific contact (thread deletion)
     */
    @Query("DELETE FROM ping_inbox WHERE contactId = :contactId")
    suspend fun deleteByContact(contactId: Long): Int

    /**
     * Delete all (testing/debugging)
     */
    @Query("DELETE FROM ping_inbox")
    suspend fun deleteAll()
}

/**
 * Projection for getStateAndAttempts() — avoids loading the full PingInbox row
 */
data class PingStateSnapshot(
    val state: Int,
    val attemptCount: Int
)
