package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.PingInbox

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
     * Count pending locks for a contact (not yet MSG_STORED)
     * Micro-optimization: faster than fetching full rows when only checking if pending exist
     */
    @Query("SELECT COUNT(*) FROM ping_inbox WHERE contactId = :contactId AND state < :msgStoredState")
    suspend fun countPendingByContact(contactId: Long, msgStoredState: Int = PingInbox.STATE_MSG_STORED): Int

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
     * Transition to PONG_SENT state (user authorized download)
     * MONOTONIC GUARD: Only transitions forward (state < PONG_SENT)
     */
    @Query("""
        UPDATE ping_inbox
        SET state = :pongSentState,
            lastUpdatedAt = :timestamp,
            pongSentAt = :timestamp
        WHERE pingId = :pingId
        AND state < :pongSentState
    """)
    suspend fun transitionToPongSent(
        pingId: String,
        timestamp: Long,
        pongSentState: Int = PingInbox.STATE_PONG_SENT
    ): Int

    /**
     * Transition to MSG_STORED state (message saved to DB)
     * MONOTONIC GUARD: Only transitions forward (state < MSG_STORED)
     */
    @Query("""
        UPDATE ping_inbox
        SET state = :msgStoredState,
            lastUpdatedAt = :timestamp,
            msgAckedAt = :timestamp
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
     * Check if ping exists
     */
    @Query("SELECT EXISTS(SELECT 1 FROM ping_inbox WHERE pingId = :pingId LIMIT 1)")
    suspend fun exists(pingId: String): Boolean

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
     * Delete all (testing/debugging)
     */
    @Query("DELETE FROM ping_inbox")
    suspend fun deleteAll()
}
