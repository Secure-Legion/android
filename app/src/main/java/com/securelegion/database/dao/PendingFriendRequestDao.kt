package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.PendingFriendRequest

/**
 * Data Access Object for PendingFriendRequest operations
 * All queries run on background thread via coroutines
 */
@Dao
interface PendingFriendRequestDao {

    /**
     * Insert a new pending friend request
     * @return ID of inserted request
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRequest(request: PendingFriendRequest): Long

    /**
     * Update existing friend request
     */
    @Update
    suspend fun updateRequest(request: PendingFriendRequest)

    /**
     * Delete friend request
     */
    @Delete
    suspend fun deleteRequest(request: PendingFriendRequest)

    /**
     * Get friend request by ID
     */
    @Query("SELECT * FROM pending_friend_requests WHERE id = :requestId")
    suspend fun getById(requestId: Long): PendingFriendRequest?

    @Query("SELECT * FROM pending_friend_requests WHERE isCompleted = 0 AND isFailed = 0")
    suspend fun getAllUnfinished(): List<PendingFriendRequest>

    /**
     * Get all friend requests needing retry
     * Used by FriendRequestWorker to find requests to retry
     */
    @Query("""
        SELECT * FROM pending_friend_requests
        WHERE needsRetry = 1
          AND isCompleted = 0
          AND isFailed = 0
          AND nextRetryAt <= :now
          AND (leaseToken IS NULL OR leaseExpiresAt <= :now)
        ORDER BY nextRetryAt ASC, id ASC
    """)
    suspend fun getFriendRequestsNeedingRetry(now: Long = System.currentTimeMillis()): List<PendingFriendRequest>

    /**
     * Mark all pending friend requests as needing retry
     * Called on app start and Tor reconnection for convergence
     * Returns count of rows updated
     */
    @Deprecated("Convergence must preserve persisted backoff; schedule the dispatcher instead")
    @Query("UPDATE pending_friend_requests SET needsRetry = 1 WHERE isCompleted = 0 AND isFailed = 0 AND needsRetry = 0")
    suspend fun markAllPendingNeedRetry(): Int

    @Query("""
        SELECT * FROM pending_friend_requests
        WHERE needsRetry = 1
          AND isCompleted = 0
          AND isFailed = 0
          AND nextRetryAt <= :now
          AND (leaseToken IS NULL OR leaseExpiresAt <= :now)
        ORDER BY nextRetryAt ASC, id ASC
        LIMIT 1
    """)
    suspend fun getNextClaimable(now: Long): PendingFriendRequest?

    @Query("""
        UPDATE pending_friend_requests
        SET leaseToken = :token, leaseExpiresAt = :expiresAt
        WHERE id = :requestId
          AND needsRetry = 1
          AND isCompleted = 0
          AND isFailed = 0
          AND nextRetryAt <= :now
          AND (leaseToken IS NULL OR leaseExpiresAt <= :now)
    """)
    suspend fun tryClaim(requestId: Long, token: String, now: Long, expiresAt: Long): Int

    @Transaction
    suspend fun claimNextDue(now: Long, token: String, expiresAt: Long): PendingFriendRequest? {
        val candidate = getNextClaimable(now) ?: return null
        return if (tryClaim(candidate.id, token, now, expiresAt) == 1) {
            candidate.copy(leaseToken = token, leaseExpiresAt = expiresAt)
        } else {
            null
        }
    }

    /** Atomically claim one known row for an immediate/UI send. */
    @Transaction
    suspend fun claimById(
        requestId: Long,
        now: Long,
        token: String,
        expiresAt: Long
    ): PendingFriendRequest? {
        val candidate = getById(requestId) ?: return null
        return if (tryClaim(requestId, token, now, expiresAt) == 1) {
            candidate.copy(leaseToken = token, leaseExpiresAt = expiresAt)
        } else {
            null
        }
    }

    @Query("""
        SELECT MIN(
            CASE
                WHEN leaseToken IS NOT NULL AND leaseExpiresAt > :now
                    THEN MAX(nextRetryAt, leaseExpiresAt)
                ELSE nextRetryAt
            END
        ) FROM pending_friend_requests
        WHERE needsRetry = 1 AND isCompleted = 0 AND isFailed = 0
    """)
    suspend fun getEarliestRetryAt(now: Long): Long?

    @Query("""
        UPDATE pending_friend_requests
        SET leaseToken = NULL, leaseExpiresAt = 0
        WHERE leaseToken IS NOT NULL AND leaseExpiresAt <= :now
    """)
    suspend fun reclaimExpiredLeases(now: Long): Int

    @Query("""
        UPDATE pending_friend_requests
        SET nextRetryAt = :now, needsRetry = 1
        WHERE id = :requestId
          AND isCompleted = 0
          AND isFailed = 0
          AND leaseToken IS NULL
    """)
    suspend fun makeDueForManualRetry(requestId: Long, now: Long): Int

    /**
     * Mark a friend request as failed
     * Set isFailed = true and needsRetry = false
     * Called when retry attempts are exhausted or required data is missing
     */
    @Query("UPDATE pending_friend_requests SET isFailed = 1, needsRetry = 0, leaseToken = NULL, leaseExpiresAt = 0 WHERE id = :requestId")
    suspend fun markFailed(requestId: Long)

    @Query("""
        UPDATE pending_friend_requests
        SET isFailed = 1, needsRetry = 0, leaseToken = NULL, leaseExpiresAt = 0
        WHERE id = :requestId AND leaseToken = :token
    """)
    suspend fun markFailedIfLeased(requestId: Long, token: String): Int

    /**
     * Mark a friend request as sent successfully
     * Clear needsRetry flag and update last sent time and retry tracking
     */
    @Query("""
        UPDATE pending_friend_requests
        SET needsRetry = 0, lastSentAt = :timestamp, retryCount = :retryCount,
            nextRetryAt = :nextRetryAt, leaseToken = NULL, leaseExpiresAt = 0
        WHERE id = :requestId
    """)
    suspend fun markSent(
        requestId: Long,
        timestamp: Long,
        retryCount: Int,
        nextRetryAt: Long
    )

    @Query("""
        UPDATE pending_friend_requests
        SET needsRetry = 0, lastSentAt = :timestamp, retryCount = :retryCount,
            nextRetryAt = :nextRetryAt, leaseToken = NULL, leaseExpiresAt = 0
        WHERE id = :requestId AND leaseToken = :token
    """)
    suspend fun markSentIfLeased(
        requestId: Long,
        token: String,
        timestamp: Long,
        retryCount: Int,
        nextRetryAt: Long
    ): Int

    /**
     * Update retry tracking for a failed attempt
     * Keep needsRetry = 1 and update the retry count and next retry time
     */
    @Query("""
        UPDATE pending_friend_requests
        SET retryCount = :retryCount, nextRetryAt = :nextRetryAt, lastSentAt = :timestamp,
            needsRetry = 1, leaseToken = NULL, leaseExpiresAt = 0
        WHERE id = :requestId
    """)
    suspend fun updateRetryTracking(
        requestId: Long,
        timestamp: Long,
        retryCount: Int,
        nextRetryAt: Long
    )

    @Query("""
        UPDATE pending_friend_requests
        SET retryCount = :retryCount, nextRetryAt = :nextRetryAt, lastSentAt = :timestamp,
            needsRetry = 1, leaseToken = NULL, leaseExpiresAt = 0
        WHERE id = :requestId AND leaseToken = :token
    """)
    suspend fun updateRetryTrackingIfLeased(
        requestId: Long,
        token: String,
        timestamp: Long,
        retryCount: Int,
        nextRetryAt: Long
    ): Int

    @Query("""
        UPDATE pending_friend_requests
        SET leaseToken = NULL, leaseExpiresAt = 0
        WHERE id = :requestId AND leaseToken = :token
    """)
    suspend fun releaseLease(requestId: Long, token: String): Int

    /**
     * Mark friend request as completed
     * Called when Phase 3 ACK is confirmed
     */
    @Query("UPDATE pending_friend_requests SET isCompleted = 1, completedAt = :timestamp, needsRetry = 0, leaseToken = NULL, leaseExpiresAt = 0 WHERE id = :requestId")
    suspend fun markCompleted(requestId: Long, timestamp: Long)

    @Query("""
        UPDATE pending_friend_requests
        SET isCompleted = 1, completedAt = :timestamp, needsRetry = 0,
            leaseToken = NULL, leaseExpiresAt = 0
        WHERE id = :requestId AND leaseToken = :token
    """)
    suspend fun markCompletedIfLeased(requestId: Long, token: String, timestamp: Long): Int

    /**
     * Get friend request by recipient onion address
     */
    @Query("SELECT * FROM pending_friend_requests WHERE recipientOnion = :onionAddress")
    suspend fun getByRecipientOnion(onionAddress: String): PendingFriendRequest?

    /**
     * Completed Phase 3 rows are retained briefly as replay tombstones. If the peer retries its
     * authenticated Phase 2 because our ACK was lost, TorService can resend the exact ciphertext
     * without rebuilding protocol state or changing the wire format.
     */
    @Query("""
        SELECT * FROM pending_friend_requests
        WHERE phase = 3
          AND isCompleted = 1
          AND isFailed = 0
          AND completedAt IS NOT NULL
          AND completedAt >= :completedAfter
          AND phase2PayloadBase64 IS NOT NULL
          AND contactCardJson IS NOT NULL
        ORDER BY completedAt DESC, id DESC
        LIMIT :limit
    """)
    suspend fun getRecentCompletedPhase3(
        completedAfter: Long,
        limit: Int = 256
    ): List<PendingFriendRequest>

    /** Recover a Phase 3 row when the legacy UUID mapping commit was interrupted. */
    @Query("""
        SELECT * FROM pending_friend_requests
        WHERE phase = 3 AND phase1PayloadJson = :requestFingerprint
        ORDER BY createdAt DESC, id DESC
        LIMIT 2
    """)
    suspend fun getPhase3ByRequestFingerprint(
        requestFingerprint: String
    ): List<PendingFriendRequest>

    /** Delete only expired replay tombstones; active request state is never touched. */
    @Query("""
        DELETE FROM pending_friend_requests
        WHERE phase = 3
          AND isCompleted = 1
          AND completedAt IS NOT NULL
          AND completedAt < :completedBefore
    """)
    suspend fun deleteExpiredCompletedPhase3(completedBefore: Long): Int

    /** Keep replay storage bounded even during a high volume period inside the TTL window. */
    @Query("""
        DELETE FROM pending_friend_requests
        WHERE id IN (
            SELECT id FROM pending_friend_requests
            WHERE phase = 3
              AND isCompleted = 1
              AND completedAt IS NOT NULL
            ORDER BY completedAt DESC, id DESC
            LIMIT -1 OFFSET :keep
        )
    """)
    suspend fun deleteCompletedPhase3BeyondLimit(keep: Int): Int

    /**
     * Delete a single friend request by primary key. Used by UI cancel/delete
     * handlers that look up the dbId via the requestId→dbId SharedPreferences map.
     */
    @Query("DELETE FROM pending_friend_requests WHERE id = :requestId")
    suspend fun deleteById(requestId: Long)

    /**
     * Delete all friend requests (for testing or account wipe)
     */
    @Query("DELETE FROM pending_friend_requests")
    suspend fun deleteAllRequests()

    /**
     * Delete any pending friend requests targeting a given .onion address.
     * Used on contact delete to remove retry state tied to that peer
     * (friend-request onion OR messaging onion — caller invokes for each).
     */
    @Query("DELETE FROM pending_friend_requests WHERE recipientOnion = :onion")
    suspend fun deleteByRecipientOnion(onion: String)

    /** Startup removes obsolete pre-ACK rows but preserves active and completed Phase 3 bytes. */
    @Query("""
        DELETE FROM pending_friend_requests
        WHERE recipientOnion = :onion
          AND isCompleted = 0
          AND phase != 3
    """)
    suspend fun deleteUnfinishedByRecipientOnion(onion: String): Int

    /**
     * Get count of pending friend requests
     */
    @Query("SELECT COUNT(*) FROM pending_friend_requests WHERE isCompleted = 0 AND isFailed = 0")
    suspend fun getPendingCount(): Int
}
