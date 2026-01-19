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

    /**
     * Get all friend requests needing retry
     * Used by FriendRequestWorker to find requests to retry
     */
    @Query("SELECT * FROM pending_friend_requests WHERE needsRetry = 1 AND isCompleted = 0 AND isFailed = 0")
    suspend fun getFriendRequestsNeedingRetry(): List<PendingFriendRequest>

    /**
     * Mark all pending friend requests as needing retry
     * Called on app start and Tor reconnection for convergence
     * Returns count of rows updated
     */
    @Query("UPDATE pending_friend_requests SET needsRetry = 1 WHERE isCompleted = 0 AND isFailed = 0")
    suspend fun markAllPendingNeedRetry(): Int

    /**
     * Mark a friend request as failed
     * Set isFailed = true and needsRetry = false
     * Called when retry attempts are exhausted or required data is missing
     */
    @Query("UPDATE pending_friend_requests SET isFailed = 1, needsRetry = 0 WHERE id = :requestId")
    suspend fun markFailed(requestId: Long)

    /**
     * Mark a friend request as sent successfully
     * Clear needsRetry flag and update last sent time and retry tracking
     */
    @Query("""
        UPDATE pending_friend_requests
        SET needsRetry = 0, lastSentAt = :timestamp, retryCount = :retryCount, nextRetryAt = :nextRetryAt
        WHERE id = :requestId
    """)
    suspend fun markSent(
        requestId: Long,
        timestamp: Long,
        retryCount: Int,
        nextRetryAt: Long
    )

    /**
     * Update retry tracking for a failed attempt
     * Keep needsRetry = 1 and update the retry count and next retry time
     */
    @Query("""
        UPDATE pending_friend_requests
        SET retryCount = :retryCount, nextRetryAt = :nextRetryAt, lastSentAt = :timestamp
        WHERE id = :requestId
    """)
    suspend fun updateRetryTracking(
        requestId: Long,
        timestamp: Long,
        retryCount: Int,
        nextRetryAt: Long
    )

    /**
     * Mark friend request as completed
     * Called when Phase 3 ACK is confirmed
     */
    @Query("UPDATE pending_friend_requests SET isCompleted = 1, completedAt = :timestamp, needsRetry = 0 WHERE id = :requestId")
    suspend fun markCompleted(requestId: Long, timestamp: Long)

    /**
     * Get friend request by recipient onion address
     */
    @Query("SELECT * FROM pending_friend_requests WHERE recipientOnion = :onionAddress")
    suspend fun getByRecipientOnion(onionAddress: String): PendingFriendRequest?

    /**
     * Delete all friend requests (for testing or account wipe)
     */
    @Query("DELETE FROM pending_friend_requests")
    suspend fun deleteAllRequests()

    /**
     * Get count of pending friend requests
     */
    @Query("SELECT COUNT(*) FROM pending_friend_requests WHERE isCompleted = 0 AND isFailed = 0")
    suspend fun getPendingCount(): Int
}
