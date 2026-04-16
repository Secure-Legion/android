package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.PendingProfilePhoto

@Dao
interface PendingProfilePhotoDao {

    /**
     * Insert a retry entry. Uses IGNORE strategy so re-queuing the same
     * contact doesn't reset the retry count — the existing entry keeps
     * its schedule and simply gets retried with the current photo.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfAbsent(entry: PendingProfilePhoto): Long

    /**
     * Get all entries whose nextRetryAtMs has elapsed.
     */
    @Query("SELECT * FROM pending_profile_photo WHERE nextRetryAtMs <= :nowMs ORDER BY createdAtMs ASC")
    suspend fun getDue(nowMs: Long): List<PendingProfilePhoto>

    /**
     * Update retry state after a failure (increment count, push out next retry).
     */
    @Query("UPDATE pending_profile_photo SET retryCount = :retryCount, nextRetryAtMs = :nextRetryAtMs WHERE contactId = :contactId")
    suspend fun updateRetryState(contactId: Long, retryCount: Int, nextRetryAtMs: Long)

    /**
     * Remove a single entry (on success or after max retries).
     */
    @Query("DELETE FROM pending_profile_photo WHERE contactId = :contactId")
    suspend fun delete(contactId: Long)

    /**
     * Remove all entries (e.g., when user deletes their photo).
     */
    @Query("DELETE FROM pending_profile_photo")
    suspend fun deleteAll()

    /**
     * Reset all retry timers to immediate (used on circuit-ready flush).
     */
    @Query("UPDATE pending_profile_photo SET nextRetryAtMs = 0")
    suspend fun resetAllRetryTimers()

    /**
     * Get count of pending entries.
     */
    @Query("SELECT COUNT(*) FROM pending_profile_photo")
    suspend fun count(): Int
}
