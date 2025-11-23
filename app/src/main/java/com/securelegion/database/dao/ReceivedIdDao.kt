package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.ReceivedId

/**
 * DAO for tracking received ping/pong/message IDs to prevent duplicates
 */
@Dao
interface ReceivedIdDao {

    /**
     * Try to insert a received ID
     * Returns the row ID if successful, -1 if ID already exists (duplicate)
     *
     * Usage:
     * val rowId = insertReceivedId(ReceivedId(...))
     * if (rowId != -1L) {
     *     // New ID - process it
     * } else {
     *     // Duplicate ID - skip processing
     * }
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertReceivedId(receivedId: ReceivedId): Long

    /**
     * Check if an ID has already been received
     * @return true if ID exists (duplicate), false if new
     */
    @Query("SELECT EXISTS(SELECT 1 FROM received_ids WHERE receivedId = :id LIMIT 1)")
    suspend fun exists(id: String): Boolean

    /**
     * Mark an ID as processed
     */
    @Query("UPDATE received_ids SET processed = 1 WHERE receivedId = :id")
    suspend fun markProcessed(id: String)

    /**
     * Delete old received IDs to prevent table bloat
     * Keeps last 30 days of IDs
     */
    @Query("DELETE FROM received_ids WHERE receivedTimestamp < :cutoffTimestamp")
    suspend fun deleteOldIds(cutoffTimestamp: Long): Int

    /**
     * Get count of received IDs by type
     */
    @Query("SELECT COUNT(*) FROM received_ids WHERE idType = :type")
    suspend fun getCountByType(type: String): Int

    /**
     * Delete all received IDs (for testing/debugging)
     */
    @Query("DELETE FROM received_ids")
    suspend fun deleteAll()
}
