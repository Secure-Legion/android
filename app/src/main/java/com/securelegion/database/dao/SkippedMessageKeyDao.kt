package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.SkippedMessageKey

/**
 * DAO for skipped message key operations
 *
 * Provides database access for storing and retrieving message keys
 * that were skipped during out-of-order message delivery.
 */
@Dao
interface SkippedMessageKeyDao {
    /**
     * Insert a single skipped message key
     * Replaces if key already exists for this (contactId, sequence)
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(key: SkippedMessageKey)

    /**
     * Insert multiple skipped message keys (bulk operation)
     * Used when processing a large gap in message sequences
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(keys: List<SkippedMessageKey>)

    /**
     * Retrieve skipped message key for specific contact and sequence
     * Returns null if no key found (message too old or already processed)
     */
    @Query("SELECT * FROM skipped_message_keys WHERE contactId = :contactId AND sequence = :sequence")
    suspend fun getKey(contactId: Long, sequence: Long): SkippedMessageKey?

    /**
     * Delete specific skipped message key after successful decryption
     * Keys should be deleted immediately after use
     */
    @Query("DELETE FROM skipped_message_keys WHERE contactId = :contactId AND sequence = :sequence")
    suspend fun deleteKey(contactId: Long, sequence: Long)

    /**
     * Delete all skipped keys older than cutoff time (TTL cleanup)
     * Returns number of keys deleted
     */
    @Query("DELETE FROM skipped_message_keys WHERE timestamp < :cutoffTime")
    suspend fun deleteOldKeys(cutoffTime: Long): Int

    /**
     * Get count of stored skipped keys for a contact
     * Useful for monitoring and debugging
     */
    @Query("SELECT COUNT(*) FROM skipped_message_keys WHERE contactId = :contactId")
    suspend fun getKeyCount(contactId: Long): Int
}
