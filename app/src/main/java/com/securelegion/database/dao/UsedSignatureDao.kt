package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.UsedSignature

/**
 * DAO for managing used transaction signatures (replay protection)
 */
@Dao
interface UsedSignatureDao {

    /**
     * Check if a signature has already been used
     * @return true if signature exists (replay attack), false if new
     */
    @Query("SELECT EXISTS(SELECT 1 FROM used_signatures WHERE signature = :signature)")
    suspend fun isSignatureUsed(signature: String): Boolean

    /**
     * Record a signature as used
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertSignature(usedSignature: UsedSignature): Long

    /**
     * Get signature record by signature string
     */
    @Query("SELECT * FROM used_signatures WHERE signature = :signature LIMIT 1")
    suspend fun getBySignature(signature: String): UsedSignature?

    /**
     * Get all signatures for a specific quote
     */
    @Query("SELECT * FROM used_signatures WHERE quoteId = :quoteId")
    suspend fun getSignaturesForQuote(quoteId: String): List<UsedSignature>

    /**
     * Clean up old signatures (optional - for maintenance)
     * Keeps signatures for 90 days by default
     */
    @Query("DELETE FROM used_signatures WHERE usedAt < :cutoffTime")
    suspend fun cleanupOldSignatures(cutoffTime: Long = System.currentTimeMillis() - 90L * 24 * 60 * 60 * 1000)

    /**
     * Get count of used signatures
     */
    @Query("SELECT COUNT(*) FROM used_signatures")
    suspend fun getCount(): Int
}
