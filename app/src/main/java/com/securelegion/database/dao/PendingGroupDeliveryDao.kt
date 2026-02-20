package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.securelegion.database.entities.PendingGroupDelivery

/**
 * DAO for the pending group delivery queue.
 *
 * Stores ops that couldn't be delivered because routing was missing.
 * Flushed when routing arrives, or retried with exponential backoff.
 */
@Dao
interface PendingGroupDeliveryDao {

    @Insert
    suspend fun insert(delivery: PendingGroupDelivery)

    @Query("SELECT * FROM pending_group_delivery WHERE groupId = :groupId AND targetPubkeyHex = :pubkeyHex")
    suspend fun getForTarget(groupId: String, pubkeyHex: String): List<PendingGroupDelivery>

    @Query("SELECT * FROM pending_group_delivery WHERE nextRetryAt <= :now AND attemptCount < 20")
    suspend fun getDueForRetry(now: Long): List<PendingGroupDelivery>

    @Query("DELETE FROM pending_group_delivery WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM pending_group_delivery WHERE groupId = :groupId AND targetPubkeyHex = :pubkeyHex")
    suspend fun deleteForTarget(groupId: String, pubkeyHex: String)

    @Query("DELETE FROM pending_group_delivery WHERE groupId = :groupId")
    suspend fun deleteForGroup(groupId: String)

    @Query("UPDATE pending_group_delivery SET attemptCount = :count, nextRetryAt = :nextRetry WHERE id = :id")
    suspend fun updateRetry(id: Long, count: Int, nextRetry: Long)

    @Query("DELETE FROM pending_group_delivery WHERE createdAt < :cutoff OR attemptCount >= 20")
    suspend fun purgeStale(cutoff: Long)
}
