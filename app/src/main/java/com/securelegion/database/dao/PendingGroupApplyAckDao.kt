package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.PendingGroupApplyAck

@Dao
interface PendingGroupApplyAckDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(rows: List<PendingGroupApplyAck>)

    @Query(
        "SELECT * FROM pending_group_apply_ack " +
            "WHERE nextRetryAt <= :now AND attemptCount <= 3 " +
            "ORDER BY nextRetryAt ASC"
    )
    suspend fun getDueForRetry(now: Long): List<PendingGroupApplyAck>

    @Query(
        "UPDATE pending_group_apply_ack " +
            "SET attemptCount = :attemptCount, nextRetryAt = :nextRetryAt " +
            "WHERE groupId = :groupId AND authorDeviceIdHex = :authorDeviceIdHex " +
            "AND lamport = :lamport AND targetPeerPubkeyHex = :targetPeerPubkeyHex"
    )
    suspend fun updateRetry(
        groupId: String,
        authorDeviceIdHex: String,
        lamport: Long,
        targetPeerPubkeyHex: String,
        attemptCount: Int,
        nextRetryAt: Long
    )

    @Query(
        "DELETE FROM pending_group_apply_ack " +
            "WHERE groupId = :groupId AND authorDeviceIdHex = :authorDeviceIdHex " +
            "AND lamport <= :lamport AND targetPeerPubkeyHex = :targetPeerPubkeyHex"
    )
    suspend fun acknowledgeUpTo(
        groupId: String,
        authorDeviceIdHex: String,
        lamport: Long,
        targetPeerPubkeyHex: String
    )

    @Query(
        "DELETE FROM pending_group_apply_ack " +
            "WHERE groupId = :groupId AND authorDeviceIdHex = :authorDeviceIdHex " +
            "AND lamport = :lamport AND targetPeerPubkeyHex = :targetPeerPubkeyHex"
    )
    suspend fun deleteOne(
        groupId: String,
        authorDeviceIdHex: String,
        lamport: Long,
        targetPeerPubkeyHex: String
    )

    @Query("DELETE FROM pending_group_apply_ack WHERE createdAt < :cutoff")
    suspend fun purgeStale(cutoff: Long)
}
