package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.CrdtOpLog

/**
 * Data Access Object for CRDT operation log.
 * Stores raw serialized ops for group state persistence.
 */
@Dao
interface CrdtOpLogDao {

    /**
     * Insert a single op (IGNORE on duplicate opId for deduplication)
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertOp(op: CrdtOpLog)

    /**
     * Insert multiple ops (bulk, IGNORE duplicates)
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertOps(ops: List<CrdtOpLog>)

    /**
     * Get all ops for a group, ordered by lamport (for crdtLoadGroup rebuild).
     */
    @Query("SELECT * FROM crdt_op_log WHERE groupId = :groupId ORDER BY lamport ASC, createdAt ASC")
    suspend fun getOpsForGroup(groupId: String): List<CrdtOpLog>

    /**
     * Get ops after a lamport value (for incremental sync).
     */
    @Query("SELECT * FROM crdt_op_log WHERE groupId = :groupId AND lamport > :afterLamport ORDER BY lamport ASC LIMIT :limit")
    suspend fun getOpsAfter(groupId: String, afterLamport: Long, limit: Int = 1000): List<CrdtOpLog>

    /**
     * Get op count for a group.
     */
    @Query("SELECT COUNT(*) FROM crdt_op_log WHERE groupId = :groupId")
    suspend fun getOpCount(groupId: String): Int

    /**
     * Check if an op already exists (deduplication check).
     */
    @Query("SELECT EXISTS(SELECT 1 FROM crdt_op_log WHERE opId = :opId)")
    suspend fun opExists(opId: String): Boolean

    /**
     * Delete all ops for a group (when deleting a group).
     */
    @Query("DELETE FROM crdt_op_log WHERE groupId = :groupId")
    suspend fun deleteOpsForGroup(groupId: String)

    /**
     * Get the max lamport for a group (for sync cursor).
     */
    @Query("SELECT MAX(lamport) FROM crdt_op_log WHERE groupId = :groupId")
    suspend fun getMaxLamport(groupId: String): Long?
}
