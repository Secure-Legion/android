package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.securelegion.database.entities.CallQualityLog

/**
 * DAO for accessing call quality logs
 */
@Dao
interface CallQualityLogDao {

    /**
     * Insert a new call quality log
     */
    @Insert
    suspend fun insert(log: CallQualityLog): Long

    /**
     * Get all call quality logs ordered by timestamp (newest first)
     * @param limit Maximum number of logs to return
     */
    @Query("SELECT * FROM call_quality_logs ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentLogs(limit: Int = 50): List<CallQualityLog>

    /**
     * Get the most recent call quality log
     */
    @Query("SELECT * FROM call_quality_logs ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastLog(): CallQualityLog?

    /**
     * Delete old logs (keep only last N days)
     * @param cutoffTimestamp Delete logs older than this timestamp
     */
    @Query("DELETE FROM call_quality_logs WHERE timestamp < :cutoffTimestamp")
    suspend fun deleteOldLogs(cutoffTimestamp: Long): Int

    /**
     * Get total count of logs
     */
    @Query("SELECT COUNT(*) FROM call_quality_logs")
    suspend fun getCount(): Int

    /**
     * Delete all logs
     */
    @Query("DELETE FROM call_quality_logs")
    suspend fun deleteAll()
}
