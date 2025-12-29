package com.securelegion.database.dao

import androidx.lifecycle.LiveData
import androidx.room.*
import com.securelegion.database.entities.CallHistory
import com.securelegion.database.entities.CallType

/**
 * CallHistoryDao - Database access for call history
 */
@Dao
interface CallHistoryDao {

    /**
     * Insert a new call history entry
     */
    @Insert
    suspend fun insert(callHistory: CallHistory): Long

    /**
     * Get all call history (most recent first)
     */
    @Query("SELECT * FROM call_history ORDER BY timestamp DESC")
    fun getAllCallHistory(): LiveData<List<CallHistory>>

    /**
     * Get call history for a specific contact
     */
    @Query("SELECT * FROM call_history WHERE contactId = :contactId ORDER BY timestamp DESC")
    fun getCallHistoryForContact(contactId: Long): LiveData<List<CallHistory>>

    /**
     * Get missed calls only
     */
    @Query("SELECT * FROM call_history WHERE type = 'MISSED' ORDER BY timestamp DESC")
    fun getMissedCalls(): LiveData<List<CallHistory>>

    /**
     * Get recent call history (last 50 calls)
     */
    @Query("SELECT * FROM call_history ORDER BY timestamp DESC LIMIT 50")
    fun getRecentCallHistory(): LiveData<List<CallHistory>>

    /**
     * Delete all call history
     */
    @Query("DELETE FROM call_history")
    suspend fun deleteAll()

    /**
     * Delete call history older than X days
     */
    @Query("DELETE FROM call_history WHERE timestamp < :timestampBefore")
    suspend fun deleteOlderThan(timestampBefore: Long)

    /**
     * Get call by call ID
     */
    @Query("SELECT * FROM call_history WHERE callId = :callId LIMIT 1")
    suspend fun getCallByCallId(callId: String): CallHistory?

    /**
     * Update call duration (when call ends)
     */
    @Query("UPDATE call_history SET duration = :duration WHERE callId = :callId")
    suspend fun updateCallDuration(callId: String, duration: Long)
}
