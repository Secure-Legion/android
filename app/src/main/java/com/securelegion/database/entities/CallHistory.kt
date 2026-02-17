package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * CallHistory - Track voice call history (incoming, outgoing, missed)
 */
@Entity(tableName = "call_history")
data class CallHistory(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    val contactId: Long, // Reference to Contact
    val contactName: String, // Cached name (in case contact deleted)
    val callId: String, // Unique call ID
    val timestamp: Long, // When call happened
    val type: CallType, // INCOMING, OUTGOING, MISSED
    val duration: Long = 0, // Call duration in seconds (0 for missed)
    val missedReason: String? = null // Reason for missed call (e.g., "App was locked")
)

enum class CallType {
    INCOMING, // Answered incoming call
    OUTGOING, // Made outgoing call
    MISSED // Missed call (not answered)
}
