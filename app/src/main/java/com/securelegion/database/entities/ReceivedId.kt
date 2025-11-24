package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Tracks all received ping/pong/message IDs to prevent duplicates
 *
 * This table provides deduplication BEFORE message processing:
 * 1. When ping/pong/message arrives, try to insert ID into this table
 * 2. If insert succeeds -> new ID, process it
 * 3. If insert fails -> duplicate ID, ignore it
 *
 * This prevents race conditions where:
 * - Same ping arrives twice before message is saved
 * - Same pong arrives twice before message is sent
 * - Same message arrives twice before database insert completes
 */
@Entity(
    tableName = "received_ids",
    indices = [Index(value = ["receivedId"], unique = true)]
)
data class ReceivedId(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * The ID that was received (ping ID, pong ID, or message ID)
     * UNIQUE constraint prevents duplicates
     */
    val receivedId: String,

    /**
     * Type of ID: PING, PONG, or MESSAGE
     */
    val idType: String,

    /**
     * Timestamp when this ID was first received
     */
    val receivedTimestamp: Long,

    /**
     * Whether processing completed successfully
     * Used for debugging and cleanup
     */
    val processed: Boolean = false
) {
    companion object {
        const val TYPE_PING = "PING"
        const val TYPE_PONG = "PONG"
        const val TYPE_MESSAGE = "MESSAGE"
    }
}
