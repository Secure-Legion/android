package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Skipped message key storage for handling out-of-order messages
 *
 * When a message arrives with sequence n > expected Nr, we derive and store
 * message keys for the gap [Nr..n-1] to allow future decryption if those
 * messages arrive late.
 *
 * This prevents message loss due to network issues, airplane mode, etc.
 */
@Entity(tableName = "skipped_message_keys")
data class SkippedMessageKey(
    @PrimaryKey
    val id: String, // Format: "contactId_sequence"
    val contactId: Long,
    val sequence: Long, // Long to match wire format
    val messageKey: ByteArray, // 32-byte message key for this specific sequence
    val timestamp: Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SkippedMessageKey
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}
