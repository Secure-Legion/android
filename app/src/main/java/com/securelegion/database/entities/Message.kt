package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Message entity stored in encrypted SQLCipher database
 * Represents an encrypted message sent or received from a contact
 */
@Entity(
    tableName = "messages",
    foreignKeys = [
        ForeignKey(
            entity = Contact::class,
            parentColumns = ["id"],
            childColumns = ["contactId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["contactId"]),
        Index(value = ["timestamp"]),
        Index(value = ["messageId"], unique = true)
    ]
)
data class Message(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * Foreign key to Contact table
     */
    val contactId: Long,

    /**
     * Unique message ID (for deduplication and acknowledgments)
     * Format: UUID or hash of (sender + timestamp + nonce)
     */
    val messageId: String,

    /**
     * Encrypted message content (Base64-encoded)
     * Encrypted with XChaCha20-Poly1305
     */
    val encryptedContent: String,

    /**
     * Message direction: true = sent by us, false = received
     */
    val isSentByMe: Boolean,

    /**
     * Unix timestamp when message was created (milliseconds)
     */
    val timestamp: Long,

    /**
     * Message delivery status
     * 0 = Pending, 1 = Sent, 2 = Delivered, 3 = Read, 4 = Failed
     */
    val status: Int = STATUS_PENDING,

    /**
     * Ed25519 signature of the message (Base64-encoded)
     * Verifies message authenticity
     */
    val signatureBase64: String,

    /**
     * Encryption nonce (Base64-encoded, 24 bytes for XChaCha20)
     */
    val nonceBase64: String,

    /**
     * Message type
     * "TEXT" = text message, "VOICE" = voice clip
     */
    val messageType: String = MESSAGE_TYPE_TEXT,

    /**
     * Voice clip duration in seconds (only for VOICE messages)
     */
    val voiceDuration: Int? = null,

    /**
     * Voice clip file path (only for VOICE messages)
     * Stored in app's private storage: files/voice_messages/
     */
    val voiceFilePath: String? = null,

    /**
     * Optional: Media attachment type
     * null = text only, "image", "file", etc.
     */
    val attachmentType: String? = null,

    /**
     * Optional: Encrypted attachment data (Base64-encoded)
     */
    val attachmentData: String? = null,

    /**
     * Message has been read locally
     */
    val isRead: Boolean = false,

    /**
     * Self-destruct timestamp (Unix milliseconds)
     * null = no self-destruct, otherwise delete message after this time
     */
    val selfDestructAt: Long? = null,

    /**
     * Whether sender wants read receipts for this message
     */
    val requiresReadReceipt: Boolean = true,

    /**
     * Ping ID for Ping-Pong protocol
     * Used to match Pongs with Pings and track message delivery
     */
    val pingId: String? = null,

    /**
     * Encrypted payload for sender-side storage
     * Contains the encrypted message blob to send after receiving Pong
     */
    val encryptedPayload: String? = null,

    /**
     * Number of retry attempts for message delivery
     * Used for exponential backoff
     */
    val retryCount: Int = 0,

    /**
     * Last retry attempt timestamp (Unix milliseconds)
     * Used to calculate next retry time with exponential backoff
     */
    val lastRetryTimestamp: Long? = null,

    /**
     * Tracks if Ping was successfully delivered to receiver
     * true = receiver has the Ping (lock icon showing), stop retrying
     * false = delivery failed (receiver offline), keep retrying
     */
    val pingDelivered: Boolean = false,

    /**
     * Tracks if message payload was successfully delivered to receiver
     * true = receiver downloaded the message, stop retrying Pong/message
     * false = message not yet delivered, keep retrying if needed
     */
    val messageDelivered: Boolean = false
) {
    companion object {
        // Message type constants
        const val MESSAGE_TYPE_TEXT = "TEXT"
        const val MESSAGE_TYPE_VOICE = "VOICE"

        // Message status constants
        const val STATUS_PENDING = 0
        const val STATUS_SENT = 1
        const val STATUS_DELIVERED = 2
        const val STATUS_READ = 3
        const val STATUS_FAILED = 4
        const val STATUS_PING_SENT = 5      // Ping sent, waiting for Pong
        const val STATUS_PONG_SENT = 6      // Pong sent, waiting for message blob

        // Self-destruct duration (24 hours in milliseconds)
        const val SELF_DESTRUCT_DURATION = 24 * 60 * 60 * 1000L

        // Retry backoff settings
        const val INITIAL_RETRY_DELAY_MS = 5000L       // 5 seconds
        const val MAX_RETRY_DELAY_MS = 300000L         // 5 minutes
        const val RETRY_BACKOFF_MULTIPLIER = 2.0       // Double each time
    }
}
