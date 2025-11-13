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
    val requiresReadReceipt: Boolean = true
) {
    companion object {
        // Message status constants
        const val STATUS_PENDING = 0
        const val STATUS_SENT = 1
        const val STATUS_DELIVERED = 2
        const val STATUS_READ = 3
        const val STATUS_FAILED = 4

        // Self-destruct duration (24 hours in milliseconds)
        const val SELF_DESTRUCT_DURATION = 24 * 60 * 60 * 1000L
    }
}
