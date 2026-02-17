package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Ignore
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * GroupMessage entity stored in encrypted SQLCipher database
 * Represents an encrypted message sent or received in a group chat
 */
@Entity(
    tableName = "group_messages",
    foreignKeys = [
        ForeignKey(
            entity = Group::class,
            parentColumns = ["groupId"],
            childColumns = ["groupId"],
            onDelete = ForeignKey.CASCADE
        ),
        ForeignKey(
            entity = Contact::class,
            parentColumns = ["id"],
            childColumns = ["senderContactId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["groupId"]),
        Index(value = ["senderContactId"]),
        Index(value = ["timestamp"]),
        Index(value = ["messageId"], unique = true)
    ]
)
data class GroupMessage(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * Foreign key to Group table
     */
    val groupId: String,

    /**
     * Foreign key to Contact table - who sent this message
     * Null if sent by current user
     */
    val senderContactId: Long? = null,

    /**
     * Sender's display name (cached for performance)
     * Shows who sent the message in group chat
     */
    val senderName: String,

    /**
     * Unique message ID (for deduplication and acknowledgments)
     * Format: UUID or hash of (sender + timestamp + nonce)
     */
    val messageId: String,

    /**
     * Encrypted message content (Base64-encoded)
     * Encrypted with AES-256-GCM using the group's shared key
     */
    val encryptedContent: String,

    /**
     * Message direction: true = sent by us, false = received from group member
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
     * Verifies message authenticity from sender
     */
    val signatureBase64: String,

    /**
     * Encryption nonce (Base64-encoded, 12 bytes for AES-GCM)
     */
    val nonceBase64: String,

    /**
     * Message type
     * "TEXT" = text message, "VOICE" = voice clip, "IMAGE" = image, "SYSTEM" = system message
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
     * For images, files, etc.
     */
    val encryptedAttachment: String? = null,

    /**
     * Optional: Self-destruct timer in seconds
     * Message will be deleted after this many seconds
     */
    val selfDestructSeconds: Int? = null,

) {
    /**
     * Decrypted message content (not stored in database)
     * Populated at runtime for display in UI
     * @Ignore tells Room not to persist this field
     */
    @Ignore
    var decryptedContent: String? = null

    companion object {
        // Message status constants
        const val STATUS_PENDING = 0
        const val STATUS_SENT = 1
        const val STATUS_DELIVERED = 2
        const val STATUS_READ = 3
        const val STATUS_FAILED = 4

        // Message type constants
        const val MESSAGE_TYPE_TEXT = "TEXT"
        const val MESSAGE_TYPE_VOICE = "VOICE"
        const val MESSAGE_TYPE_IMAGE = "IMAGE"
        const val MESSAGE_TYPE_SYSTEM = "SYSTEM" // System messages like "Alice added Bob"
    }
}
