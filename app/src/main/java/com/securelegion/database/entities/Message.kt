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
     * Generated once when message is created, never changes (prevents ghost pings)
     */
    val pingId: String? = null,

    /**
     * Ping timestamp (epoch milliseconds)
     * Generated once when message is created, used with pingId to recreate same PingToken
     * This ensures retries use identical encrypted bytes (same nonce + same timestamp = safe)
     */
    val pingTimestamp: Long? = null,

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
    val messageDelivered: Boolean = false,

    /**
     * Tracks if TAP was successfully delivered to receiver
     * true = receiver acknowledged our TAP check-in (TAP_ACK received)
     * false = TAP not yet acknowledged
     */
    val tapDelivered: Boolean = false,

    /**
     * Tracks if PONG was successfully delivered to receiver
     * true = receiver acknowledged PONG arrival (PONG_ACK received)
     * false = PONG not yet acknowledged
     */
    val pongDelivered: Boolean = false,

    /**
     * Encrypted Ping wire bytes (Base64-encoded)
     * Stores the complete encrypted Ping token for retry without regenerating nonce
     * This prevents ghost pings by ensuring retries use the SAME Ping ID
     */
    val pingWireBytes: String? = null,

    // ==================== NLx402 PAYMENT FIELDS ====================

    /**
     * Payment quote JSON (for PAYMENT_REQUEST messages)
     * Contains quote_id, recipient, amount, token, expiry, etc.
     */
    val paymentQuoteJson: String? = null,

    /**
     * Payment status
     * null = not a payment message
     * "pending" = payment request sent, awaiting payment
     * "paid" = payment completed and verified
     * "expired" = quote expired without payment
     * "cancelled" = payment request cancelled
     */
    val paymentStatus: String? = null,

    /**
     * Transaction signature (for completed payments)
     * Solana/Zcash transaction ID
     */
    val txSignature: String? = null,

    /**
     * Token type for payment (SOL, ZEC, USDC, etc.)
     */
    val paymentToken: String? = null,

    /**
     * Payment amount in smallest unit (lamports/zatoshis)
     */
    val paymentAmount: Long? = null
) {
    companion object {
        // Message type constants
        const val MESSAGE_TYPE_TEXT = "TEXT"
        const val MESSAGE_TYPE_VOICE = "VOICE"
        const val MESSAGE_TYPE_IMAGE = "IMAGE"
        const val MESSAGE_TYPE_PAYMENT_REQUEST = "PAYMENT_REQUEST"
        const val MESSAGE_TYPE_PAYMENT_SENT = "PAYMENT_SENT"
        const val MESSAGE_TYPE_PAYMENT_ACCEPTED = "PAYMENT_ACCEPTED"

        // Payment status constants
        const val PAYMENT_STATUS_PENDING = "pending"
        const val PAYMENT_STATUS_PAID = "paid"
        const val PAYMENT_STATUS_EXPIRED = "expired"
        const val PAYMENT_STATUS_CANCELLED = "cancelled"

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
