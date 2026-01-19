package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Message entity stored in encrypted SQLCipher database
 * Represents an encrypted message sent or received from a contact
 *
 * ==================== PHASE 1.1: STABLE IDENTITY ====================
 * This entity ensures messages have stable identity across retries and crashes
 * by using deterministic ID generation based on stable inputs (not timestamps).
 *
 * ==================== PHASE 1.2: SORTED PUBKEYS (1-TO-1 CHATS) ====================
 * For 1-to-1 messaging, BOTH Alice and Bob must derive the same conversationId.
 * This requires lexicographically sorted public keys in the messageId hash.
 *
 * SCENARIO:
 * Alice sends to Bob:
 *   - Alice computes: conversationId = sort([AlicePubKey, BobPubKey])
 *   - Result: "AlicePubKey|BobPubKey" (alphabetically sorted)
 *
 * Bob receives from Alice:
 *   - Bob computes: conversationId = sort([AlicePubKey, BobPubKey])
 *   - Result: "AlicePubKey|BobPubKey" (SAME conversationId!)
 *   - Both derive same messageId → dedup works → ONE thread, not two
 *
 * WITHOUT SORTING (BROKEN):
 *   - Alice: conversationId = "AlicePubKey|BobPubKey"
 *   - Bob: conversationId = "BobPubKey|AlicePubKey" (DIFFERENT!)
 *   - → Two separate threads, broken dedup, "why do I see two chats?" bug
 *   - → ACKs and messages don't line up
 *
 * Critical Fields:
 * - messageNonce: Random 64-bit nonce generated ONCE at creation, NEVER regenerated
 * - messageId: Deterministic hash from (SORTED sender+recipient + plaintext + nonce)
 * - pingId: Random nonce for ping-pong protocol, stored with pingWireBytes for exact replay
 *
 * Why It Matters:
 * If messageNonce changes on retry, messageId changes → receiver gets ghost duplicates.
 * If messageId uses timestamp, crash recovery reconstructs different ID → desync.
 * If conversationId is not sorted, Alice and Bob get different IDs → two separate threads.
 * If retry doesn't reuse pingWireBytes/pingId, ghost pings appear.
 *
 * Invariants (DO NOT BREAK):
 * 1. messageNonce is set ONCE at creation and NEVER regenerated
 * 2. messageId never changes (stable across crashes, retries, app reinstalls)
 * 3. conversationId is ALWAYS computed from SORTED public keys (lexicographic order)
 * 4. Retries load from DB and reuse stored messageNonce/pingId/pingWireBytes
 * 5. messageId hash formula: SHA256(v1 || SORTED_conversationId || senderPub || recipientPub || plaintextHash || messageNonce)
 * 6. NO timestamp in messageId hash (breaks determinism after crash)
 *
 * Implementation Details (PHASE 1.2):
 *
 * SENDER PATH (sendMessage):
 *   1. Generate: messageNonce = SecureRandom.nextLong()
 *   2. Compute: conversationId = sort([ourKey, theirKey])
 *   3. Calculate: messageId = SHA256(v1 || conversationId || ourKey || theirKey || plaintextHash || messageNonce)
 *   4. Store: messageNonce in DB (never changes)
 *   5. Retry: Load from DB, recompute same messageId (uses stored messageNonce)
 *
 * RECEIVER PATH (receiveMessage):
 *   1. Receive: senderPublicKey as ByteArray parameter
 *   2. Generate: messageNonce = SecureRandom.nextLong() (local dedup only)
 *   3. Compute: conversationId = sort([senderKey, ourKey])
 *   4. Calculate: messageId = SHA256(v1 || conversationId || senderKey || ourKey || plaintextHash || messageNonce)
 *      NOTE: sort([senderKey, ourKey]) == sort([ourKey, senderKey])
 *      → Both sender and receiver get SAME messageId!
 *   5. Check: Database for duplicate (dedup blocks retries)
 *   6. Store: messageNonce in DB (for consistency)
 *
 * Testing:
 * - Send message, kill app, restart → same message (not duplicate) [PHASE 1.1]
 * - Retry same message 100 times → all retries use identical messageId [PHASE 1.1]
 * - Receive duplicate message → database dedup check blocks it [PHASE 1.1]
 * - Alice sends to Bob, Bob receives → both compute same conversationId [PHASE 1.2]
 * - Message dedup works on both sender and receiver side [PHASE 1.2]
 * - No two separate chat threads (sorted pubkeys prevent this) [PHASE 1.2]
 * - ACKs and messages line up correctly [PHASE 1.2]
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
        Index(value = ["messageId"], unique = true),
        Index(value = ["pingId"], unique = true)  // Ultimate dedup authority for received messages
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
     * Message nonce for deterministic ID generation (CRITICAL for retry dedup)
     *
     * HARD CONSTRAINT: Generated ONCE at message creation, NEVER regenerated
     *
     * Used in messageId hash calculation:
     * messageId = SHA-256(v1 || conversationId || senderPub || recipientPub || plaintextHash || messageNonce)
     *
     * This ensures:
     * - Retry with same DB row = same messageId = dedup
     * - App crash/recreate = same messageId = dedup
     * - Never use System.currentTimeMillis() in ID - breaks crash recovery
     *
     * If this field is NULL, retries will generate NEW IDs = GHOST DUPLICATES
     */
    val messageNonce: Long,
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
     * Retries re-send the EXACT SAME ciphertext bytes (no re-encryption on retry)
     * This makes message identity stable and prevents nonce reuse vulnerabilities
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
     * Next scheduled retry time (Unix milliseconds)
     * Calculated from retryCount and lastRetryTimestamp using exponential backoff
     * null = message delivered or not yet attempted
     */
    val nextRetryAtMs: Long? = null,

    /**
     * Last error message from failed send attempt
     * Helps diagnose why message delivery failed (max 256 chars, no newlines)
     * null = no error
     */
    val lastError: String? = null,

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
