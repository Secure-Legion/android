package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index

/**
 * Persistent ping inbox for tracking message delivery state
 *
 * This table provides idempotent state tracking over Tor:
 * - PING_SEEN (0): Received notification, sent PING_ACK
 * - PONG_SENT (1): User authorized download, sent PONG
 * - MSG_STORED (2): Message stored in DB, sent MESSAGE_ACK
 *
 * Benefits:
 * - Survives app restarts
 * - Prevents duplicate notifications
 * - Prevents ghost lock icons
 * - Separates PING_ACK ("I saw it") from MESSAGE_ACK ("I stored it")
 */
@Entity(
    tableName = "ping_inbox",
    indices = [
        Index(value = ["contactId", "state"]),  // Query pending locks per contact
        Index(value = ["state"])                // Query all pending locks
    ],
    primaryKeys = ["pingId"]
)
data class PingInbox(
    /**
     * Deterministic message ID that ties PING → PONG → MESSAGE → ACK together
     * This is the primary key - one row per message
     */
    val pingId: String,

    /**
     * Contact who sent this message
     */
    val contactId: Long,

    /**
     * Current state of this message delivery
     * 0 = PING_SEEN, 1 = PONG_SENT, 2 = MSG_STORED
     */
    val state: Int,

    /**
     * When this ping was first seen
     */
    val firstSeenAt: Long,

    /**
     * When state was last updated
     */
    val lastUpdatedAt: Long,

    /**
     * When we last received a PING for this message (updates on duplicates)
     * Used to track retry frequency and prevent notification spam
     */
    val lastPingAt: Long,

    /**
     * When we sent PING_ACK (null if not yet sent)
     */
    val pingAckedAt: Long? = null,

    /**
     * When we sent PONG (null if not yet sent)
     */
    val pongSentAt: Long? = null,

    /**
     * When we sent MESSAGE_ACK (null if not yet sent)
     */
    val msgAckedAt: Long? = null,

    /**
     * How many times we've seen this PING (for debugging/metrics)
     */
    val attemptCount: Int = 1,

    /**
     * Encrypted ping wire bytes (Base64-encoded) for download/resend
     * Stored at PING_SEEN time so download can retrieve from DB instead of SharedPrefs
     * Format: [type_byte][sender_x25519_pubkey (32 bytes)][encrypted_payload]
     * Null after message is successfully downloaded (STATE_MSG_STORED)
     */
    val pingWireBytesBase64: String? = null
) {
    companion object {
        // State constants (Int for performance)
        const val STATE_PING_SEEN = 0    // PING received, PING_ACK sent
        const val STATE_PONG_SENT = 1    // User authorized, PONG sent
        const val STATE_MSG_STORED = 2   // Message in DB, MESSAGE_ACK sent
    }
}
