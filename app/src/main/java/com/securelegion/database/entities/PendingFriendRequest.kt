package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Database entity for tracking friend request state
 *
 * This replaces the fragile SharedPreferences-based tracking with
 * DB-authoritative state management for friend requests.
 *
 * Phase Flow:
 * - PHASE_1_SENT: Sent Phase 1 PIN-encrypted request, awaiting Phase 2 response
 * - PHASE_2_SENT: Sent Phase 2 X25519-encrypted acceptance, awaiting Phase 3 ACK
 * - PHASE_3_SENT: Sent Phase 3 ACK confirmation, friend request complete
 */
@Entity(
    tableName = "pending_friend_requests",
    indices = [
        Index(value = ["recipientOnion"], unique = false),
        Index(value = ["phase"], unique = false),
        Index(value = ["needsRetry"], unique = false)
    ]
)
data class PendingFriendRequest(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * Recipient's .onion address (friend-request.onion or messaging.onion)
     */
    val recipientOnion: String,

    /**
     * Recipient's PIN (for Phase 1 encryption)
     * Stored encrypted in database via SQLCipher
     */
    val recipientPin: String? = null,

    /**
     * Current phase of friend request
     * 1 = Phase 1 sent (awaiting Phase 2)
     * 2 = Phase 2 sent (awaiting Phase 3 ACK)
     * 3 = Phase 3 ACK sent (request complete)
     */
    val phase: Int,

    /**
     * Direction of friend request
     * "outgoing" = we initiated
     * "incoming" = they initiated
     */
    val direction: String,

    /**
     * Whether this request needs retry
     * Set to true on send failure or app start (convergence)
     */
    val needsRetry: Boolean = false,

    /**
     * Whether friend request is complete (Phase 3 confirmed)
     */
    val isCompleted: Boolean = false,

    /**
     * Whether friend request has permanently failed
     * Set to true after terminal failure (e.g., missing required data)
     */
    val isFailed: Boolean = false,

    /**
     * Unix timestamp of last successful send attempt (milliseconds)
     */
    val lastSentAt: Long? = null,

    /**
     * Unix timestamp when next retry should occur (milliseconds)
     * Calculated using exponential backoff
     */
    val nextRetryAt: Long = 0,

    /**
     * Number of retry attempts
     * Used for exponential backoff calculation
     */
    val retryCount: Int = 0,

    /**
     * Phase 1 payload JSON (for retry)
     * Contains: username, friend_request_onion, x25519_public_key, kyber_public_key
     */
    val phase1PayloadJson: String? = null,

    /**
     * Phase 2 payload (encrypted bytes as Base64)
     * Stored for retry if Phase 2 send fails
     */
    val phase2PayloadBase64: String? = null,

    /**
     * Received contact card JSON
     * Populated when we receive their Phase 2 or Phase 3
     */
    val contactCardJson: String? = null,

    /**
     * Hybrid shared secret (X25519 + Kyber) for key chain initialization
     * Stored as Base64
     */
    val hybridSharedSecretBase64: String? = null,

    /**
     * Unix timestamp when friend request was created (milliseconds)
     */
    val createdAt: Long = System.currentTimeMillis(),

    /**
     * Unix timestamp when friend request was completed (milliseconds)
     */
    val completedAt: Long? = null,

    /**
     * Contact ID (set when contact is added to database)
     * Links friend request to the created Contact entity
     */
    val contactId: Long? = null
) {
    companion object {
        // Phase constants
        const val PHASE_1_SENT = 1
        const val PHASE_2_SENT = 2
        const val PHASE_3_SENT = 3

        // Direction constants
        const val DIRECTION_OUTGOING = "outgoing"
        const val DIRECTION_INCOMING = "incoming"
    }
}
