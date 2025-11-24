package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Contact entity stored in encrypted SQLCipher database
 * Represents a contact with their identity and cryptographic keys
 */
@Entity(
    tableName = "contacts",
    indices = [
        Index(value = ["solanaAddress"], unique = true),
        Index(value = ["torOnionAddress"], unique = true)
    ]
)
data class Contact(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * Display name (username) of the contact
     */
    val displayName: String,

    /**
     * Solana wallet address (Base58-encoded)
     */
    val solanaAddress: String,

    /**
     * Ed25519 public key (32 bytes) for message signing/verification
     * Stored as Base64 for database compatibility
     */
    val publicKeyBase64: String,

    /**
     * X25519 public key (32 bytes) for message encryption (ECDH)
     * Stored as Base64 for database compatibility
     */
    val x25519PublicKeyBase64: String,

    /**
     * Tor v3 onion address with port (e.g., "abc123...xyz.onion:9050")
     * Used for establishing direct P2P connections
     */
    val torOnionAddress: String,

    /**
     * Unix timestamp when contact was added (milliseconds)
     */
    val addedTimestamp: Long,

    /**
     * Unix timestamp of last message exchange (milliseconds)
     * Updated on send or receive
     */
    val lastContactTimestamp: Long = addedTimestamp,

    /**
     * Trust level indicator
     * 0 = Untrusted, 1 = Verified, 2 = Trusted
     */
    val trustLevel: Int = 0,

    /**
     * Whether this contact will receive distress signals
     * True if contact is marked with blue star for emergency notifications
     */
    val isDistressContact: Boolean = false,

    /**
     * Optional notes about the contact
     */
    val notes: String? = null,

    /**
     * Whether this contact is blocked
     * Blocked contacts cannot send messages
     */
    val isBlocked: Boolean = false,

    /**
     * Friendship status - tracks bidirectional friend relationship
     * PENDING_SENT: You added them, waiting for them to add you back
     * CONFIRMED: Mutual friends - both have added each other, can message
     */
    val friendshipStatus: String = FRIENDSHIP_PENDING_SENT
) {
    companion object {
        // Trust levels
        const val TRUST_UNTRUSTED = 0
        const val TRUST_VERIFIED = 1
        const val TRUST_TRUSTED = 2

        // Friendship status
        const val FRIENDSHIP_PENDING_SENT = "PENDING_SENT"
        const val FRIENDSHIP_CONFIRMED = "CONFIRMED"
    }
}
