package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import android.util.Base64

/**
 * Contact entity stored in encrypted SQLCipher database
 * Represents a contact with their identity and cryptographic keys
 */
@Entity(
    tableName = "contacts",
    indices = [
        Index(value = ["solanaAddress"], unique = true),
        Index(value = ["friendRequestOnion"], unique = false),  // NEW - not unique (can be empty for migrated)
        Index(value = ["messagingOnion"], unique = false)       // NEW
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
     * DEPRECATED - Tor v3 onion address (v1.0 single .onion)
     * Kept for migration compatibility - use messagingOnion instead
     */
    @Deprecated("Use friendRequestOnion and messagingOnion instead")
    val torOnionAddress: String? = null,

    /**
     * NEW (v2.0) - Public .onion address for friend requests (port 9151)
     * Empty string for contacts from v1.0 (before migration)
     */
    val friendRequestOnion: String = "",

    /**
     * NEW (v2.0) - Private .onion address for messaging (port 8080)
     * Same as old torOnionAddress for migrated contacts
     */
    val messagingOnion: String? = null,

    /**
     * NEW (v2.0) - IPFS CID for their contact card (deterministic)
     */
    val ipfsCid: String? = null,

    /**
     * NEW (v2.0) - Their 10-digit PIN (encrypted in database)
     * Format: XXX-XXX-XXXX
     */
    val contactPin: String? = null,

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

/**
 * Extension property to decode Ed25519 public key from Base64 to ByteArray
 */
val Contact.ed25519PublicKeyBytes: ByteArray
    get() = Base64.decode(publicKeyBase64, Base64.NO_WRAP)

/**
 * Extension property to decode X25519 public key from Base64 to ByteArray
 */
val Contact.x25519PublicKeyBytes: ByteArray
    get() = Base64.decode(x25519PublicKeyBase64, Base64.NO_WRAP)
