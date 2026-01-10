package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import android.util.Base64

/**
 * ContactKeyChain entity for progressive ephemeral key evolution
 *
 * Stores per-contact key chain state for messaging encryption with forward secrecy.
 * Keys are evolved forward using HMAC-SHA256 after each message, providing:
 * - Per-message forward secrecy (old messages stay secure if current key compromised)
 * - Post-compromise recovery (future messages become secure after compromise ends)
 * - Automatic key erasure (old chain keys cannot be recovered from new ones)
 *
 * Stored in encrypted SQLCipher database (AES-256).
 */
@Entity(
    tableName = "contact_key_chains",
    foreignKeys = [
        ForeignKey(
            entity = Contact::class,
            parentColumns = ["id"],
            childColumns = ["contactId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["contactId"], unique = true)
    ]
)
data class ContactKeyChain(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * Foreign key to Contact table
     * One-to-one relationship: each contact has exactly one key chain
     */
    val contactId: Long,

    /**
     * Root key (32 bytes) derived from X25519 shared secret using HKDF-SHA256
     * This is the initial key from which send/receive chain keys are derived
     * Stored as Base64 for database compatibility
     *
     * Derivation: HKDF-SHA256(shared_secret, info="SecureLegion-RootKey-v1")
     */
    val rootKeyBase64: String,

    /**
     * Send chain key (32 bytes) for encrypting outgoing messages
     * Evolved forward after each sent message using HMAC-SHA256
     * Stored as Base64 for database compatibility
     *
     * Evolution: new_key = HMAC-SHA256(current_key, 0x01)
     */
    val sendChainKeyBase64: String,

    /**
     * Receive chain key (32 bytes) for decrypting incoming messages
     * Evolved forward after each received message using HMAC-SHA256
     * Stored as Base64 for database compatibility
     *
     * Evolution: new_key = HMAC-SHA256(current_key, 0x01)
     */
    val receiveChainKeyBase64: String,

    /**
     * Send counter - monotonically increasing sequence number for outgoing messages
     * Included in wire format to prevent replay attacks
     * Incremented after each sent message
     */
    val sendCounter: Long = 0,

    /**
     * Receive counter - expected sequence number for incoming messages
     * Used to verify message ordering and prevent replay attacks
     * Incremented after each received message
     */
    val receiveCounter: Long = 0,

    /**
     * Unix timestamp (milliseconds) when key chain was created
     */
    val createdTimestamp: Long = System.currentTimeMillis(),

    /**
     * Unix timestamp (milliseconds) when keys were last evolved
     * Updated on every message send/receive
     */
    val lastEvolutionTimestamp: Long = System.currentTimeMillis()
)

/**
 * Extension property to decode root key from Base64 to ByteArray
 */
val ContactKeyChain.rootKeyBytes: ByteArray
    get() = Base64.decode(rootKeyBase64, Base64.NO_WRAP)

/**
 * Extension property to decode send chain key from Base64 to ByteArray
 */
val ContactKeyChain.sendChainKeyBytes: ByteArray
    get() = Base64.decode(sendChainKeyBase64, Base64.NO_WRAP)

/**
 * Extension property to decode receive chain key from Base64 to ByteArray
 */
val ContactKeyChain.receiveChainKeyBytes: ByteArray
    get() = Base64.decode(receiveChainKeyBase64, Base64.NO_WRAP)
