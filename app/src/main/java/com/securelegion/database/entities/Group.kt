package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * CRDT group entity stored in encrypted SQLCipher database.
 *
 * This is a lightweight index/cache for the group list UI.
 * The authoritative group state (members, messages, metadata) lives in the
 * CRDT op log and is rebuilt in Rust on demand via crdtLoadGroup().
 */
@Entity(
    tableName = "groups",
    indices = [
        Index(value = ["groupId"], unique = true)
    ]
)
data class Group(
    @PrimaryKey
    val groupId: String,

    /**
     * Display name of the group (cached from CRDT metadata)
     */
    val name: String,

    /**
     * XChaCha20-Poly1305 group secret (32 bytes, Base64-encoded).
     * Used to encrypt/decrypt all group messages.
     * Protected at rest by SQLCipher database encryption.
     */
    val groupSecretB64: String,

    /**
     * Group icon/emoji (optional)
     */
    val groupIcon: String? = null,

    /**
     * Unix timestamp when group was created (milliseconds)
     */
    val createdAt: Long,

    /**
     * Unix timestamp of last activity (milliseconds)
     * Updated when messages are sent/received
     */
    val lastActivityTimestamp: Long = createdAt,

    /**
     * Whether notifications are muted for this group
     */
    val isMuted: Boolean = false,

    /**
     * Optional group description (cached from CRDT metadata)
     */
    val description: String? = null,

    /**
     * Cached member count (accepted, non-removed members).
     * Updated by CrdtGroupManager on member changes.
     */
    val memberCount: Int = 0,

    /**
     * Cached last message preview text (decrypted).
     * Updated by CrdtGroupManager on message send/receive.
     */
    val lastMessagePreview: String? = null,

    /**
     * True if local user has been invited but hasn't accepted yet.
     * Set to true by checkAndProcessPendingInvites(), false by acceptInvite().
     */
    val isPendingInvite: Boolean = false,

    /**
     * Whether this group is pinned to the main messages tab
     */
    val isPinned: Boolean = false
)
