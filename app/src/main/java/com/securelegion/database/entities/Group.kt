package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Group entity stored in encrypted SQLCipher database
 * Represents a group chat with multiple members using shared key encryption
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
     * Display name of the group
     */
    val name: String,

    /**
     * AES-256 group key (32 bytes) for message encryption
     * Encrypted with user's master key, stored as Base64
     * This key is shared among all group members
     */
    val encryptedGroupKeyBase64: String,

    /**
     * 6-digit PIN for group access/verification
     */
    val groupPin: String,

    /**
     * Group icon/emoji (optional)
     * Future: could be emoji character or icon ID
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
     * Whether current user is admin of this group
     * Admins can add/remove members, change settings
     */
    val isAdmin: Boolean = true,

    /**
     * Whether notifications are muted for this group
     */
    val isMuted: Boolean = false,

    /**
     * Optional group description
     */
    val description: String? = null
)
