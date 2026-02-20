package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Routing-only storage for group members who may not be in the Contact (friend) table.
 *
 * When an admin invites their friend to a group, other members who aren't friends with
 * the invitee need routing info (onion address) to reach them. This table stores that
 * info per-group, separate from Contact/friend status.
 *
 * Populated via:
 * - ROUTING_UPDATE (0x35) wire messages during invite flow
 * - Self-healing ROUTING_REQUEST/RESPONSE
 * - Seeded from Contact table on join
 *
 * NOT a contact: being in GroupPeer does NOT grant DM capability.
 */
@Entity(
    tableName = "group_peers",
    indices = [
        Index(value = ["groupId", "pubkeyHex"], unique = true),
        Index(value = ["groupId"]),
        Index(value = ["groupId", "x25519PubkeyHex"])
    ]
)
data class GroupPeer(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val groupId: String,           // 64-char hex (32 bytes)
    val pubkeyHex: String,         // Ed25519 public key, 64-char hex
    val x25519PubkeyHex: String,   // X25519 public key, 64-char hex
    val messagingOnion: String,    // .onion address (normalized: lowercase, trimmed)
    val displayName: String,       // SecureLegion username
    val addedAt: Long = System.currentTimeMillis()
)
