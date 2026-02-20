package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Persistent queue for group ops that couldn't be delivered because
 * the target member's routing info (onion address) is not yet known.
 *
 * Instead of silently dropping messages when a member isn't in the Contact
 * table or GroupPeer table, we persist them here and retry when routing arrives.
 *
 * Retry strategy: exponential backoff (30s → 60s → 120s → ...), max 20 attempts.
 * Entries are flushed immediately when a ROUTING_UPDATE provides the missing onion.
 * Stale entries (>1 hour or 20 attempts) are cleaned up by the sweep loop.
 */
@Entity(
    tableName = "pending_group_delivery",
    indices = [
        Index(value = ["groupId", "targetPubkeyHex"])
    ]
)
data class PendingGroupDelivery(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val groupId: String,            // 64-char hex
    val targetPubkeyHex: String,    // Ed25519 pubkey of unreachable member
    val wireType: Int,              // e.g. 0x30 for CRDT_OPS
    val payload: ByteArray,         // full wire payload to send
    val attemptCount: Int = 0,
    val nextRetryAt: Long = 0,
    val createdAt: Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingGroupDelivery) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}
