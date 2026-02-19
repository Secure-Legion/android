package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * CRDT operation log entry — the source of truth for group state.
 *
 * All group mutations (create, invite, message, etc.) are stored as signed ops.
 * On startup, ops are loaded from this table and replayed via crdtLoadGroup()
 * to rebuild in-memory CRDT state in Rust.
 */
@Entity(
    tableName = "crdt_op_log",
    indices = [
        Index(value = ["groupId"]),
        Index(value = ["groupId", "lamport"])
    ]
)
data class CrdtOpLog(
    /**
     * Unique op ID from Rust: "authorHex:lamportHex:nonceHex"
     */
    @PrimaryKey
    val opId: String,

    /**
     * Group this op belongs to (32-byte hex, 64 chars)
     */
    val groupId: String,

    /**
     * Op type: "GroupCreate", "MemberInvite", "MemberAccept", "MemberRemove",
     * "RoleSet", "MsgAdd", "MsgEdit", "MsgDelete", "ReactionSet", "MetadataSet"
     */
    val opType: String,

    /**
     * Raw serialized op bytes (bincode format from Rust).
     * This is what gets fed to crdtLoadGroup/crdtApplyOps.
     */
    val opBytes: ByteArray,

    /**
     * Lamport timestamp for causal ordering
     */
    val lamport: Long,

    /**
     * Local wall-clock time when this op was stored (milliseconds)
     */
    val createdAt: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CrdtOpLog) return false
        return opId == other.opId
    }

    override fun hashCode(): Int = opId.hashCode()
}
