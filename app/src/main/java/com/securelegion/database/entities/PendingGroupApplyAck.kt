package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index

/**
 * Durable per-peer ACK tracker for local CRDT group ops.
 */
@Entity(
    tableName = "pending_group_apply_ack",
    primaryKeys = ["groupId", "authorDeviceIdHex", "lamport", "targetPeerPubkeyHex"],
    indices = [
        Index(value = ["nextRetryAt"]),
        Index(value = ["createdAt"])
    ]
)
data class PendingGroupApplyAck(
    val groupId: String,
    val authorDeviceIdHex: String,
    val lamport: Long,
    val targetPeerPubkeyHex: String,
    val payload: ByteArray,
    val attemptCount: Int = 0,
    val nextRetryAt: Long,
    val createdAt: Long = System.currentTimeMillis()
)
