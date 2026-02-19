package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Persists in-flight ping signer expectations so PONG verification survives process restart.
 *
 * Rust keeps an in-memory HashMap<ping_id, signer_pubkey> for fast-path verification.
 * This table is the slow-path fallback: on cache miss, Rust queries Room via JNI.
 *
 * Only stores public verification material (Ed25519 pubkey) — safe in encrypted DB.
 * TTL: 4 hours (Tor recipients may be offline; retries upsert to refresh expiry).
 */
@Entity(tableName = "pending_pings")
data class PendingPing(
    @PrimaryKey val pingId: String,
    val signerPubKey: ByteArray,
    val createdAtElapsed: Long,
    val expiresAtElapsed: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingPing) return false
        return pingId == other.pingId
    }

    override fun hashCode(): Int = pingId.hashCode()
}
