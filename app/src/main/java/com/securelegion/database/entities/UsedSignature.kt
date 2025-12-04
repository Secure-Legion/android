package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Stores transaction signatures that have been used for NLx402 payments.
 * This provides replay protection - the same transaction cannot be used
 * to fulfill multiple payment requests.
 */
@Entity(
    tableName = "used_signatures",
    indices = [Index(value = ["signature"], unique = true)]
)
data class UsedSignature(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /** The blockchain transaction signature */
    val signature: String,

    /** The quote ID this signature was used for */
    val quoteId: String,

    /** Token type (SOL, ZEC, etc.) */
    val token: String,

    /** Amount in smallest unit */
    val amount: Long,

    /** Timestamp when this signature was recorded */
    val usedAt: Long = System.currentTimeMillis()
)
