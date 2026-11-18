package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Public endpoint authorized by the current signed roster only. */
@Entity(tableName = "authorized_devices", indices = [Index(value = ["accountEd"])])
data class AuthorizedDevice(
    @PrimaryKey val deviceId: String,
    val accountEd: String,
    val displayName: String,
    val syncOnion: String,
    val deviceEd: ByteArray,
    val deviceX: ByteArray,
    val mlKemPublic: ByteArray,
    val certificate: ByteArray,
    val capabilities: Int,
    val issuedAtMs: Long,
    val expiresAtMs: Long,
    val rosterEpoch: Long,
    val isSelf: Boolean
)
