package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/** Highest account-root-signed roster accepted by this installation. */
@Entity(tableName = "device_rosters")
data class DeviceRoster(
    @PrimaryKey val accountEd: String,
    val epoch: Long,
    val issuedAtMs: Long,
    val primaryDeviceId: String,
    val signedRoster: ByteArray,
    val acceptedAtMs: Long
)
