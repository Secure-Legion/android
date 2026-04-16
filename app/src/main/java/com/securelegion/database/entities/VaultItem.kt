package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Secure Vault item — an encrypted media store for images, voice clips, and files.
 *
 * Accessible from Settings. Protected by an optional PIN (SHA-256 hash in Keystore).
 * Data is COPIED at save time — deleting the source message does not affect the vault.
 *
 * Type values:
 * - "image" — base64-encoded image data in `data`
 * - "voice" — file path in `data`, duration in `duration`
 * - "file"  — file path in `data`
 */
@Entity(
    tableName = "vault_items",
    indices = [Index(value = ["type"])]
)
data class VaultItem(
    @PrimaryKey
    val id: String,
    val type: String,            // "image", "voice", "file"
    val data: String?,           // base64 for images, file path for voice/files
    val fileName: String? = null,
    val duration: Double? = null, // seconds, voice only
    val senderName: String? = null, // who sent the original message
    val sourceTimestamp: Long? = null, // original message timestamp (epoch ms)
    val createdAtMs: Long
)
