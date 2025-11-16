package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "wallets")
data class Wallet(
    @PrimaryKey
    val walletId: String,              // Unique identifier for the wallet
    val name: String,                   // User-friendly name (e.g., "Wallet 1", "Trading Wallet")
    val solanaAddress: String,          // Public Solana address
    val isMainWallet: Boolean,          // True if this is the main account wallet
    val createdAt: Long,                // Timestamp when wallet was created
    val lastUsedAt: Long                // Timestamp when wallet was last used
)
