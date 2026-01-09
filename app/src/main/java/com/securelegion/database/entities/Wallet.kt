package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "wallets")
data class Wallet(
    @PrimaryKey
    val walletId: String,                     // Unique identifier for the wallet
    val name: String,                          // User-friendly name (e.g., "Wallet 1", "Trading Wallet")
    val solanaAddress: String,                 // Public Solana address
    val zcashAddress: String? = null,          // Zcash unified address (nullable for backward compatibility)
    val zcashUnifiedAddress: String? = null,   // Zcash unified address (per-wallet derived)
    val zcashAccountIndex: Int = 0,            // Zcash account index (default 0)
    val zcashBirthdayHeight: Long? = null,     // Block height when wallet was created (for faster sync)
    val isActiveZcash: Boolean = false,        // True if this is the active Zcash wallet for syncing
    val isMainWallet: Boolean,                 // True if this is a protected wallet
    val createdAt: Long,                       // Timestamp when wallet was created
    val lastUsedAt: Long                       // Timestamp when wallet was last used
)
