package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.Wallet

@Dao
interface WalletDao {
    @Query("SELECT * FROM wallets ORDER BY lastUsedAt DESC")
    suspend fun getAllWallets(): List<Wallet>

    @Query("SELECT * FROM wallets WHERE walletId = :walletId")
    suspend fun getWalletById(walletId: String): Wallet?

    @Query("SELECT * FROM wallets WHERE isMainWallet = 1 LIMIT 1")
    suspend fun getMainWallet(): Wallet?

    @Query("SELECT * FROM wallets WHERE solanaAddress = :address LIMIT 1")
    suspend fun getWalletByAddress(address: String): Wallet?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertWallet(wallet: Wallet)

    @Update
    suspend fun updateWallet(wallet: Wallet)

    @Query("UPDATE wallets SET lastUsedAt = :timestamp WHERE walletId = :walletId")
    suspend fun updateLastUsed(walletId: String, timestamp: Long)

    @Delete
    suspend fun deleteWallet(wallet: Wallet)

    @Query("DELETE FROM wallets WHERE walletId = :walletId AND isMainWallet = 0")
    suspend fun deleteWalletById(walletId: String): Int

    @Query("SELECT COUNT(*) FROM wallets WHERE isMainWallet = 0")
    suspend fun getWalletCount(): Int

    // Zcash-specific methods

    @Query("UPDATE wallets SET zcashUnifiedAddress = :ua, zcashAccountIndex = :accountIndex, zcashBirthdayHeight = :birthdayHeight WHERE walletId = :walletId")
    suspend fun updateZcashDerivedInfo(walletId: String, ua: String, accountIndex: Int, birthdayHeight: Long?)

    @Query("SELECT zcashUnifiedAddress FROM wallets WHERE walletId = :walletId")
    suspend fun getWalletZcashUnifiedAddress(walletId: String): String?

    @Query("SELECT zcashBirthdayHeight FROM wallets WHERE walletId = :walletId")
    suspend fun getBirthdayHeight(walletId: String): Long?

    @Query("UPDATE wallets SET isActiveZcash = 0 WHERE isActiveZcash = 1")
    suspend fun clearActiveZcashWallet()

    @Query("UPDATE wallets SET isActiveZcash = 1 WHERE walletId = :walletId")
    suspend fun setActiveZcashWallet(walletId: String)

    @Query("SELECT walletId FROM wallets WHERE isActiveZcash = 1 LIMIT 1")
    suspend fun getActiveZcashWalletId(): String?

    @Query("SELECT * FROM wallets WHERE isActiveZcash = 1 LIMIT 1")
    suspend fun getActiveZcashWallet(): Wallet?
}
