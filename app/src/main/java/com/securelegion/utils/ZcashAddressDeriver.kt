package com.securelegion.utils

import android.util.Log
import cash.z.ecc.android.bip39.Mnemonics
import cash.z.ecc.android.bip39.toSeed
import cash.z.ecc.android.sdk.model.ZcashNetwork
import cash.z.ecc.android.sdk.model.Zip32AccountIndex
import cash.z.ecc.android.sdk.tool.DerivationTool

/**
 * Zcash Address Deriver
 *
 * Offline derivation of Zcash unified addresses from seed phrases.
 * Does NOT require a full synchronizer - perfect for wallet import flows.
 */
object ZcashAddressDeriver {
    private const val TAG = "ZcashAddressDeriver"

    /**
     * Derive unified address from seed phrase (offline)
     *
     * @param seedPhrase BIP39 mnemonic (12 or 24 words)
     * @param network Zcash network (mainnet or testnet)
     * @param accountIndex Account derivation index (default 0)
     * @return Unified address string
     */
    suspend fun deriveUnifiedAddressFromSeed(
        seedPhrase: String,
        network: ZcashNetwork = ZcashNetwork.Mainnet,
        accountIndex: Int = 0
    ): String {
        try {
            // 1) Convert mnemonic -> seed bytes (64 bytes from BIP39)
            val mnemonicWords = seedPhrase.trim().split("\\s+".toRegex())
            val seedBytes = Mnemonics.MnemonicCode(mnemonicWords.joinToString(" ")).toSeed()

            // 2) Derive unified spending key for account index
            val derivationTool = DerivationTool.getInstance()
            val unifiedSpendingKey = derivationTool.deriveUnifiedSpendingKey(
                seed = seedBytes,
                network = network,
                accountIndex = Zip32AccountIndex.new(accountIndex.toLong())
            )

            // 3) Derive unified address from spending key
            // Note: The ECC SDK's DerivationTool doesn't expose deriveUnifiedAddress directly.
            // We need to use the viewing key to derive the address.
            val unifiedFullViewingKey = derivationTool.deriveUnifiedFullViewingKey(
                usk = unifiedSpendingKey,
                network = network
            )

            val unifiedAddress = derivationTool.deriveUnifiedAddress(
                viewingKey = unifiedFullViewingKey.encoding,
                network = network
            )

            Log.d(TAG, "Successfully derived UA for account $accountIndex")
            return unifiedAddress

        } catch (e: Exception) {
            Log.e(TAG, "Failed to derive unified address from seed", e)
            throw IllegalStateException("Failed to derive Zcash address: ${e.message}", e)
        }
    }

    /**
     * Validate if a seed phrase is valid for Zcash
     */
    fun isValidSeedPhrase(seedPhrase: String): Boolean {
        return try {
            val words = seedPhrase.trim().split("\\s+".toRegex())
            words.size == 12 || words.size == 24
        } catch (e: Exception) {
            false
        }
    }
}
