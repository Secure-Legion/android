package com.securelegion.services

import android.content.Context
import android.util.Log
import cash.z.ecc.android.bip39.Mnemonics
import cash.z.ecc.android.bip39.toSeed
import cash.z.ecc.android.sdk.Synchronizer
import cash.z.ecc.android.sdk.WalletInitMode
import cash.z.ecc.android.sdk.ext.convertZatoshiToZec
import cash.z.ecc.android.sdk.model.AccountCreateSetup
import cash.z.ecc.android.sdk.model.BlockHeight
import cash.z.ecc.android.sdk.model.FirstClassByteArray
import cash.z.ecc.android.sdk.model.TransactionSubmitResult
import cash.z.ecc.android.sdk.model.UnifiedSpendingKey
import cash.z.ecc.android.sdk.model.WalletBalance
import cash.z.ecc.android.sdk.model.Zatoshi
import cash.z.ecc.android.sdk.model.ZcashNetwork
import cash.z.ecc.android.sdk.model.Zip32AccountIndex
import cash.z.ecc.android.sdk.tool.DerivationTool
import co.electriccoin.lightwallet.client.model.LightWalletEndpoint
import com.securelegion.crypto.KeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * Zcash Service
 * Manages Zcash wallet functionality using the official Zcash Android SDK (v2.4.0+)
 *
 * Provides interface for sending/receiving ZEC with privacy
 * Uses shielded (Sapling/Orchard) addresses for transactions
 *
 * Architecture:
 * - Uses Zcash Synchronizer for blockchain interaction (routes through Tor)
 * - Derives keys from BIP39 seed phrase
 * - Supports both mainnet and testnet
 * - Syncs blocks in background, caches wallet state
 * - All traffic routed through Tor SOCKS proxy for privacy
 */
class ZcashService(private val context: Context) {

    private val keyManager = KeyManager.getInstance(context)

    // Configure OkHttpClient to use Tor SOCKS5 proxy for privacy (price fetching, etc.)
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050)))
        .build()

    companion object {
        private const val TAG = "ZcashService"

        // Zatoshis per ZEC (1 ZEC = 100 million zatoshis)
        private const val ZATOSHIS_PER_ZEC = 100_000_000L

        // CoinGecko price API (free, no key required)
        private const val COINGECKO_API = "https://api.coingecko.com/api/v3/simple/price?ids=zcash&vs_currencies=usd"

        // Lightwalletd servers (Zcash Foundation public servers)
        private const val MAINNET_LIGHTWALLETD_HOST = "mainnet.lightwalletd.com"
        private const val MAINNET_LIGHTWALLETD_PORT = 9067

        private const val TESTNET_LIGHTWALLETD_HOST = "lightwalletd.testnet.electriccoin.co"
        private const val TESTNET_LIGHTWALLETD_PORT = 9067

        // Synchronizer alias for this wallet instance
        private const val WALLET_ALIAS = "securelegion_wallet"

        // Account key source identifier
        private const val ACCOUNT_KEY_SOURCE = "securelegion"

        // Default account index
        private const val DEFAULT_ACCOUNT_INDEX = 0L

        @Volatile
        private var instance: ZcashService? = null

        fun getInstance(context: Context): ZcashService {
            return instance ?: synchronized(this) {
                instance ?: ZcashService(context.applicationContext).also { instance = it }
            }
        }
    }

    // Synchronizer instance (lazy initialized)
    private var synchronizer: Synchronizer? = null
    private var network: ZcashNetwork = ZcashNetwork.Mainnet

    /**
     * Initialize Zcash wallet from seed phrase
     * @param seedPhrase BIP39 mnemonic (12 or 24 words)
     * @param useTestnet true for testnet, false for mainnet
     * @return Unified address for receiving ZEC
     */
    suspend fun initialize(
        seedPhrase: String,
        useTestnet: Boolean = false
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Initializing Zcash wallet (testnet: $useTestnet)")

            // Set network
            network = if (useTestnet) ZcashNetwork.Testnet else ZcashNetwork.Mainnet

            // Convert seed phrase to bytes using Zcash BIP39 library
            val seedBytes = Mnemonics.MnemonicCode(seedPhrase.toCharArray()).toSeed()

            // Get latest checkpoint for wallet birthday
            val birthday = BlockHeight.ofLatestCheckpoint(context, network)

            // Create lightwalletd endpoint
            val endpoint = if (useTestnet) {
                LightWalletEndpoint(TESTNET_LIGHTWALLETD_HOST, TESTNET_LIGHTWALLETD_PORT, true)
            } else {
                LightWalletEndpoint(MAINNET_LIGHTWALLETD_HOST, MAINNET_LIGHTWALLETD_PORT, true)
            }

            // Create synchronizer with Tor routing enabled
            synchronizer = Synchronizer.new(
                context = context,
                zcashNetwork = network,
                alias = WALLET_ALIAS,
                lightWalletEndpoint = endpoint,
                birthday = birthday,
                walletInitMode = WalletInitMode.RestoreWallet,
                setup = AccountCreateSetup(
                    accountName = "SecureLegion Wallet",
                    keySource = ACCOUNT_KEY_SOURCE,
                    seed = FirstClassByteArray(seedBytes)
                ),
                isTorEnabled = true, // Route all SDK traffic through Tor for privacy
                isExchangeRateEnabled = false // Disable exchange rate fetching for privacy
            )

            // Derive unified address
            val derivationTool = DerivationTool.getInstance()

            // First derive the spending key
            val spendingKey = derivationTool.deriveUnifiedSpendingKey(
                seed = seedBytes,
                network = network,
                accountIndex = Zip32AccountIndex.new(DEFAULT_ACCOUNT_INDEX)
            )

            // Then derive the viewing key from the spending key
            val viewingKey = derivationTool.deriveUnifiedFullViewingKey(
                usk = spendingKey,
                network = network
            )

            val unifiedAddress = derivationTool.deriveUnifiedAddress(
                viewingKey.encoding,
                network
            )

            // Store Zcash address in KeyManager
            keyManager.setZcashAddress(unifiedAddress)

            Log.i(TAG, "Zcash wallet initialized successfully")
            Log.d(TAG, "Unified address: $unifiedAddress")

            Result.success(unifiedAddress)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Zcash wallet", e)
            (synchronizer as? AutoCloseable)?.close()
            synchronizer = null
            Result.failure(e)
        }
    }

    /**
     * Get ZEC balance for the wallet
     * Requires synchronizer to be initialized
     * @return Balance in ZEC (e.g., 0.5 ZEC)
     */
    suspend fun getBalance(): Result<Double> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching ZEC balance")

            val sync = synchronizer
            if (sync == null) {
                Log.w(TAG, "Synchronizer not initialized, balance unavailable")
                return@withContext Result.success(0.0)
            }

            // Get accounts
            val accounts = sync.getAccounts()
            if (accounts.isEmpty()) {
                Log.w(TAG, "No accounts found")
                return@withContext Result.success(0.0)
            }

            val account = accounts[DEFAULT_ACCOUNT_INDEX.toInt()]

            // Get wallet balances
            val balances = sync.walletBalances.filterNotNull().first()
            val walletBalance = balances[account.accountUuid]

            if (walletBalance == null) {
                Log.w(TAG, "Wallet balance not available yet")
                return@withContext Result.success(0.0)
            }

            // Get shielded balance (Sapling + Orchard)
            val saplingBalance = walletBalance.sapling
            val orchardBalance = walletBalance.orchard

            // Convert to ZEC (available balance only)
            val totalAvailableZatoshi = saplingBalance.available.value + orchardBalance.available.value
            val balanceZEC = totalAvailableZatoshi.toDouble() / ZATOSHIS_PER_ZEC

            Log.i(TAG, "Balance: $balanceZEC ZEC ($totalAvailableZatoshi zatoshis)")
            Log.d(TAG, "  Sapling: ${saplingBalance.available.convertZatoshiToZec()} ZEC")
            Log.d(TAG, "  Orchard: ${orchardBalance.available.convertZatoshiToZec()} ZEC")

            Result.success(balanceZEC)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch balance", e)
            Result.failure(e)
        }
    }

    /**
     * Get Zcash unified address for receiving
     * @return Unified address (starts with 'u1' for mainnet, 'utest' for testnet)
     */
    fun getReceiveAddress(): String? {
        val address = keyManager.getZcashAddress()
        Log.d(TAG, "Receive address: ${address ?: "not initialized"}")
        return address
    }

    /**
     * Get Zcash unified address from synchronizer
     * This is the preferred method as it gets the address directly from the SDK
     * @return Unified address or null if not initialized
     */
    suspend fun getUnifiedAddress(): String? = withContext(Dispatchers.IO) {
        val sync = synchronizer ?: return@withContext null

        try {
            val accounts = sync.getAccounts()
            if (accounts.isEmpty()) return@withContext null

            val account = accounts[DEFAULT_ACCOUNT_INDEX.toInt()]
            sync.getUnifiedAddress(account)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get unified address", e)
            null
        }
    }

    /**
     * Send ZEC to an address (shielded transaction)
     * Requires synchronizer to be initialized and synced
     *
     * @param toAddress Recipient's Zcash address (unified, Sapling, or transparent)
     * @param amountZEC Amount in ZEC to send
     * @param memo Optional encrypted memo (up to 512 bytes, only for shielded transactions)
     * @return Transaction ID if successful
     */
    suspend fun sendTransaction(
        toAddress: String,
        amountZEC: Double,
        memo: String = ""
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending $amountZEC ZEC to $toAddress")

            val sync = synchronizer
            if (sync == null) {
                return@withContext Result.failure(
                    IllegalStateException("Synchronizer not initialized. Call initialize() first.")
                )
            }

            // Check sync status
            val currentStatus = sync.status.first()
            if (currentStatus != Synchronizer.Status.SYNCED) {
                return@withContext Result.failure(
                    IllegalStateException("Wallet is not synced. Current status: $currentStatus")
                )
            }

            // Convert ZEC to zatoshis
            val zatoshis = Zatoshi((amountZEC * ZATOSHIS_PER_ZEC).toLong())

            // Get account
            val accounts = sync.getAccounts()
            if (accounts.isEmpty()) {
                return@withContext Result.failure(
                    IllegalStateException("No accounts available")
                )
            }
            val account = accounts[DEFAULT_ACCOUNT_INDEX.toInt()]

            // Get spending key from seed
            val seedBytes = keyManager.getWalletSeed()
                ?: return@withContext Result.failure(
                    IllegalStateException("Wallet seed not available")
                )

            val spendingKey = DerivationTool.getInstance().deriveUnifiedSpendingKey(
                seed = seedBytes,
                network = network,
                accountIndex = Zip32AccountIndex.new(DEFAULT_ACCOUNT_INDEX)
            )

            // Create transaction proposal
            val proposal = sync.proposeTransfer(
                account = account,
                recipient = toAddress,
                amount = zatoshis,
                memo = memo
            )

            // Create and submit transaction
            Log.d(TAG, "Creating and submitting transaction...")
            val txResultFlow = sync.createProposedTransactions(
                proposal = proposal,
                usk = spendingKey
            )

            // Collect the first result from the flow
            val firstResult = txResultFlow.first()

            // Check if submission was successful
            when (firstResult) {
                is TransactionSubmitResult.Success -> {
                    val txId = firstResult.txIdString()
                    Log.i(TAG, "Transaction submitted successfully: $txId")
                    Result.success(txId)
                }
                is TransactionSubmitResult.Failure -> {
                    val errorMsg = "Transaction failed (code ${firstResult.code}): ${firstResult.description ?: "Unknown error"}"
                    Log.e(TAG, errorMsg)
                    Result.failure(Exception(errorMsg))
                }
                is TransactionSubmitResult.NotAttempted -> {
                    val txId = firstResult.txIdString()
                    Log.w(TAG, "Transaction created but not submitted: $txId")
                    Result.failure(Exception("Transaction was not submitted to the network"))
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send transaction", e)
            Result.failure(e)
        }
    }

    /**
     * Get ZEC price in USD from CoinGecko (over Tor)
     * @return Price in USD
     */
    suspend fun getZecPrice(): Result<Double> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching ZEC price from CoinGecko (over Tor)")

            val request = Request.Builder()
                .url(COINGECKO_API)
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.e(TAG, "Failed to fetch ZEC price: HTTP ${response.code}")
                    return@withContext Result.failure(IOException("HTTP ${response.code}"))
                }

                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response"))

                val json = JSONObject(responseBody)
                val zcash = json.getJSONObject("zcash")
                val priceUSD = zcash.getDouble("usd")

                Log.i(TAG, "ZEC price: $$priceUSD")
                return@withContext Result.success(priceUSD)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch ZEC price", e)
            return@withContext Result.failure(e)
        }
    }

    /**
     * Get synchronization progress
     * @return Percentage (0-100) of blocks synced
     */
    suspend fun getSyncProgress(): Result<Int> = withContext(Dispatchers.IO) {
        try {
            val sync = synchronizer ?: return@withContext Result.success(0)

            val progress = sync.progress.first()
            val percentage = progress.toPercentage()

            Log.d(TAG, "Sync progress: $percentage%")
            Result.success(percentage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get sync progress", e)
            Result.failure(e)
        }
    }

    /**
     * Get sync status
     * @return Status string (SYNCING, SYNCED, DISCONNECTED, etc.)
     */
    suspend fun getSyncStatus(): Result<String> = withContext(Dispatchers.IO) {
        try {
            val sync = synchronizer ?: return@withContext Result.success("NOT_INITIALIZED")

            val status = sync.status.first()
            Log.d(TAG, "Sync status: $status")
            Result.success(status.toString())

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get sync status", e)
            Result.failure(e)
        }
    }

    /**
     * Get recent transactions
     * Requires synchronizer to be initialized
     *
     * @param limit Maximum number of transactions to return
     * @return List of transaction info
     */
    suspend fun getRecentTransactions(limit: Int = 10): Result<List<TransactionInfo>> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching recent transactions (limit: $limit)")

            val sync = synchronizer
            if (sync == null) {
                Log.w(TAG, "Synchronizer not initialized")
                return@withContext Result.success(emptyList())
            }

            // TODO: Implement proper transaction history parsing
            // The SDK provides transactions through flows:
            // - sync.transactions (all transactions)
            // The TransactionOverview object contains transaction details
            Log.w(TAG, "Transaction history not yet implemented")
            Result.success(emptyList())

        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch transactions", e)
            Result.failure(e)
        }
    }

    /**
     * Transaction info model (matches SolanaService structure)
     */
    data class TransactionInfo(
        val txId: String,
        val timestamp: Long,
        val amount: Double, // in ZEC
        val type: String, // "send" or "receive"
        val status: String, // "confirmed", "pending", or "failed"
        val otherPartyAddress: String,
        val memo: String = ""
    )

    /**
     * Start background synchronization
     * This downloads and scans blocks from the network
     *
     * Note: The synchronizer starts automatically when created
     * This method is kept for compatibility but is essentially a no-op
     */
    suspend fun startSynchronization(): Result<Unit> {
        val sync = synchronizer
        if (sync == null) {
            Log.w(TAG, "Cannot start synchronization - synchronizer not initialized")
            return Result.failure(IllegalStateException("Synchronizer not initialized"))
        }

        Log.d(TAG, "Synchronizer is running (started automatically on creation)")
        return Result.success(Unit)
    }

    /**
     * Stop synchronizer and cleanup resources
     */
    fun shutdown() {
        try {
            (synchronizer as? AutoCloseable)?.close()
            synchronizer = null
            Log.d(TAG, "Zcash service shutdown complete")
        } catch (e: Exception) {
            Log.e(TAG, "Error during shutdown", e)
        }
    }
}
