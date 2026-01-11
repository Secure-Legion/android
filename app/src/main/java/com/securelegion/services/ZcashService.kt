package com.securelegion.services

import android.content.Context
import android.util.Log
import cash.z.ecc.android.bip39.Mnemonics
import cash.z.ecc.android.bip39.toSeed
import cash.z.ecc.android.sdk.Synchronizer
import cash.z.ecc.android.sdk.WalletInitMode
import cash.z.ecc.android.sdk.ext.convertZatoshiToZec
import cash.z.ecc.android.sdk.model.AccountBalance
import cash.z.ecc.android.sdk.model.AccountCreateSetup
import cash.z.ecc.android.sdk.model.BlockHeight
import cash.z.ecc.android.sdk.model.FirstClassByteArray
import cash.z.ecc.android.sdk.model.TransactionSubmitResult
import cash.z.ecc.android.sdk.model.UnifiedSpendingKey
import cash.z.ecc.android.sdk.model.Zatoshi
import cash.z.ecc.android.sdk.model.ZcashNetwork
import cash.z.ecc.android.sdk.model.Zip32AccountIndex
import cash.z.ecc.android.sdk.tool.DerivationTool
import co.electriccoin.lightwallet.client.model.LightWalletEndpoint
import com.securelegion.crypto.KeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.web3j.crypto.Bip32ECKeyPair
import org.web3j.crypto.MnemonicUtils
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.MessageDigest
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

        // Lightwalletd servers - using na.zec.rocks (North America, Tor-friendly)
        private const val MAINNET_LIGHTWALLETD_HOST = "na.zec.rocks"
        private const val MAINNET_LIGHTWALLETD_PORT = 443

        private const val TESTNET_LIGHTWALLETD_HOST = "testnet.zec.rocks"
        private const val TESTNET_LIGHTWALLETD_PORT = 443

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

        /**
         * Derive transparent Zcash address from seed phrase using BIP44
         * Path: m/44'/133'/account'/0/addressIndex
         *
         * @param seedPhrase BIP39 mnemonic
         * @param network Zcash network (mainnet or testnet)
         * @param addressIndex Address index (usually 0 for first address)
         * @return Transparent address (t1... for mainnet, tm... for testnet)
         */
        private fun deriveTransparentAddress(
            seedPhrase: String,
            network: ZcashNetwork,
            addressIndex: Int = 0
        ): String {
            // Convert seed phrase to seed bytes using Web3j's BIP39 implementation
            val seed = MnemonicUtils.generateSeed(seedPhrase, "")

            // Derive master key from seed
            val masterKey = Bip32ECKeyPair.generateKeyPair(seed)

            // BIP44 path for Zcash: m/44'/133'/0'/0/0
            // 44' = 0x8000002C (purpose - hardened)
            // 133' = 0x80000085 (coin type for Zcash - hardened)
            // 0' = 0x80000000 (account - hardened)
            // 0 = external chain (not hardened)
            // addressIndex = address index (not hardened)
            val purpose = 44 or 0x80000000.toInt()  // 44' (hardened)
            val coinType = 133 or 0x80000000.toInt() // 133' (Zcash, hardened)
            val account = 0 or 0x80000000.toInt()   // 0' (hardened)
            val chain = 0                            // 0 (external, not hardened)

            // Build the full derivation path as an array
            val derivationPath = intArrayOf(purpose, coinType, account, chain, addressIndex)

            // Derive the key following BIP44 path
            val addressKey = Bip32ECKeyPair.deriveKeyPair(masterKey, derivationPath)

            // Get compressed public key
            val publicKey = addressKey.publicKey.toByteArray()
            val compressedPubKey = compressPublicKey(publicKey)

            // Hash the public key (SHA-256 then RIPEMD-160)
            val sha256 = MessageDigest.getInstance("SHA-256")
            val sha256Hash = sha256.digest(compressedPubKey)

            val ripemd160 = RIPEMD160Digest()
            val pubKeyHash = ByteArray(20)
            ripemd160.update(sha256Hash, 0, sha256Hash.size)
            ripemd160.doFinal(pubKeyHash, 0)

            // Add version bytes for Zcash P2PKH addresses
            // Mainnet: 0x1CB8, Testnet: 0x1D25
            val versionBytes = if (network == ZcashNetwork.Mainnet) {
                byteArrayOf(0x1C.toByte(), 0xB8.toByte())
            } else {
                byteArrayOf(0x1D.toByte(), 0x25.toByte())
            }

            // Combine version + pubKeyHash
            val addressBytes = versionBytes + pubKeyHash

            // Encode with Base58Check
            return base58CheckEncode(addressBytes)
        }

        /**
         * Compress a public key to 33 bytes (02/03 prefix + x coordinate)
         */
        private fun compressPublicKey(publicKey: ByteArray): ByteArray {
            if (publicKey.size == 33) return publicKey // Already compressed

            // publicKey is 65 bytes: 0x04 + x (32 bytes) + y (32 bytes)
            val x = publicKey.sliceArray(1..32)
            val y = publicKey.sliceArray(33..64)

            // If y is even, use 0x02 prefix, else 0x03
            val prefix = if (y.last().toInt() and 1 == 0) 0x02.toByte() else 0x03.toByte()

            return byteArrayOf(prefix) + x
        }

        /**
         * Base58Check encoding for Zcash addresses
         */
        private fun base58CheckEncode(payload: ByteArray): String {
            // Calculate checksum (double SHA-256)
            val sha256 = MessageDigest.getInstance("SHA-256")
            val hash1 = sha256.digest(payload)
            val hash2 = sha256.digest(hash1)
            val checksum = hash2.sliceArray(0..3)

            // Combine payload + checksum
            val addressBytes = payload + checksum

            // Encode to Base58
            return base58Encode(addressBytes)
        }

        /**
         * Base58 encoding (Bitcoin alphabet)
         */
        private fun base58Encode(input: ByteArray): String {
            val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

            // Count leading zeros
            var leadingZeros = 0
            while (leadingZeros < input.size && input[leadingZeros] == 0.toByte()) {
                leadingZeros++
            }

            // Convert to base58
            val encoded = StringBuilder()
            var num = java.math.BigInteger(1, input)
            val base = java.math.BigInteger.valueOf(58)

            while (num > java.math.BigInteger.ZERO) {
                val remainder = num.mod(base).toInt()
                encoded.insert(0, alphabet[remainder])
                num = num.divide(base)
            }

            // Add '1' for each leading zero byte
            for (i in 0 until leadingZeros) {
                encoded.insert(0, '1')
            }

            return encoded.toString()
        }
    }

    // Synchronizer instance (lazy initialized)
    private var synchronizer: Synchronizer? = null
    private var network: ZcashNetwork = ZcashNetwork.Mainnet
    private var zcashAccount: cash.z.ecc.android.sdk.model.Account? = null

    // Active wallet tracking
    @Volatile
    private var activeWalletId: String? = null

    // Birthday height of the currently initialized wallet
    @Volatile
    private var currentBirthdayHeight: Long? = null

    // Cached balance (updated automatically when synced)
    @Volatile
    private var cachedBalance: Double = 0.0

    /**
     * Initialize Zcash wallet from seed phrase
     * @param seedPhrase BIP39 mnemonic (12 or 24 words)
     * @param useTestnet true for testnet, false for mainnet
     * @param birthdayHeight Optional block height when wallet was created (for restoring old wallets)
     * @return Unified address for receiving ZEC
     */
    suspend fun initialize(
        seedPhrase: String,
        useTestnet: Boolean = false,
        birthdayHeight: Long? = null
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            // If already initialized, return existing address
            if (synchronizer != null && zcashAccount != null) {
                val existingAddress = keyManager.getZcashAddress()
                if (existingAddress != null) {
                    Log.d(TAG, "ZcashService already initialized, returning existing address")
                    return@withContext Result.success(existingAddress)
                }
            }

            Log.d(TAG, "Initializing Zcash wallet (testnet: $useTestnet, birthday: ${birthdayHeight ?: "latest"})")

            // Set network
            network = if (useTestnet) ZcashNetwork.Testnet else ZcashNetwork.Mainnet

            // Convert seed phrase to bytes using Zcash BIP39 library
            val seedBytes = Mnemonics.MnemonicCode(seedPhrase.toCharArray()).toSeed()

            // Use provided birthday or latest checkpoint for new wallets
            val birthday = if (birthdayHeight != null && birthdayHeight > 0) {
                BlockHeight.new(birthdayHeight)
            } else {
                BlockHeight.ofLatestCheckpoint(context, network)
            }
            // Store birthday height for later retrieval
            currentBirthdayHeight = birthday.value
            Log.d(TAG, "Using birthday block height: ${birthday.value}")

            // Create lightwalletd endpoint
            val endpoint = if (useTestnet) {
                LightWalletEndpoint(TESTNET_LIGHTWALLETD_HOST, TESTNET_LIGHTWALLETD_PORT, true)
            } else {
                LightWalletEndpoint(MAINNET_LIGHTWALLETD_HOST, MAINNET_LIGHTWALLETD_PORT, true)
            }

            // Enable Tor for Zcash SDK - routes through SOCKS proxy on 127.0.0.1:9050
            // This provides full privacy: lightwalletd server can't see your IP address
            Log.i(TAG, "Connecting to lightwalletd: ${endpoint.host}:${endpoint.port} through Tor")
            Log.i(TAG, "Network: ${if (useTestnet) "TESTNET" else "MAINNET"}, Birthday: ${birthday.value}")

            synchronizer = Synchronizer.newBlocking(
                context = context,
                zcashNetwork = network,
                alias = WALLET_ALIAS,
                lightWalletEndpoint = endpoint,
                birthday = birthday,
                walletInitMode = WalletInitMode.RestoreWallet,
                setup = AccountCreateSetup(
                    accountName = "SecureLegion Wallet",
                    keySource = null,
                    seed = FirstClassByteArray(seedBytes)
                ),
                isTorEnabled = true,  // ✅ Route all blockchain sync through Tor (uses 127.0.0.1:9050)
                isExchangeRateEnabled = false
            )

            Log.i(TAG, "Synchronizer created successfully")

            zcashAccount = runBlocking { synchronizer?.getAccounts()?.firstOrNull() }
            val unifiedAddress = runBlocking {
                zcashAccount?.let { synchronizer?.getUnifiedAddress(it) }
            }
            val transparentAddress = runBlocking {
                zcashAccount?.let { synchronizer?.getTransparentAddress(it) }
            }

            if (unifiedAddress != null) {
                keyManager.setZcashAddress(unifiedAddress)
                Log.i(TAG, "Unified address: $unifiedAddress")
            }
            if (transparentAddress != null) {
                keyManager.setZcashTransparentAddress(transparentAddress)
                Log.i(TAG, "Transparent address (from SDK): $transparentAddress")
            }

            Log.i(TAG, "Zcash wallet initialized successfully")

            Result.success(unifiedAddress ?: "")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Zcash wallet", e)
            (synchronizer as? AutoCloseable)?.close()
            synchronizer = null
            Result.failure(e)
        }
    }

    /**
     * Set active Zcash wallet for syncing
     * Stops current synchronizer and starts new one with selected wallet's seed
     *
     * @param walletId Wallet ID to activate
     * @return Result with unified address or error
     */
    suspend fun setActiveZcashWallet(walletId: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.i(TAG, "Setting active Zcash wallet: $walletId")

            // Get database access
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Update database: mark this wallet as active
            database.walletDao().clearActiveZcashWallet()
            database.walletDao().setActiveZcashWallet(walletId)

            // Stop current synchronizer
            stopSynchronizer()

            // Get seed phrase for this wallet
            // Try wallet-specific seed first, fall back to main wallet seed for Zcash wallets
            val seedPhrase = try {
                keyManager.getWalletSeedPhrase(walletId)
            } catch (e: Exception) {
                Log.w(TAG, "Wallet-specific seed not found, trying main wallet seed for Zcash")
                keyManager.getMainWalletSeedForZcash()
            } ?: return@withContext Result.failure(IllegalStateException("No seed phrase found for wallet: $walletId"))

            // Get wallet info from database
            val wallet = database.walletDao().getWalletById(walletId)
                ?: return@withContext Result.failure(IllegalStateException("Wallet not found: $walletId"))

            // Initialize synchronizer with this wallet's seed
            activeWalletId = walletId
            val result = initializeSynchronizerForWallet(
                walletId = walletId,
                seedPhrase = seedPhrase,
                birthdayHeight = wallet.zcashBirthdayHeight
            )

            if (result.isSuccess) {
                Log.i(TAG, "Successfully activated Zcash wallet: $walletId")
            } else {
                Log.e(TAG, "Failed to activate Zcash wallet: $walletId", result.exceptionOrNull())
            }

            result

        } catch (e: Exception) {
            Log.e(TAG, "Failed to set active Zcash wallet", e)
            Result.failure(e)
        }
    }

    /**
     * Initialize synchronizer for a specific wallet
     * Uses per-wallet data directory for isolation
     *
     * @param walletId Wallet ID
     * @param seedPhrase BIP39 seed phrase
     * @param birthdayHeight Optional birthday height
     * @return Result with unified address
     */
    private suspend fun initializeSynchronizerForWallet(
        walletId: String,
        seedPhrase: String,
        birthdayHeight: Long? = null
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Initializing synchronizer for wallet: $walletId")

            // Set network (always mainnet for now)
            network = ZcashNetwork.Mainnet

            // Convert seed phrase to bytes
            val seedBytes = Mnemonics.MnemonicCode(seedPhrase.toCharArray()).toSeed()

            // Use provided birthday or latest checkpoint
            val birthday = if (birthdayHeight != null && birthdayHeight > 0) {
                BlockHeight.new(birthdayHeight)
            } else {
                BlockHeight.ofLatestCheckpoint(context, network)
            }
            Log.d(TAG, "Using birthday block height: ${birthday.value} for wallet: $walletId")

            // Create lightwalletd endpoint (mainnet)
            val endpoint = LightWalletEndpoint(MAINNET_LIGHTWALLETD_HOST, MAINNET_LIGHTWALLETD_PORT, true)

            Log.i(TAG, "Connecting to lightwalletd for wallet $walletId through Tor")

            // IMPORTANT: Use per-wallet alias for separate data directories
            val walletAlias = "securelegion_wallet_${walletId}"

            synchronizer = Synchronizer.newBlocking(
                context = context,
                zcashNetwork = network,
                alias = walletAlias,  // ✅ Per-wallet data directory
                lightWalletEndpoint = endpoint,
                birthday = birthday,
                walletInitMode = WalletInitMode.RestoreWallet,
                setup = AccountCreateSetup(
                    accountName = "SecureLegion Wallet $walletId",
                    keySource = null,
                    seed = FirstClassByteArray(seedBytes)
                ),
                isTorEnabled = true,
                isExchangeRateEnabled = false
            )

            Log.i(TAG, "Synchronizer created for wallet: $walletId")

            // Get account and addresses
            zcashAccount = runBlocking { synchronizer?.getAccounts()?.firstOrNull() }
            val unifiedAddress = runBlocking {
                zcashAccount?.let { synchronizer?.getUnifiedAddress(it) }
            }
            val transparentAddress = runBlocking {
                zcashAccount?.let { synchronizer?.getTransparentAddress(it) }
            }

            if (unifiedAddress != null) {
                Log.i(TAG, "Unified address for wallet $walletId: $unifiedAddress")
            }
            if (transparentAddress != null) {
                Log.i(TAG, "Transparent address for wallet $walletId: $transparentAddress")
            }

            Result.success(unifiedAddress ?: "")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize synchronizer for wallet: $walletId", e)
            (synchronizer as? AutoCloseable)?.close()
            synchronizer = null
            Result.failure(e)
        }
    }

    /**
     * Stop current synchronizer and clean up
     */
    private suspend fun stopSynchronizer() = withContext(Dispatchers.IO) {
        try {
            val sync = synchronizer
            if (sync != null) {
                Log.i(TAG, "Stopping synchronizer for wallet: $activeWalletId")
                (sync as? AutoCloseable)?.close()
                synchronizer = null
                zcashAccount = null
                cachedBalance = 0.0
                Log.i(TAG, "Synchronizer stopped successfully")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping synchronizer", e)
        }
    }

    /**
     * Get currently active wallet ID
     */
    fun getActiveWalletId(): String? = activeWalletId

    /**
     * Get the birthday height of the currently initialized wallet
     * @return Birthday height or null if not initialized
     */
    fun getBirthdayHeight(): Long? = currentBirthdayHeight

    /**
     * Initialize from active wallet on app startup
     * Loads the wallet marked as active in the database and starts syncing
     *
     * @return Result with unified address or null if no active wallet
     */
    suspend fun initializeFromActiveWallet(): Result<String?> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Initializing from active wallet on startup")

            // Get database access
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Find active Zcash wallet
            val activeWalletId = database.walletDao().getActiveZcashWalletId()

            if (activeWalletId == null) {
                Log.i(TAG, "No active Zcash wallet found")
                return@withContext Result.success(null)
            }

            // Get seed phrase for active wallet
            val seedPhrase = keyManager.getWalletSeedPhrase(activeWalletId)
            if (seedPhrase == null) {
                Log.w(TAG, "No seed phrase found for active wallet: $activeWalletId")
                return@withContext Result.success(null)
            }

            // Get wallet info
            val wallet = database.walletDao().getWalletById(activeWalletId)
            if (wallet == null) {
                Log.w(TAG, "Active wallet not found in database: $activeWalletId")
                return@withContext Result.success(null)
            }

            // Initialize synchronizer
            this@ZcashService.activeWalletId = activeWalletId
            val result = initializeSynchronizerForWallet(
                walletId = activeWalletId,
                seedPhrase = seedPhrase,
                birthdayHeight = wallet.zcashBirthdayHeight
            )

            if (result.isSuccess) {
                Log.i(TAG, "Successfully initialized active Zcash wallet on startup: $activeWalletId")
            } else {
                Log.e(TAG, "Failed to initialize active wallet: $activeWalletId", result.exceptionOrNull())
            }

            result

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize from active wallet", e)
            Result.failure(e)
        }
    }

    /**
     * Get ZEC balance for the wallet
     * Returns cached balance (updated automatically by SDK) for instant response
     * @return Balance in ZEC (e.g., 0.5 ZEC)
     */
    suspend fun getBalance(): Result<Double> = withContext(Dispatchers.IO) {
        try {
            val sync = synchronizer
            if (sync == null) {
                Log.w(TAG, "Synchronizer not initialized")
                return@withContext Result.success(0.0)
            }

            val account = zcashAccount
            if (account == null) {
                Log.w(TAG, "Account not initialized")
                return@withContext Result.success(0.0)
            }

            // Try to get latest balance quickly (no blocking)
            try {
                val balances = sync.walletBalances.value
                if (balances != null) {
                    val balance = balances[account.accountUuid]
                    if (balance != null) {
                        // AccountBalance structure (from Unstoppable Wallet):
                        // - balance.sapling.available + balance.sapling.pending
                        // - balance.orchard.available + balance.orchard.pending
                        // - balance.unshielded (transparent balance)
                        val saplingAvailable = balance.sapling.available.convertZatoshiToZec(4).toDouble()
                        val saplingPending = balance.sapling.pending.convertZatoshiToZec(4).toDouble()
                        val orchardAvailable = balance.orchard.available.convertZatoshiToZec(4).toDouble()
                        val orchardPending = balance.orchard.pending.convertZatoshiToZec(4).toDouble()
                        val unshieldedZEC = balance.unshielded.convertZatoshiToZec(4).toDouble()

                        // Total balance including pending
                        val totalZEC = saplingAvailable + saplingPending + orchardAvailable + orchardPending + unshieldedZEC

                        cachedBalance = totalZEC

                        Log.d(TAG, "ZEC Balance - Sapling: ${saplingAvailable + saplingPending}")
                        Log.d(TAG, "             Orchard: ${orchardAvailable + orchardPending}")
                        Log.d(TAG, "             Transparent: $unshieldedZEC")
                        Log.d(TAG, "             Total: $totalZEC ZEC")
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Could not get latest balance: ${e.message}")
            }

            // Return cached balance (instant, no blocking)
            Log.d(TAG, "Returning cached balance: $cachedBalance ZEC")
            Result.success(cachedBalance)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get balance", e)
            Result.failure(e)
        }
    }

    /**
     * Balance breakdown data class
     */
    data class BalanceBreakdown(
        val transparentZEC: Double,
        val shieldedZEC: Double,
        val totalZEC: Double
    )

    /**
     * Get balance breakdown (transparent vs shielded)
     * @return BalanceBreakdown with transparent, shielded, and total amounts
     */
    suspend fun getBalanceBreakdown(): Result<BalanceBreakdown> = withContext(Dispatchers.IO) {
        try {
            val sync = synchronizer
            if (sync == null) {
                return@withContext Result.success(BalanceBreakdown(0.0, 0.0, 0.0))
            }

            val account = zcashAccount
            if (account == null) {
                return@withContext Result.success(BalanceBreakdown(0.0, 0.0, 0.0))
            }

            val balances = sync.walletBalances.value
            if (balances != null) {
                val balance = balances[account.accountUuid]
                if (balance != null) {
                    val saplingAvailable = balance.sapling.available.convertZatoshiToZec(4).toDouble()
                    val saplingPending = balance.sapling.pending.convertZatoshiToZec(4).toDouble()
                    val orchardAvailable = balance.orchard.available.convertZatoshiToZec(4).toDouble()
                    val orchardPending = balance.orchard.pending.convertZatoshiToZec(4).toDouble()
                    val transparentZEC = balance.unshielded.convertZatoshiToZec(4).toDouble()
                    val shieldedZEC = saplingAvailable + saplingPending + orchardAvailable + orchardPending
                    val totalZEC = shieldedZEC + transparentZEC

                    return@withContext Result.success(BalanceBreakdown(transparentZEC, shieldedZEC, totalZEC))
                }
            }

            Result.success(BalanceBreakdown(0.0, 0.0, 0.0))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get balance breakdown", e)
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
     * Get transparent address for exchange compatibility
     * Returns the t1... address that exchanges like Kraken accept
     */
    fun getTransparentAddress(): String? {
        return keyManager.getZcashTransparentAddress()
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

            // Check balance before attempting transaction
            val balances = sync.walletBalances.value
            val accountBalance = balances?.get(account.accountUuid)

            if (accountBalance != null) {
                val saplingAvailableZatoshis = accountBalance.sapling.available.value
                val orchardAvailableZatoshis = accountBalance.orchard.available.value
                val transparentZatoshis = accountBalance.unshielded.value
                val totalShielded = saplingAvailableZatoshis + orchardAvailableZatoshis

                Log.d(TAG, "Shielded balance (Sapling): $saplingAvailableZatoshis zatoshis (${saplingAvailableZatoshis.toDouble() / ZATOSHIS_PER_ZEC} ZEC)")
                Log.d(TAG, "Shielded balance (Orchard): $orchardAvailableZatoshis zatoshis (${orchardAvailableZatoshis.toDouble() / ZATOSHIS_PER_ZEC} ZEC)")
                Log.d(TAG, "Transparent balance: $transparentZatoshis zatoshis (${transparentZatoshis.toDouble() / ZATOSHIS_PER_ZEC} ZEC)")
                Log.d(TAG, "Total shielded: $totalShielded zatoshis (${totalShielded.toDouble() / ZATOSHIS_PER_ZEC} ZEC)")

                if (totalShielded < zatoshis.value) {
                    val needed = zatoshis.value.toDouble() / ZATOSHIS_PER_ZEC
                    val shielded = totalShielded.toDouble() / ZATOSHIS_PER_ZEC
                    val transparent = transparentZatoshis.toDouble() / ZATOSHIS_PER_ZEC

                    // Check if user has funds in transparent pool
                    if (transparentZatoshis > zatoshis.value) {
                        return@withContext Result.failure(
                            IllegalStateException(
                                "Insufficient shielded balance. Your ZEC is in transparent pool.\n\n" +
                                "Shielded: $shielded ZEC\n" +
                                "Transparent: $transparent ZEC\n\n" +
                                "You need to shield your transparent funds first. Go to your ZEC wallet and tap the balance display to shield funds."
                            )
                        )
                    } else {
                        return@withContext Result.failure(
                            IllegalStateException(
                                "Insufficient balance.\n\n" +
                                "Need: $needed ZEC\n" +
                                "Shielded: $shielded ZEC\n" +
                                "Transparent: $transparent ZEC"
                            )
                        )
                    }
                }
            }

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
            Log.d(TAG, "Creating transaction proposal: $zatoshis zatoshis to $toAddress")
            val proposal = try {
                sync.proposeTransfer(
                    account = account,
                    recipient = toAddress,
                    amount = zatoshis,
                    memo = memo
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create transaction proposal", e)
                return@withContext Result.failure(
                    Exception("Failed to create transaction proposal: ${e.message}", e)
                )
            }

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
     * Shield transparent funds to shielded pool (Sapling/Orchard)
     * Moves transparent funds to your shielded address
     * @param amountZEC Optional amount to shield in ZEC. If null, shields all transparent funds.
     * @return Transaction ID if successful
     */
    suspend fun shieldTransparentFunds(amountZEC: Double? = null): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting transparent funds shielding...")

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

            // Get account
            val accounts = sync.getAccounts()
            if (accounts.isEmpty()) {
                return@withContext Result.failure(
                    IllegalStateException("No accounts available")
                )
            }
            val account = accounts[DEFAULT_ACCOUNT_INDEX.toInt()]

            // Check transparent balance
            val balances = sync.walletBalances.value
            val accountBalance = balances?.get(account.accountUuid)

            val transparentZatoshis: Long
            val amountToShieldZatoshis: Long

            if (accountBalance != null) {
                transparentZatoshis = accountBalance.unshielded.value

                if (transparentZatoshis <= 0) {
                    return@withContext Result.failure(
                        IllegalStateException("No transparent funds to shield. Transparent balance: 0 ZEC")
                    )
                }

                val transparentZEC = transparentZatoshis.toDouble() / ZATOSHIS_PER_ZEC

                // Determine amount to shield
                amountToShieldZatoshis = if (amountZEC == null) {
                    // Shield all
                    transparentZatoshis
                } else {
                    // Shield custom amount
                    val requestedZatoshis = (amountZEC * ZATOSHIS_PER_ZEC).toLong()
                    if (requestedZatoshis > transparentZatoshis) {
                        return@withContext Result.failure(
                            IllegalStateException("Requested amount ($amountZEC ZEC) exceeds transparent balance ($transparentZEC ZEC)")
                        )
                    }
                    requestedZatoshis
                }

                val amountZECFormatted = amountToShieldZatoshis.toDouble() / ZATOSHIS_PER_ZEC
                Log.d(TAG, "Shielding $amountZECFormatted ZEC ($amountToShieldZatoshis zatoshis) from transparent pool")
            } else {
                return@withContext Result.failure(
                    IllegalStateException("Could not retrieve balance information")
                )
            }

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

            // Create shielding proposal
            // NOTE: Zcash SDK's proposeShielding always shields ALL transparent funds.
            // Custom amount parameter is accepted for UI/logging but actual shielding is all-or-nothing.
            // For true partial shielding, would need to use proposeTransfer instead (future enhancement).
            Log.d(TAG, "Creating shielding proposal...")
            val proposal = try {
                sync.proposeShielding(
                    account = account,
                    shieldingThreshold = Zatoshi(10000L), // Minimum 0.0001 ZEC to shield
                    memo = if (amountZEC != null) "Shielding $amountZEC ZEC" else "Shielding transparent funds",
                    transparentReceiver = null // Shield to default address
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create shielding proposal", e)
                return@withContext Result.failure(
                    Exception("Failed to create shielding proposal: ${e.message}", e)
                )
            }

            if (proposal == null) {
                return@withContext Result.failure(
                    IllegalStateException("No shielding proposal created. Transparent balance may be below threshold.")
                )
            }

            // Create and submit shielding transaction
            Log.d(TAG, "Creating and submitting shielding transaction...")
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
                    Log.i(TAG, "Shielding transaction submitted successfully: $txId")
                    Result.success(txId)
                }
                is TransactionSubmitResult.Failure -> {
                    val errorMsg = "Shielding failed (code ${firstResult.code}): ${firstResult.description ?: "Unknown error"}"
                    Log.e(TAG, errorMsg)
                    Result.failure(Exception(errorMsg))
                }
                is TransactionSubmitResult.NotAttempted -> {
                    val txId = firstResult.txIdString()
                    Log.w(TAG, "Shielding transaction created but not submitted: $txId")
                    Result.failure(Exception("Transaction was not submitted to the network"))
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to shield transparent funds", e)
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
     * Get estimated network fee for a Zcash transaction
     * Returns the standard recommended fee which is consistent across most transactions
     *
     * Unlike Solana, Zcash fees don't fluctuate based on network congestion
     * The standard fee is 10,000 zatoshis (0.0001 ZEC) for typical transactions
     *
     * Note: Shielded transactions or complex operations may have slightly higher fees,
     * but this provides an accurate estimate for >95% of transactions
     *
     * @return Fee in ZEC (not zatoshis)
     */
    suspend fun getTransactionFee(): Result<Double> = withContext(Dispatchers.IO) {
        try {
            // Zcash standard recommended fee
            // This is consistent and doesn't require network calls
            // 1 ZEC = 100,000,000 zatoshis
            val standardFeeZatoshis = 10000L
            val feeZEC = standardFeeZatoshis.toDouble() / 100_000_000

            Log.d(TAG, "Transaction fee (standard): $feeZEC ZEC ($standardFeeZatoshis zatoshis)")
            Log.d(TAG, "Zcash fees are consistent - no need to fetch from network")

            return@withContext Result.success(feeZEC)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to calculate transaction fee", e)
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
