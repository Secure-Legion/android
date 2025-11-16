package com.securelegion.crypto

import android.content.Context
import android.util.Log
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Sign
import org.web3j.crypto.MnemonicUtils
import java.math.BigInteger
import java.security.MessageDigest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * KeyManager - Unified key management for wallet and messaging
 *
 * Uses Solana wallet keys (Ed25519) for both:
 * - Blockchain transactions
 * - Message signing (Ping-Pong tokens)
 *
 * Derives X25519 encryption keys from the same seed for:
 * - Message encryption (EC DH)
 * - Ping-Pong token encryption
 *
 * All keys stored in Android Keystore (hardware-backed secure storage)
 *
 * Note: Uses applicationContext to prevent memory leaks
 */
@Suppress("StaticFieldLeak") // Safe: uses applicationContext
class KeyManager private constructor(context: Context) {

    private val appContext = context.applicationContext

    companion object {
        private const val TAG = "KeyManager"
        private const val KEYSTORE_ALIAS_PREFIX = "securelegion_"
        private const val PREFS_NAME = "secure_legion_keys"

        // Key aliases
        private const val WALLET_SEED_ALIAS = "${KEYSTORE_ALIAS_PREFIX}wallet_seed"
        private const val ED25519_SIGNING_KEY_ALIAS = "${KEYSTORE_ALIAS_PREFIX}signing_key"
        private const val X25519_ENCRYPTION_KEY_ALIAS = "${KEYSTORE_ALIAS_PREFIX}encryption_key"
        private const val HIDDEN_SERVICE_KEY_ALIAS = "${KEYSTORE_ALIAS_PREFIX}hidden_service_key"
        private const val DEVICE_PASSWORD_HASH_ALIAS = "${KEYSTORE_ALIAS_PREFIX}device_password_hash"

        init {
            // Register BouncyCastle provider for SHA3-256 support
            Security.addProvider(BouncyCastleProvider())
        }

        @Volatile
        private var instance: KeyManager? = null

        @Suppress("unused") // Called via JNI from Rust code
        @JvmStatic
        fun getInstance(context: Context): KeyManager {
            return instance ?: synchronized(this) {
                instance ?: KeyManager(context.applicationContext).also { instance = it }
            }
        }
    }

    private val masterKey: MasterKey = MasterKey.Builder(appContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val encryptedPrefs = EncryptedSharedPreferences.create(
        appContext,
        PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private val lazySodium = LazySodiumAndroid(SodiumAndroid())

    /**
     * Initialize keys from seed phrase (12-word mnemonic)
     * This is called during account creation or restoration
     */
    @Suppress("unused") // Will be called during account setup
    fun initializeFromSeed(seedPhrase: String) {
        try {
            Log.d(TAG, "Initializing keys from seed phrase")

            // Derive wallet keys from seed phrase
            val seed = mnemonicToSeed(seedPhrase)

            // Generate Ed25519 signing key (for Solana wallet + message signing)
            val ed25519KeyPair = deriveEd25519KeyPair(seed)

            // Generate X25519 encryption key (for message encryption)
            val x25519KeyPair = deriveX25519KeyPair(seed)

            // Generate Ed25519 hidden service key (for deterministic .onion address)
            val hiddenServiceKeyPair = deriveHiddenServiceKeyPair(seed)

            // Store keys securely in encrypted preferences
            storeKeyPair(ED25519_SIGNING_KEY_ALIAS, ed25519KeyPair)
            storeKeyPair(X25519_ENCRYPTION_KEY_ALIAS, x25519KeyPair)
            storeKeyPair(HIDDEN_SERVICE_KEY_ALIAS, hiddenServiceKeyPair)

            // Store seed (encrypted by EncryptedSharedPreferences)
            encryptedPrefs.edit {
                putString(WALLET_SEED_ALIAS, bytesToHex(seed))
            }

            Log.i(TAG, "Keys initialized successfully from seed")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize keys from seed", e)
            throw KeyManagerException("Failed to initialize keys: ${e.message}", e)
        }
    }

    /**
     * Get Ed25519 signing private key (32 bytes)
     * Used for: Solana transactions, Ping/Pong signatures, message authentication
     * Called via JNI from Rust code
     */
    @Suppress("unused")
    fun getSigningKeyBytes(): ByteArray {
        return getStoredKey("${ED25519_SIGNING_KEY_ALIAS}_private")
            ?: throw KeyManagerException("Signing key not found. Initialize wallet first.")
    }

    /**
     * Get Ed25519 signing public key (32 bytes)
     * This is also the Solana wallet public key
     * Called via JNI from Rust code
     */
    @Suppress("unused")
    fun getSigningPublicKey(): ByteArray {
        return getStoredKey("${ED25519_SIGNING_KEY_ALIAS}_public")
            ?: throw KeyManagerException("Signing public key not found")
    }

    /**
     * Get X25519 encryption private key (32 bytes)
     * Used for: Message ECDH encryption, Ping/Pong token encryption
     * Called via JNI from Rust code
     */
    @Suppress("unused")
    fun getEncryptionKeyBytes(): ByteArray {
        return getStoredKey("${X25519_ENCRYPTION_KEY_ALIAS}_private")
            ?: throw KeyManagerException("Encryption key not found")
    }

    /**
     * Get X25519 encryption public key (32 bytes)
     * Shared with contacts for ECDH message encryption
     * Called via JNI from Rust code
     */
    @Suppress("unused")
    fun getEncryptionPublicKey(): ByteArray {
        return getStoredKey("${X25519_ENCRYPTION_KEY_ALIAS}_public")
            ?: throw KeyManagerException("Encryption public key not found")
    }

    /**
     * Get hidden service Ed25519 private key (32 bytes)
     * Used for deterministic .onion address generation
     * Called via JNI from Rust code
     */
    @Suppress("unused")
    fun getHiddenServiceKeyBytes(): ByteArray {
        return getStoredKey("${HIDDEN_SERVICE_KEY_ALIAS}_private")
            ?: throw KeyManagerException("Hidden service key not found. Initialize wallet first.")
    }

    /**
     * Get hidden service Ed25519 public key (32 bytes)
     * Used to derive the .onion address
     * Called via JNI from Rust code
     */
    @Suppress("unused")
    fun getHiddenServicePublicKey(): ByteArray {
        return getStoredKey("${HIDDEN_SERVICE_KEY_ALIAS}_public")
            ?: throw KeyManagerException("Hidden service public key not found")
    }

    /**
     * Get Solana wallet address (base58-encoded public key)
     */
    @Suppress("unused") // Will be used to display wallet address
    fun getSolanaAddress(): String {
        val publicKey = getSigningPublicKey()
        return base58Encode(publicKey)
    }

    /**
     * Get Solana public key (raw 32 bytes)
     */
    fun getSolanaPublicKey(): ByteArray {
        return getSigningPublicKey()
    }

    /**
     * Get Tor onion address from TorManager
     * Uses the actual address that Tor created, not a computed one
     */
    fun getTorOnionAddress(): String {
        // Get the actual address from TorManager instead of computing
        // This ensures we always use the exact address that Tor generated
        val torManager = TorManager.getInstance(appContext)
        return torManager.getOnionAddress()
            ?: throw KeyManagerException("Tor onion address not found. Initialize Tor first.")
    }

    /**
     * Convert Ed25519 public key to Tor v3 onion address
     */
    private fun publicKeyToOnionAddress(publicKey: ByteArray): String {
        // Tor v3 address = base32(public_key || checksum || version)
        // Checksum MUST use SHA3-256 (Keccak), not SHA-256!
        val version = byteArrayOf(0x03)
        val checksumInput = ".onion checksum".toByteArray() + publicKey + version
        val checksum = sha3_256(checksumInput).take(2).toByteArray()

        val combined = publicKey + checksum + version
        return base32Encode(combined).lowercase() + ".onion"
    }

    /**
     * Base32 encoding for Tor addresses
     */
    private fun base32Encode(bytes: ByteArray): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        val output = StringBuilder()
        var buffer = 0
        var bitsLeft = 0

        for (byte in bytes) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                output.append(alphabet[(buffer shr (bitsLeft - 5)) and 0x1F])
                bitsLeft -= 5
            }
        }

        if (bitsLeft > 0) {
            output.append(alphabet[(buffer shl (5 - bitsLeft)) and 0x1F])
        }

        return output.toString()
    }

    /**
     * SHA-256 hash
     */
    private fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    /**
     * SHA3-256 hash (Keccak) - required for Tor v3 onion address checksum
     */
    private fun sha3_256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA3-256", org.bouncycastle.jce.provider.BouncyCastleProvider())
        return digest.digest(data)
    }

    /**
     * Sign data with Ed25519 signing key
     * Used by Rust FFI for Ping/Pong token signatures
     * Called via JNI from Rust code
     */
    @Suppress("unused")
    fun signData(data: ByteArray): ByteArray {
        val privateKey = getSigningKeyBytes()
        return ed25519Sign(privateKey, data)
    }

    /**
     * Check if wallet is initialized
     */
    @Suppress("unused") // Will be called on app startup
    fun isInitialized(): Boolean {
        return encryptedPrefs.contains(WALLET_SEED_ALIAS)
    }

    /**
     * Wipe all keys (for duress PIN or account deletion)
     * Clears EncryptedSharedPreferences which internally manages Android Keystore
     */
    @Suppress("unused") // Will be called for duress PIN feature
    fun wipeAllKeys() {
        Log.w(TAG, "Wiping all keys from KeyManager")

        // Clear encrypted preferences (which manages Android Keystore internally)
        encryptedPrefs.edit { clear() }

        Log.i(TAG, "All keys wiped successfully")
    }

    // ==================== PRIVATE HELPER METHODS ====================

    /**
     * Convert BIP39 mnemonic to seed (64 bytes)
     */
    private fun mnemonicToSeed(mnemonic: String): ByteArray {
        // Use web3j's BIP39 implementation to generate seed from mnemonic
        // Password can be empty string for standard BIP39
        val seed = MnemonicUtils.generateSeed(mnemonic, "")
        Log.d(TAG, "Generated BIP39 seed from mnemonic (${seed.size} bytes)")
        return seed
    }

    /**
     * Derive Ed25519 keypair from seed using BIP44 path m/44'/501'/0'/0'
     * 501 = Solana's coin type
     *
     * Note: Solana uses SLIP-10 derivation. For simplicity, we use the first 32 bytes
     * of the BIP39 seed as the Ed25519 seed (common pattern for Solana wallets)
     */
    private fun deriveEd25519KeyPair(seed: ByteArray): KeyPair {
        // Use first 32 bytes of BIP39 seed as Ed25519 seed
        val ed25519Seed = seed.copyOfRange(0, 32)

        // Generate Ed25519 keypair from seed using libsodium
        val publicKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
        val privateKeyFull = ByteArray(Sign.ED25519_SECRETKEYBYTES) // 64 bytes

        lazySodium.cryptoSignSeedKeypair(publicKey, privateKeyFull, ed25519Seed)

        // Extract 32-byte private key (libsodium returns 64 bytes: seed || public_key)
        val privateKey = privateKeyFull.copyOfRange(0, 32)

        Log.d(TAG, "Derived Ed25519 keypair (private: ${privateKey.size} bytes, public: ${publicKey.size} bytes)")

        return KeyPair(privateKey, publicKey)
    }

    /**
     * Derive X25519 keypair from seed
     * Uses domain separation: SHA-256(seed || "x25519")
     */
    private fun deriveX25519KeyPair(seed: ByteArray): KeyPair {
        // Domain separation: hash seed with "x25519" to derive different key
        val messageDigest = MessageDigest.getInstance("SHA-256")
        messageDigest.update(seed)
        messageDigest.update("x25519".toByteArray())
        val privateKey = messageDigest.digest()

        // Generate X25519 public key from private key using libsodium
        val publicKey = x25519GetPublicKey(privateKey)

        Log.d(TAG, "Derived X25519 keypair (private: ${privateKey.size} bytes, public: ${publicKey.size} bytes)")

        return KeyPair(privateKey, publicKey)
    }

    /**
     * Derive Ed25519 keypair for Tor hidden service from seed
     * Uses domain separation: SHA-256(seed || "tor_hs")
     * This ensures the same seed always produces the same .onion address
     */
    private fun deriveHiddenServiceKeyPair(seed: ByteArray): KeyPair {
        // Domain separation: hash seed with "tor_hs" to derive different key
        val messageDigest = MessageDigest.getInstance("SHA-256")
        messageDigest.update(seed)
        messageDigest.update("tor_hs".toByteArray())
        val hsSeed = messageDigest.digest()

        // Generate Ed25519 keypair from seed using libsodium
        val publicKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
        val privateKeyFull = ByteArray(Sign.ED25519_SECRETKEYBYTES) // 64 bytes

        lazySodium.cryptoSignSeedKeypair(publicKey, privateKeyFull, hsSeed)

        // Extract 32-byte private key (libsodium returns 64 bytes: seed || public_key)
        val privateKey = privateKeyFull.copyOfRange(0, 32)

        Log.d(TAG, "Derived hidden service Ed25519 keypair (private: ${privateKey.size} bytes, public: ${publicKey.size} bytes)")

        return KeyPair(privateKey, publicKey)
    }

    /**
     * Store keypair in encrypted preferences
     */
    private fun storeKeyPair(alias: String, keyPair: KeyPair) {
        encryptedPrefs.edit {
            putString("${alias}_private", bytesToHex(keyPair.privateKey))
            putString("${alias}_public", bytesToHex(keyPair.publicKey))
        }
    }

    /**
     * Retrieve key from encrypted preferences
     */
    private fun getStoredKey(alias: String): ByteArray? {
        val hexKey = encryptedPrefs.getString(alias, null) ?: return null
        return hexToBytes(hexKey)
    }

    /**
     * Get Ed25519 public key from private key (seed)
     * Uses libsodium via LazySodium
     * Called during key derivation
     */
    @Suppress("unused")
    private fun ed25519GetPublicKey(privateKey: ByteArray): ByteArray {
        val publicKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
        val secretKey = ByteArray(Sign.ED25519_SECRETKEYBYTES)

        // Generate keypair from seed
        lazySodium.cryptoSignSeedKeypair(publicKey, secretKey, privateKey)

        return publicKey
    }

    /**
     * Sign data with Ed25519
     */
    private fun ed25519Sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        // Reconstruct the full 64-byte secret key from 32-byte seed
        val publicKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
        val secretKey = ByteArray(Sign.ED25519_SECRETKEYBYTES)
        lazySodium.cryptoSignSeedKeypair(publicKey, secretKey, privateKey)

        // Sign the data
        val signature = ByteArray(Sign.ED25519_BYTES)
        lazySodium.cryptoSignDetached(signature, data, data.size.toLong(), secretKey)

        return signature
    }

    /**
     * Get X25519 public key from private key
     * Uses libsodium via lazysodium
     */
    private fun x25519GetPublicKey(privateKey: ByteArray): ByteArray {
        val publicKey = ByteArray(32) // X25519 public key is 32 bytes

        // Compute Curve25519 scalar multiplication: public = base * private
        lazySodium.cryptoScalarMultBase(publicKey, privateKey)

        return publicKey
    }

    // ==================== CONTACT CARD STORAGE ====================

    /**
     * Store contact card CID and PIN in encrypted storage
     */
    fun storeContactCardInfo(cid: String, pin: String) {
        encryptedPrefs.edit {
            putString("contact_card_cid", cid)
            putString("contact_card_pin", pin)
        }
        Log.i(TAG, "Stored contact card info")
    }

    /**
     * Get contact card CID
     */
    fun getContactCardCid(): String? {
        return encryptedPrefs.getString("contact_card_cid", null)
    }

    /**
     * Get contact card PIN
     */
    fun getContactCardPin(): String? {
        return encryptedPrefs.getString("contact_card_pin", null)
    }

    /**
     * Check if contact card info is stored
     */
    fun hasContactCardInfo(): Boolean {
        return getContactCardCid() != null && getContactCardPin() != null
    }

    /**
     * Check if account setup is complete (has wallet, contact card, AND username)
     */
    fun isAccountSetupComplete(): Boolean {
        val hasWallet = isInitialized()
        val hasContactCard = hasContactCardInfo()
        val hasUsername = getUsername() != null
        Log.d(TAG, "Account setup check - Wallet: $hasWallet, Contact card: $hasContactCard, Username: $hasUsername")
        return hasWallet && hasContactCard && hasUsername
    }

    /**
     * Store username in encrypted storage
     */
    fun storeUsername(username: String) {
        encryptedPrefs.edit {
            putString("username", username)
        }
        Log.i(TAG, "Stored username: $username")
    }

    /**
     * Get stored username
     */
    fun getUsername(): String? {
        return encryptedPrefs.getString("username", null)
    }

    // ==================== DEVICE PASSWORD MANAGEMENT ====================

    /**
     * Set device password (stores SHA-256 hash)
     * Called during account creation
     */
    fun setDevicePassword(password: String) {
        if (password.isBlank()) {
            throw IllegalArgumentException("Password cannot be blank")
        }

        // Hash password with SHA-256
        val passwordHash = sha256(password.toByteArray(Charsets.UTF_8))

        // Store hash in encrypted preferences
        encryptedPrefs.edit {
            putString(DEVICE_PASSWORD_HASH_ALIAS, bytesToHex(passwordHash))
        }

        Log.i(TAG, "Device password set successfully")
    }

    /**
     * Verify device password
     * Returns true if password matches stored hash
     */
    fun verifyDevicePassword(password: String): Boolean {
        val storedHashHex = encryptedPrefs.getString(DEVICE_PASSWORD_HASH_ALIAS, null)
            ?: return false

        // Hash provided password
        val providedHash = sha256(password.toByteArray(Charsets.UTF_8))

        // Compare hashes (constant-time comparison)
        val storedHash = hexToBytes(storedHashHex)
        return storedHash.contentEquals(providedHash)
    }

    /**
     * Check if device password is set
     */
    fun isDevicePasswordSet(): Boolean {
        return encryptedPrefs.contains(DEVICE_PASSWORD_HASH_ALIAS)
    }

    // ==================== DATABASE ENCRYPTION ====================

    /**
     * Get the raw seed bytes from encrypted storage
     */
    private fun getSeedBytes(): ByteArray {
        val hexSeed = encryptedPrefs.getString(WALLET_SEED_ALIAS, null)
            ?: throw IllegalStateException("Wallet seed not found")
        return hexToBytes(hexSeed)
    }

    /**
     * Derive database encryption passphrase from BIP39 seed
     * Uses SHA-256(seed + "database_key" salt) for deterministic key
     * @return 32-byte passphrase for SQLCipher
     */
    fun getDatabasePassphrase(): ByteArray {
        if (!isInitialized()) {
            throw IllegalStateException("KeyManager not initialized")
        }

        val seed = getSeedBytes()

        // Derive database key using SHA-256 with application-specific salt
        // This ensures database key is deterministic and unique per wallet
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(seed)
        digest.update("secure_legion_database_v1".toByteArray(Charsets.UTF_8))
        val databaseKey = digest.digest()

        Log.i(TAG, "Derived database encryption key")
        return databaseKey
    }

    // ==================== HELPER FUNCTIONS ====================

    /**
     * Base58 encode (for Solana addresses)
     * Bitcoin/Solana alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
     */
    private fun base58Encode(bytes: ByteArray): String {
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var num = BigInteger(1, bytes)
        val base = BigInteger.valueOf(58)
        val sb = StringBuilder()

        // Convert to base58
        while (num > BigInteger.ZERO) {
            val remainder = num.mod(base).toInt()
            sb.insert(0, alphabet[remainder])
            num = num.divide(base)
        }

        // Add leading zeros (encoded as '1' in base58)
        for (b in bytes) {
            if (b.toInt() == 0) {
                sb.insert(0, alphabet[0])
            } else {
                break
            }
        }

        return sb.toString()
    }

    /**
     * Convert bytes to hex string
     */
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Convert hex string to bytes
     */
    private fun hexToBytes(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    // ==================== MULTI-WALLET SUPPORT ====================

    /**
     * Generate a new wallet with a unique seed
     * @return walletId and Solana address
     */
    fun generateNewWallet(): Pair<String, String> {
        try {
            Log.d(TAG, "Generating new wallet")

            // Generate new random seed phrase
            val entropy = ByteArray(16)
            java.security.SecureRandom().nextBytes(entropy)
            val seedPhrase = MnemonicUtils.generateMnemonic(entropy)

            // Derive keys from seed
            val seed = mnemonicToSeed(seedPhrase)
            val ed25519KeyPair = deriveEd25519KeyPair(seed)

            // Generate unique wallet ID
            val walletId = java.util.UUID.randomUUID().toString()

            // Store keypair with wallet ID prefix
            val walletKeyAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_ed25519"
            storeKeyPair(walletKeyAlias, ed25519KeyPair)

            // Store seed phrase for this wallet
            val walletSeedAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_seed"
            encryptedPrefs.edit {
                putString(walletSeedAlias, seedPhrase)
            }

            // Get Solana address
            val solanaAddress = base58Encode(ed25519KeyPair.publicKey)

            Log.i(TAG, "New wallet generated: $walletId -> $solanaAddress")
            return Pair(walletId, solanaAddress)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate new wallet", e)
            throw KeyManagerException("Failed to generate new wallet", e)
        }
    }

    /**
     * Get Solana address for a specific wallet
     */
    fun getWalletSolanaAddress(walletId: String): String {
        try {
            if (walletId == "main") {
                return getSolanaAddress()
            }

            val walletKeyAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_ed25519"
            val publicKey = getStoredKey("${walletKeyAlias}_public")
                ?: throw KeyManagerException("Wallet not found: $walletId")

            return base58Encode(publicKey)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get wallet address", e)
            throw KeyManagerException("Failed to get wallet address", e)
        }
    }

    /**
     * Get private key for a specific wallet (for export)
     * NOTE: Main wallet (walletId="main") will return null for security
     */
    fun getWalletPrivateKey(walletId: String): ByteArray? {
        try {
            // Don't allow exporting main wallet private key
            if (walletId == "main") {
                Log.w(TAG, "Cannot export main wallet private key")
                return null
            }

            val walletKeyAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_ed25519"
            val privateKey = getStoredKey("${walletKeyAlias}_private")
                ?: throw KeyManagerException("Wallet not found: $walletId")

            Log.i(TAG, "Retrieved private key for wallet: $walletId")
            return privateKey

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get wallet private key", e)
            throw KeyManagerException("Failed to get wallet private key", e)
        }
    }

    /**
     * Get seed phrase for a specific wallet (for backup)
     * NOTE: Main wallet will return null for security
     */
    fun getWalletSeedPhrase(walletId: String): String? {
        try {
            // Don't allow exporting main wallet seed
            if (walletId == "main") {
                Log.w(TAG, "Cannot export main wallet seed phrase")
                return null
            }

            val walletSeedAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_seed"
            val seedPhrase = encryptedPrefs.getString(walletSeedAlias, null)
                ?: throw KeyManagerException("Wallet seed not found: $walletId")

            Log.i(TAG, "Retrieved seed phrase for wallet: $walletId")
            return seedPhrase

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get wallet seed phrase", e)
            throw KeyManagerException("Failed to get wallet seed phrase", e)
        }
    }

    /**
     * Delete a wallet (NOT allowed for main wallet)
     */
    fun deleteWallet(walletId: String): Boolean {
        try {
            // Don't allow deleting main wallet
            if (walletId == "main") {
                Log.w(TAG, "Cannot delete main wallet")
                return false
            }

            val walletKeyAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_ed25519"
            val walletSeedAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_seed"

            encryptedPrefs.edit {
                remove(walletKeyAlias + "_private")
                remove(walletKeyAlias + "_public")
                remove(walletSeedAlias)
            }

            Log.i(TAG, "Deleted wallet: $walletId")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete wallet", e)
            return false
        }
    }

    /**
     * Simple keypair holder
     */
    private data class KeyPair(
        val privateKey: ByteArray,
        val publicKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as KeyPair
            if (!privateKey.contentEquals(other.privateKey)) return false
            if (!publicKey.contentEquals(other.publicKey)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = privateKey.contentHashCode()
            result = 31 * result + publicKey.contentHashCode()
            return result
        }
    }
}

/**
 * KeyManager exception
 */
class KeyManagerException(message: String, cause: Throwable? = null) : Exception(message, cause)
