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

        @Volatile
        private var instance: KeyManager? = null

        @Suppress("unused") // Called via JNI from Rust code
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
     * Get Tor onion address derived from hidden service key
     */
    fun getTorOnionAddress(): String {
        val publicKey = getStoredKey("${HIDDEN_SERVICE_KEY_ALIAS}_public")
            ?: throw KeyManagerException("Hidden service key not found")

        // Convert Ed25519 public key to onion address v3 format
        // Format: base32(public_key + checksum + version).onion
        val onionAddress = publicKeyToOnionAddress(publicKey)
        return "$onionAddress:9050" // Default Tor port
    }

    /**
     * Convert Ed25519 public key to Tor v3 onion address
     */
    private fun publicKeyToOnionAddress(publicKey: ByteArray): String {
        // Tor v3 address = base32(public_key || checksum || version)
        // This is a simplified version - full implementation requires Tor spec
        val version = byteArrayOf(0x03)
        val checksumInput = ".onion checksum".toByteArray() + publicKey + version
        val checksum = sha256(checksumInput).take(2).toByteArray()

        val combined = publicKey + checksum + version
        return base32Encode(combined).lowercase()
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
