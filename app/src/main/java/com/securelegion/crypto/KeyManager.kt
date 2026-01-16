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
import java.io.File
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
        private const val KYBER_KEY_ALIAS = "${KEYSTORE_ALIAS_PREFIX}kyber_key"  // Post-quantum Kyber-1024 keys
        private const val HIDDEN_SERVICE_KEY_ALIAS = "${KEYSTORE_ALIAS_PREFIX}hidden_service_key"
        private const val DEVICE_PASSWORD_HASH_ALIAS = "${KEYSTORE_ALIAS_PREFIX}device_password_hash"
        private const val DEVICE_PASSWORD_SALT_ALIAS = "${KEYSTORE_ALIAS_PREFIX}device_password_salt"
        private const val ZCASH_ADDRESS_ALIAS = "${KEYSTORE_ALIAS_PREFIX}zcash_address"
        private const val ZCASH_TRANSPARENT_ADDRESS_ALIAS = "${KEYSTORE_ALIAS_PREFIX}zcash_transparent_address"

        // NEW v2.0 - Two .onion system keys
        private const val FRIEND_REQUEST_ONION_ALIAS = "${KEYSTORE_ALIAS_PREFIX}friend_request_onion"
        private const val MESSAGING_ONION_ALIAS = "${KEYSTORE_ALIAS_PREFIX}messaging_onion"
        private const val VOICE_ONION_ALIAS = "${KEYSTORE_ALIAS_PREFIX}voice_onion"
        private const val CONTACT_PIN_ALIAS = "${KEYSTORE_ALIAS_PREFIX}contact_pin"
        private const val IPFS_CID_ALIAS = "${KEYSTORE_ALIAS_PREFIX}ipfs_cid"
        private const val SEED_PHRASE_ALIAS = "${KEYSTORE_ALIAS_PREFIX}wallet_main_seed"

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

            // Generate Ed25519 voice service key (for voice calling .onion address)
            val voiceServiceKeyPair = deriveVoiceServiceKeyPair(seed)

            // Generate hybrid post-quantum KEM keypair (X25519 + Kyber-1024)
            val kyberKeyPair = deriveHybridKEMKeypair(seed)

            // Store keys securely in encrypted preferences
            storeKeyPair(ED25519_SIGNING_KEY_ALIAS, ed25519KeyPair)
            storeKeyPair(X25519_ENCRYPTION_KEY_ALIAS, x25519KeyPair)
            storeKeyPair(KYBER_KEY_ALIAS, kyberKeyPair)
            storeKeyPair(HIDDEN_SERVICE_KEY_ALIAS, hiddenServiceKeyPair)
            storeKeyPair(VOICE_ONION_ALIAS, voiceServiceKeyPair)

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
     * Create friend request .onion address (v2.0)
     * This creates the public .onion address for receiving friend requests
     * Called during account creation
     * @return The .onion address (56 characters + ".onion")
     */
    fun createFriendRequestOnion(): String {
        try {
            Log.d(TAG, "Creating friend request .onion address")

            // Get the persistent directory path that matches torrc configuration
            // This must be the same directory torrc uses: appContext.filesDir/tor/friend_request_hidden_service
            val torDataDir = File(appContext.filesDir, "tor")
            val friendRequestHiddenServiceDir = File(torDataDir, "friend_request_hidden_service")

            // Ensure directory exists
            friendRequestHiddenServiceDir.mkdirs()

            // Call Rust native function to generate/read persistent keys and derive .onion address
            // This does NOT start Tor - it just creates the keypair and derives the address locally
            val onionAddress = RustBridge.createFriendRequestHiddenService(
                servicePort = 9151,  // Public port for friend requests (not used in new implementation)
                localPort = 9151,    // Local wire protocol listener (not used in new implementation)
                directory = friendRequestHiddenServiceDir.absolutePath  // Full path to persistent directory
            )

            if (onionAddress.isEmpty()) {
                throw KeyManagerException("Failed to create friend request .onion: empty address returned")
            }

            // Store the .onion address
            storeFriendRequestOnion(onionAddress)

            Log.i(TAG, "Friend request .onion created: $onionAddress")
            return onionAddress
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create friend request .onion", e)
            throw KeyManagerException("Failed to create friend request .onion: ${e.message}", e)
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
     * Get Kyber-1024 public key (1568 bytes)
     * Shared with contacts for hybrid post-quantum key encapsulation
     * Used together with X25519 public key for quantum-resistant encryption
     */
    fun getKyberPublicKey(): ByteArray {
        return getStoredKey("${KYBER_KEY_ALIAS}_public")
            ?: throw KeyManagerException("Kyber public key not found. Initialize wallet first.")
    }

    /**
     * Get Kyber-1024 secret key (3168 bytes)
     * Used for hybrid post-quantum key decapsulation
     * Must be kept secret and protected
     */
    fun getKyberSecretKey(): ByteArray {
        return getStoredKey("${KYBER_KEY_ALIAS}_private")
            ?: throw KeyManagerException("Kyber secret key not found. Initialize wallet first.")
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
     * Get friend request Ed25519 private key (32 bytes)
     * Derives key on-the-fly from seed using domain separation (v2.0)
     * Called via JNI from Rust code for friend request .onion creation
     */
    @Suppress("unused")
    fun getFriendRequestKeyBytes(): ByteArray {
        // Get seed phrase (stored as plain text, not hex)
        val seedPhraseString = encryptedPrefs.getString(SEED_PHRASE_ALIAS, null)
            ?: throw KeyManagerException("Seed phrase not found. Initialize wallet first.")

        // Derive seed from mnemonic
        val seed = mnemonicToSeed(seedPhraseString)

        // Derive friend request keypair
        val keyPair = deriveFriendRequestKeyPair(seed)

        return keyPair.privateKey
    }

    /**
     * Get voice service Ed25519 private key (32 bytes)
     * Used for voice calling .onion address creation (v2.0)
     * Called via JNI from Rust code for voice hidden service creation
     */
    @Suppress("unused")
    fun getVoiceServicePrivateKey(): ByteArray {
        return getStoredKey("${VOICE_ONION_ALIAS}_private")
            ?: throw KeyManagerException("Voice service key not found. Initialize wallet first.")
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
     * Get wallet seed for Zcash SDK initialization
     * Returns the same BIP39 seed used for Solana (64 bytes)
     * Zcash SDK will use BIP44 path m/44'/133'/0'/0' for key derivation
     */
    fun getWalletSeed(): ByteArray {
        val seedHex = encryptedPrefs.getString(WALLET_SEED_ALIAS, null)
            ?: throw KeyManagerException("Wallet seed not found. Initialize wallet first.")
        return hexToBytes(seedHex)
    }

    /**
     * Get Zcash unified address (stored after Zcash SDK initialization)
     * Returns the shielded address for receiving ZEC
     */
    fun getZcashAddress(): String? {
        return encryptedPrefs.getString(ZCASH_ADDRESS_ALIAS, null)
    }

    /**
     * Store Zcash unified address
     * Called after Zcash SDK generates the address
     */
    fun setZcashAddress(address: String) {
        encryptedPrefs.edit {
            putString(ZCASH_ADDRESS_ALIAS, address)
        }
        Log.d(TAG, "Zcash address stored: $address")
    }

    /**
     * Get Zcash transparent address (for exchange compatibility)
     */
    fun getZcashTransparentAddress(): String? {
        return encryptedPrefs.getString(ZCASH_TRANSPARENT_ADDRESS_ALIAS, null)
    }

    /**
     * Store Zcash transparent address
     * This is the t1... address compatible with exchanges
     */
    fun setZcashTransparentAddress(address: String) {
        encryptedPrefs.edit {
            putString(ZCASH_TRANSPARENT_ADDRESS_ALIAS, address)
        }
        Log.d(TAG, "Zcash transparent address stored: $address")
    }

    /**
     * Clear all stored Zcash addresses
     * Use this when deleting a Zcash wallet or switching accounts
     */
    fun clearZcashAddresses() {
        encryptedPrefs.edit {
            remove(ZCASH_ADDRESS_ALIAS)
            remove(ZCASH_TRANSPARENT_ADDRESS_ALIAS)
        }
        Log.d(TAG, "Zcash addresses cleared from KeyManager")
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
     * Derive hybrid post-quantum KEM keypair from seed (X25519 + Kyber-1024)
     * Stores only Kyber keys (1568-byte public + 3168-byte secret)
     * X25519 keys are already stored separately via deriveX25519KeyPair
     *
     * Security: Uses same seed as X25519, but Rust applies domain separation
     * internally to derive independent Kyber seed via SHA-256(seed || "kyber1024")
     */
    private fun deriveHybridKEMKeypair(seed: ByteArray): KeyPair {
        // Use same seed derivation as X25519 for consistency
        val messageDigest = MessageDigest.getInstance("SHA-256")
        messageDigest.update(seed)
        messageDigest.update("x25519".toByteArray())
        val x25519Seed = messageDigest.digest()

        // Call Rust to generate full hybrid keypair
        // Returns: [x25519_pub:32][x25519_sec:32][kyber_pub:1568][kyber_sec:3168]
        val fullKeypair = RustBridge.generateHybridKEMKeypairFromSeed(x25519Seed)

        // Extract only Kyber keys (skip first 64 bytes which are X25519 keys)
        val kyberPublic = fullKeypair.copyOfRange(64, 64 + 1568)
        val kyberSecret = fullKeypair.copyOfRange(64 + 1568, fullKeypair.size)

        Log.d(TAG, "Derived Kyber-1024 keypair (public: ${kyberPublic.size} bytes, secret: ${kyberSecret.size} bytes)")

        return KeyPair(kyberSecret, kyberPublic)
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
     * Derive Ed25519 keypair for friend request .onion from seed (v2.0)
     * Uses domain separation: SHA-256(seed || "friend_req")
     * This is DIFFERENT from the messaging .onion to enable two-onion architecture
     */
    private fun deriveFriendRequestKeyPair(seed: ByteArray): KeyPair {
        // Domain separation: hash seed with "friend_req" to derive different key
        val messageDigest = MessageDigest.getInstance("SHA-256")
        messageDigest.update(seed)
        messageDigest.update("friend_req".toByteArray())
        val frSeed = messageDigest.digest()

        // Generate Ed25519 keypair from seed using libsodium
        val publicKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
        val privateKeyFull = ByteArray(Sign.ED25519_SECRETKEYBYTES) // 64 bytes

        lazySodium.cryptoSignSeedKeypair(publicKey, privateKeyFull, frSeed)

        // Extract 32-byte private key (libsodium returns 64 bytes: seed || public_key)
        val privateKey = privateKeyFull.copyOfRange(0, 32)

        Log.d(TAG, "Derived friend request Ed25519 keypair (private: ${privateKey.size} bytes, public: ${publicKey.size} bytes)")

        return KeyPair(privateKey, publicKey)
    }

    /**
     * Derive Ed25519 keypair for voice .onion from seed (v2.0)
     * Uses domain separation: SHA-256(seed || "tor_voice")
     * Third .onion address dedicated to voice calling (port 9152)
     */
    private fun deriveVoiceServiceKeyPair(seed: ByteArray): KeyPair {
        // Domain separation: hash seed with "tor_voice" to derive different key
        val messageDigest = MessageDigest.getInstance("SHA-256")
        messageDigest.update(seed)
        messageDigest.update("tor_voice".toByteArray())
        val voiceSeed = messageDigest.digest()

        // Generate Ed25519 keypair from seed using libsodium
        val publicKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
        val privateKeyFull = ByteArray(Sign.ED25519_SECRETKEYBYTES) // 64 bytes

        lazySodium.cryptoSignSeedKeypair(publicKey, privateKeyFull, voiceSeed)

        // Extract 32-byte private key (libsodium returns 64 bytes: seed || public_key)
        val privateKey = privateKeyFull.copyOfRange(0, 32)

        Log.d(TAG, "Derived voice service Ed25519 keypair (private: ${privateKey.size} bytes, public: ${publicKey.size} bytes)")

        return KeyPair(privateKey, publicKey)
    }

    /**
     * Derive deterministic IPFS CID from seed phrase (v2.0)
     * Uses domain separation: SHA-256(seed || "ipfs_cid")
     * Returns CIDv1 format (base32-encoded multihash)
     * Format: b{base32(0x01 || 0x55 || 0x12 || 0x20 || hash)}
     */
    fun deriveIPFSCID(seedPhrase: String): String {
        try {
            // Get BIP39 seed
            val seed = mnemonicToSeed(seedPhrase)

            // Domain separation: hash seed with "ipfs_cid" to derive unique hash
            val messageDigest = MessageDigest.getInstance("SHA-256")
            messageDigest.update(seed)
            messageDigest.update("ipfs_cid".toByteArray())
            val hash = messageDigest.digest()

            // Build CIDv1 multihash structure:
            // 0x01 = CIDv1
            // 0x55 = raw codec
            // 0x12 = SHA-256 multihash type
            // 0x20 = hash length (32 bytes)
            // + hash bytes
            val cidBytes = ByteArray(1 + 1 + 1 + 1 + hash.size)
            cidBytes[0] = 0x01.toByte() // CIDv1
            cidBytes[1] = 0x55.toByte() // raw codec
            cidBytes[2] = 0x12.toByte() // SHA-256
            cidBytes[3] = 0x20.toByte() // 32 bytes
            System.arraycopy(hash, 0, cidBytes, 4, hash.size)

            // Encode to base32 (lowercase for CIDv1)
            val base32 = android.util.Base64.encodeToString(cidBytes, android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
                .lowercase()
                .replace('+', '-')
                .replace('/', '_')

            // CIDv1 format: "b" + base32-encoded bytes
            val cid = "b$base32"

            Log.d(TAG, "Derived IPFS CID: $cid")
            return cid
        } catch (e: Exception) {
            Log.e(TAG, "Failed to derive IPFS CID", e)
            throw e
        }
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
        return getIPFSCID() != null && getContactPin() != null
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

    /**
     * Store friend request .onion address (v2.0)
     * This is the public .onion address for receiving friend requests
     */
    fun storeFriendRequestOnion(onion: String) {
        encryptedPrefs.edit {
            putString(FRIEND_REQUEST_ONION_ALIAS, onion)
        }
        Log.i(TAG, "Stored friend request .onion: $onion")
    }

    /**
     * Get friend request .onion address (v2.0)
     */
    fun getFriendRequestOnion(): String? {
        return encryptedPrefs.getString(FRIEND_REQUEST_ONION_ALIAS, null)
    }

    /**
     * Store messaging .onion address (v2.0)
     */
    fun storeMessagingOnion(onion: String) {
        encryptedPrefs.edit {
            putString(MESSAGING_ONION_ALIAS, onion)
        }
        Log.i(TAG, "Stored messaging .onion: $onion")
    }

    /**
     * Get messaging .onion address (v2.0)
     */
    fun getMessagingOnion(): String? {
        return encryptedPrefs.getString(MESSAGING_ONION_ALIAS, null)
    }

    /**
     * Store contact PIN (v2.0)
     * 10-digit PIN formatted as XXX-XXX-XXXX
     * Stored encrypted in EncryptedSharedPreferences
     */
    fun storeContactPin(pin: String) {
        encryptedPrefs.edit {
            putString(CONTACT_PIN_ALIAS, pin)
        }
        Log.i(TAG, "Stored contact PIN")
    }

    /**
     * Get contact PIN (v2.0)
     */
    fun getContactPin(): String? {
        return encryptedPrefs.getString(CONTACT_PIN_ALIAS, null)
    }

    /**
     * Store IPFS CID (v2.0)
     * Deterministic CID derived from seed phrase
     */
    fun storeIPFSCID(cid: String) {
        encryptedPrefs.edit {
            putString(IPFS_CID_ALIAS, cid)
        }
        Log.i(TAG, "Stored IPFS CID: $cid")
    }

    /**
     * Get IPFS CID (v2.0)
     */
    fun getIPFSCID(): String? {
        return encryptedPrefs.getString(IPFS_CID_ALIAS, null)
    }

    // ==================== CONTACT LIST BACKUP (v5 Architecture) ====================

    /**
     * Derive deterministic contact list CID from stored seed phrase (v5)
     * Uses domain separation: SHA-256(seed || "contact_list_cid")
     * Returns CIDv1 format for IPFS mesh backup
     */
    fun deriveContactListCID(): String {
        val seedPhrase = getMainWalletSeedForZcash()
            ?: throw KeyManagerException("Seed phrase not found. Initialize wallet first.")
        return deriveContactListCIDFromSeed(seedPhrase)
    }

    /**
     * Derive deterministic contact list CID from provided seed phrase (v5)
     * Used during account recovery to locate user's contact list in IPFS mesh
     *
     * Domain separation ensures contact list CID is different from contact card CID
     * Format: b{base32(0x01 || 0x55 || 0x12 || 0x20 || hash)}
     */
    fun deriveContactListCIDFromSeed(seedPhrase: String): String {
        try {
            // Get BIP39 seed
            val seed = mnemonicToSeed(seedPhrase)

            // Domain separation: hash seed with "contact_list_cid"
            // This is DIFFERENT from contact card CID ("ipfs_cid")
            val messageDigest = MessageDigest.getInstance("SHA-256")
            messageDigest.update(seed)
            messageDigest.update("contact_list_cid".toByteArray())
            val hash = messageDigest.digest()

            // Build CIDv1 multihash structure:
            // 0x01 = CIDv1
            // 0x55 = raw codec
            // 0x12 = SHA-256 multihash type
            // 0x20 = hash length (32 bytes)
            val cidBytes = ByteArray(1 + 1 + 1 + 1 + hash.size)
            cidBytes[0] = 0x01.toByte() // CIDv1
            cidBytes[1] = 0x55.toByte() // raw codec
            cidBytes[2] = 0x12.toByte() // SHA-256
            cidBytes[3] = 0x20.toByte() // 32 bytes
            System.arraycopy(hash, 0, cidBytes, 4, hash.size)

            // Encode to base32 (lowercase for CIDv1)
            val base32 = android.util.Base64.encodeToString(cidBytes, android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
                .lowercase()
                .replace('+', '-')
                .replace('/', '_')

            // CIDv1 format: "b" + base32-encoded bytes
            val cid = "b$base32"

            Log.d(TAG, "Derived contact list CID: $cid")
            return cid
        } catch (e: Exception) {
            Log.e(TAG, "Failed to derive contact list CID", e)
            throw e
        }
    }

    /**
     * Derive contact PIN from provided seed phrase (v5)
     * Used during account recovery to decrypt contact list from IPFS mesh
     *
     * Derives a 10-digit PIN formatted as XXX-XXX-XXXX
     * Domain separation: SHA-256(seed || "contact_list_pin")
     */
    fun deriveContactPinFromSeed(seedPhrase: String): String {
        try {
            // Get BIP39 seed
            val seed = mnemonicToSeed(seedPhrase)

            // Domain separation: hash seed with "contact_list_pin"
            val messageDigest = MessageDigest.getInstance("SHA-256")
            messageDigest.update(seed)
            messageDigest.update("contact_list_pin".toByteArray())
            val hash = messageDigest.digest()

            // Convert first 4 bytes of hash to a 10-digit number
            val num = (hash[0].toInt() and 0xFF shl 24) or
                     (hash[1].toInt() and 0xFF shl 16) or
                     (hash[2].toInt() and 0xFF shl 8) or
                     (hash[3].toInt() and 0xFF)

            // Take absolute value and mod by 10 billion to get 10 digits
            val pinNumber = kotlin.math.abs(num.toLong()) % 10000000000L

            // Format as XXX-XXX-XXXX
            val pinString = pinNumber.toString().padStart(10, '0')
            val pin = "${pinString.substring(0, 3)}-${pinString.substring(3, 6)}-${pinString.substring(6, 10)}"

            Log.d(TAG, "Derived contact list PIN")
            return pin
        } catch (e: Exception) {
            Log.e(TAG, "Failed to derive contact list PIN", e)
            throw e
        }
    }

    // ==================== SEED PHRASE STORAGE ====================

    /**
     * Store seed phrase (encrypted) for display on account created screen
     * WARNING: This is stored temporarily and should be cleared after user confirms backup
     */
    fun storeSeedPhrase(seedPhrase: String) {
        encryptedPrefs.edit {
            putString("seed_phrase_backup", seedPhrase)
        }
        Log.i(TAG, "Stored seed phrase for backup display")
    }

    /**
     * Store seed phrase permanently for main wallet (needed for Zcash initialization)
     */
    fun storeMainWalletSeed(seedPhrase: String) {
        encryptedPrefs.edit {
            putString("${KEYSTORE_ALIAS_PREFIX}wallet_main_seed", seedPhrase)
        }
        Log.i(TAG, "Stored seed phrase permanently for main wallet")
    }

    /**
     * Get main wallet seed phrase for internal use (Zcash initialization)
     * This bypasses the export protection in getWalletSeedPhrase()
     */
    fun getMainWalletSeedForZcash(): String? {
        return encryptedPrefs.getString("${KEYSTORE_ALIAS_PREFIX}wallet_main_seed", null)
    }

    /**
     * Get stored seed phrase for display
     */
    fun getSeedPhrase(): String? {
        return encryptedPrefs.getString("seed_phrase_backup", null)
    }

    /**
     * Clear stored seed phrase after user confirms backup
     */
    fun clearSeedPhraseBackup() {
        encryptedPrefs.edit {
            remove("seed_phrase_backup")
        }
        Log.i(TAG, "Cleared seed phrase backup")
    }

    // ==================== DEVICE PASSWORD MANAGEMENT ====================

    /**
     * Set device password (stores Argon2id hash with random salt)
     * Called during account creation
     */
    fun setDevicePassword(password: String) {
        if (password.isBlank()) {
            throw IllegalArgumentException("Password cannot be blank")
        }

        // Generate random 32-byte salt
        val salt = ByteArray(32)
        java.security.SecureRandom().nextBytes(salt)

        // Hash password with Argon2id (memory-hard, GPU-resistant)
        val passwordHash = RustBridge.hashPassword(password, salt)

        // Store both hash and salt in encrypted preferences
        encryptedPrefs.edit {
            putString(DEVICE_PASSWORD_HASH_ALIAS, bytesToHex(passwordHash))
            putString(DEVICE_PASSWORD_SALT_ALIAS, bytesToHex(salt))
        }

        Log.i(TAG, "Device password set successfully (Argon2id)")
    }

    /**
     * Verify device password using Argon2id
     * Returns true if password matches stored hash
     */
    fun verifyDevicePassword(password: String): Boolean {
        val storedHashHex = encryptedPrefs.getString(DEVICE_PASSWORD_HASH_ALIAS, null)
            ?: return false
        val storedSaltHex = encryptedPrefs.getString(DEVICE_PASSWORD_SALT_ALIAS, null)
            ?: return false

        try {
            // Decode stored hash and salt
            val storedHash = hexToBytes(storedHashHex)
            val salt = hexToBytes(storedSaltHex)

            // Hash provided password with same salt
            val providedHash = RustBridge.hashPassword(password, salt)

            // Constant-time comparison to prevent timing attacks
            return java.security.MessageDigest.isEqual(storedHash, providedHash)
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying device password", e)
            return false
        }
    }

    /**
     * Get the stored password hash for biometric encryption
     * Used to encrypt password hash with biometric-protected key
     */
    fun getPasswordHash(): ByteArray? {
        val storedHashHex = encryptedPrefs.getString(DEVICE_PASSWORD_HASH_ALIAS, null)
            ?: return null
        return try {
            hexToBytes(storedHashHex)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting password hash", e)
            null
        }
    }

    /**
     * Verify password hash directly (used after biometric decryption)
     * @param providedHash The password hash to verify (from biometric decryption)
     * @return true if hash matches stored hash
     */
    fun verifyPasswordHash(providedHash: ByteArray): Boolean {
        val storedHashHex = encryptedPrefs.getString(DEVICE_PASSWORD_HASH_ALIAS, null)
            ?: return false

        try {
            val storedHash = hexToBytes(storedHashHex)
            // Constant-time comparison to prevent timing attacks
            return java.security.MessageDigest.isEqual(storedHash, providedHash)
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying password hash", e)
            return false
        }
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
     *
     * SECURITY: Caller MUST zeroize the returned ByteArray after use!
     * Use the extension function: passphrase.zeroize() or passphrase.useAndZeroize { }
     *
     * @return 32-byte passphrase for SQLCipher (must be zeroized after use)
     */
    fun getDatabasePassphrase(): ByteArray {
        if (!isInitialized()) {
            throw IllegalStateException("KeyManager not initialized")
        }

        var seed: ByteArray? = null
        try {
            seed = getSeedBytes()

            // Derive database key using SHA-256 with application-specific salt
            // This ensures database key is deterministic and unique per wallet
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(seed)
            digest.update("secure_legion_database_v1".toByteArray(Charsets.UTF_8))
            val databaseKey = digest.digest()

            Log.i(TAG, "Derived database encryption key")
            return databaseKey
        } finally {
            // SECURITY: Zeroize seed from memory to prevent extraction
            seed?.let { java.util.Arrays.fill(it, 0.toByte()) }
        }
    }

    /**
     * Derive voice file encryption key from BIP39 seed
     * Uses SHA-256(seed + "voice_files_key" salt) for deterministic key
     *
     * SECURITY: Caller MUST zeroize the returned ByteArray after use!
     * Use the extension function: key.zeroize() or key.useAndZeroize { }
     *
     * @return 32-byte key for voice file encryption (must be zeroized after use)
     */
    fun getVoiceFileEncryptionKey(): ByteArray {
        if (!isInitialized()) {
            throw IllegalStateException("KeyManager not initialized")
        }

        var seed: ByteArray? = null
        try {
            seed = getSeedBytes()

            // Derive voice file key using SHA-256 with application-specific salt
            // This ensures key is deterministic and unique per wallet
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(seed)
            digest.update("secure_legion_voice_files_v1".toByteArray(Charsets.UTF_8))
            val voiceKey = digest.digest()

            Log.i(TAG, "Derived voice file encryption key")
            return voiceKey
        } finally {
            // SECURITY: Zeroize seed from memory to prevent extraction
            seed?.let { java.util.Arrays.fill(it, 0.toByte()) }
        }
    }

    /**
     * Encrypt voice file data using AES-256-GCM
     * @param audioBytes Raw audio data to encrypt
     * @return Encrypted data with format: [12-byte nonce][encrypted audio][16-byte auth tag]
     */
    fun encryptVoiceFile(audioBytes: ByteArray): ByteArray {
        var key: ByteArray? = null
        try {
            key = getVoiceFileEncryptionKey()

            // Generate random 12-byte nonce for AES-GCM
            val nonce = ByteArray(12)
            java.security.SecureRandom().nextBytes(nonce)

            // Create AES-GCM cipher
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey = javax.crypto.spec.SecretKeySpec(key, "AES")
            val gcmSpec = javax.crypto.spec.GCMParameterSpec(128, nonce) // 128-bit auth tag
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

            // Encrypt (includes 16-byte authentication tag)
            val encrypted = cipher.doFinal(audioBytes)

            // Return [nonce][encrypted+tag]
            val result = ByteArray(nonce.size + encrypted.size)
            System.arraycopy(nonce, 0, result, 0, nonce.size)
            System.arraycopy(encrypted, 0, result, nonce.size, encrypted.size)

            Log.i(TAG, "Encrypted voice file: ${audioBytes.size} bytes → ${result.size} bytes")
            return result
        } finally {
            // SECURITY: Zeroize key from memory
            key?.let { java.util.Arrays.fill(it, 0.toByte()) }
        }
    }

    /**
     * Decrypt voice file data using AES-256-GCM
     * @param encryptedData Encrypted data with format: [12-byte nonce][encrypted audio][16-byte auth tag]
     * @return Decrypted audio data
     */
    fun decryptVoiceFile(encryptedData: ByteArray): ByteArray {
        var key: ByteArray? = null
        try {
            if (encryptedData.size < 12 + 16) {
                throw IllegalArgumentException("Encrypted data too short (minimum 28 bytes)")
            }

            key = getVoiceFileEncryptionKey()

            // Extract nonce (first 12 bytes)
            val nonce = ByteArray(12)
            System.arraycopy(encryptedData, 0, nonce, 0, 12)

            // Extract encrypted data + tag (remaining bytes)
            val encrypted = ByteArray(encryptedData.size - 12)
            System.arraycopy(encryptedData, 12, encrypted, 0, encrypted.size)

            // Create AES-GCM cipher
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey = javax.crypto.spec.SecretKeySpec(key, "AES")
            val gcmSpec = javax.crypto.spec.GCMParameterSpec(128, nonce) // 128-bit auth tag
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            // Decrypt (verifies authentication tag)
            val decrypted = cipher.doFinal(encrypted)

            Log.i(TAG, "Decrypted voice file: ${encryptedData.size} bytes → ${decrypted.size} bytes")
            return decrypted
        } catch (e: javax.crypto.AEADBadTagException) {
            Log.e(TAG, "Voice file authentication failed - data corrupted or tampered")
            throw SecurityException("Voice file authentication failed", e)
        } finally {
            // SECURITY: Zeroize key from memory
            key?.let { java.util.Arrays.fill(it, 0.toByte()) }
        }
    }

    /**
     * Extension function to zeroize ByteArray (fill with zeros)
     * Call this on sensitive data like passphrases after use
     */
    fun ByteArray.zeroize() {
        java.util.Arrays.fill(this, 0.toByte())
    }

    /**
     * Extension function to safely use and automatically zeroize a ByteArray
     * Usage: passphrase.useAndZeroize { pass -> database.init(pass) }
     */
    inline fun <T> ByteArray.useAndZeroize(block: (ByteArray) -> T): T {
        return try {
            block(this)
        } finally {
            this.zeroize()
        }
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
     * NOTE: Protected wallets will return null for security
     */
    fun getWalletPrivateKey(walletId: String): ByteArray? {
        try {
            // Don't allow exporting protected wallet private key
            if (walletId == "main") {
                Log.w(TAG, "Cannot export protected wallet private key")
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
     * Store seed phrase for a specific wallet
     */
    fun storeWalletSeed(walletId: String, seedPhrase: String) {
        try {
            val walletSeedAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_seed"
            encryptedPrefs.edit {
                putString(walletSeedAlias, seedPhrase)
            }
            Log.i(TAG, "Stored seed phrase for wallet: $walletId")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store wallet seed phrase", e)
            throw KeyManagerException("Failed to store wallet seed phrase", e)
        }
    }

    /**
     * Get seed phrase for a specific wallet (for backup)
     * NOTE: Protected wallets will return null for security
     */
    fun getWalletSeedPhrase(walletId: String): String? {
        try {
            // Don't allow exporting protected wallet seed
            if (walletId == "main") {
                Log.w(TAG, "Cannot export protected wallet seed phrase")
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
     * Import wallet from seed phrase
     */
    fun importWalletFromSeed(walletId: String, seedPhrase: String): Boolean {
        try {
            Log.i(TAG, "Importing wallet from seed phrase: $walletId")

            // Validate seed phrase (should be 12 or 24 words)
            val words = seedPhrase.trim().split("\\s+".toRegex())
            if (words.size != 12 && words.size != 24) {
                Log.e(TAG, "Invalid seed phrase: expected 12 or 24 words, got ${words.size}")
                return false
            }

            // Store the seed phrase
            val walletSeedAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_seed"
            encryptedPrefs.edit {
                putString(walletSeedAlias, seedPhrase)
            }

            // Derive Ed25519 keypair from seed
            val seed = mnemonicToSeed(seedPhrase)
            val keyPair = deriveEd25519KeyPair(seed)

            // Store Ed25519 keys
            val walletKeyAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_ed25519"
            encryptedPrefs.edit {
                putString(walletKeyAlias + "_private", bytesToHex(keyPair.privateKey))
                putString(walletKeyAlias + "_public", bytesToHex(keyPair.publicKey))
            }

            Log.i(TAG, "Wallet imported successfully from seed phrase: $walletId")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to import wallet from seed", e)
            return false
        }
    }

    /**
     * Import Solana wallet from private key (base58 encoded)
     */
    fun importSolanaWalletFromPrivateKey(walletId: String, privateKeyInput: String): Boolean {
        try {
            Log.i(TAG, "Importing Solana wallet from private key: $walletId")

            // Decode private key - support both Base58 and JSON array formats
            val privateKeyBytes = try {
                val trimmedInput = privateKeyInput.trim()

                // Check if it's a JSON array format like [1,2,3,...]
                if (trimmedInput.startsWith("[") && trimmedInput.endsWith("]")) {
                    Log.d(TAG, "Detected JSON array format private key")
                    val jsonArray = trimmedInput.substring(1, trimmedInput.length - 1)
                    val byteValues = jsonArray.split(",").map { it.trim().toInt().toByte() }
                    byteValues.toByteArray()
                } else {
                    // Assume Base58 format
                    Log.d(TAG, "Attempting Base58 decode")
                    org.bitcoinj.core.Base58.decode(trimmedInput)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Invalid private key format (not Base58 or JSON array)", e)
                return false
            }

            // Solana uses Ed25519, private key should be 32 or 64 bytes
            val actualPrivateKey = if (privateKeyBytes.size == 64) {
                // If 64 bytes, first 32 are the private key, last 32 are public key
                Log.d(TAG, "64-byte key detected, using first 32 bytes")
                privateKeyBytes.copyOfRange(0, 32)
            } else if (privateKeyBytes.size == 32) {
                Log.d(TAG, "32-byte key detected")
                privateKeyBytes
            } else {
                Log.e(TAG, "Invalid private key size: ${privateKeyBytes.size} bytes (expected 32 or 64)")
                return false
            }

            // Derive public key from private key
            val publicKey = deriveEd25519PublicKey(actualPrivateKey)

            // Store Ed25519 keys
            val walletKeyAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_ed25519"
            encryptedPrefs.edit {
                putString(walletKeyAlias + "_private", bytesToHex(actualPrivateKey))
                putString(walletKeyAlias + "_public", bytesToHex(publicKey))
            }

            Log.i(TAG, "Solana wallet imported successfully from private key: $walletId")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to import Solana wallet from private key", e)
            return false
        }
    }

    /**
     * Import Zcash wallet from private key (WIF format)
     */
    fun importZcashWalletFromPrivateKey(walletId: String, privateKeyWIF: String): Boolean {
        try {
            Log.i(TAG, "Importing Zcash wallet from private key: $walletId")

            // For now, treat WIF as base58 and decode
            // Note: Full WIF parsing would require checksum validation
            val privateKeyBytes = try {
                org.bitcoinj.core.Base58.decode(privateKeyWIF)
            } catch (e: Exception) {
                Log.e(TAG, "Invalid WIF private key", e)
                return false
            }

            // Remove version byte and checksum if present
            val actualPrivateKey = when {
                privateKeyBytes.size == 37 && privateKeyBytes[0] == 0x80.toByte() -> {
                    // Mainnet WIF: 1 byte version + 32 bytes key + 4 bytes checksum
                    privateKeyBytes.copyOfRange(1, 33)
                }
                privateKeyBytes.size == 38 && privateKeyBytes[0] == 0x80.toByte() -> {
                    // Compressed WIF: 1 byte version + 32 bytes key + 1 byte compression flag + 4 bytes checksum
                    privateKeyBytes.copyOfRange(1, 33)
                }
                privateKeyBytes.size == 32 -> {
                    // Raw 32-byte key
                    privateKeyBytes
                }
                else -> {
                    Log.e(TAG, "Invalid WIF key size: ${privateKeyBytes.size}")
                    return false
                }
            }

            // Derive public key from private key
            val publicKey = deriveEd25519PublicKey(actualPrivateKey)

            // Store Ed25519 keys
            val walletKeyAlias = "${KEYSTORE_ALIAS_PREFIX}wallet_${walletId}_ed25519"
            encryptedPrefs.edit {
                putString(walletKeyAlias + "_private", bytesToHex(actualPrivateKey))
                putString(walletKeyAlias + "_public", bytesToHex(publicKey))
            }

            Log.i(TAG, "Zcash wallet imported successfully from private key: $walletId")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to import Zcash wallet from private key", e)
            return false
        }
    }

    /**
     * Derive Ed25519 public key from private key
     */
    private fun deriveEd25519PublicKey(privateKey: ByteArray): ByteArray {
        try {
            // Use BouncyCastle Ed25519 to derive public key from private key
            val privateKeyParams = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(privateKey, 0)
            val publicKeyParams = privateKeyParams.generatePublicKey()
            return publicKeyParams.encoded
        } catch (e: Exception) {
            Log.e(TAG, "Failed to derive public key from private key", e)
            throw KeyManagerException("Failed to derive public key from private key", e)
        }
    }

    /**
     * Delete a wallet (NOT allowed for protected wallets)
     */
    fun deleteWallet(walletId: String): Boolean {
        try {
            // Don't allow deleting protected wallet
            if (walletId == "main") {
                Log.w(TAG, "Cannot delete protected wallet")
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
