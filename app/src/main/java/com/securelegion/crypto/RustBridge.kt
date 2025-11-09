package com.securelegion.crypto

/**
 * JNI bridge to Rust cryptographic library
 *
 * Provides access to:
 * - Message encryption/decryption (XChaCha20-Poly1305)
 * - Digital signatures (Ed25519)
 * - Password hashing (Argon2id)
 * - Key generation and management
 * - Tor network integration
 * - Ping-Pong Wake Protocol
 */
object RustBridge {

    private var libraryLoaded = false

    init {
        try {
            android.util.Log.d("RustBridge", "Loading native library...")
            System.loadLibrary("securelegion")
            libraryLoaded = true
            android.util.Log.d("RustBridge", "Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            android.util.Log.e("RustBridge", "Failed to load native library", e)
            libraryLoaded = false
        }
    }

    // ==================== CRYPTOGRAPHY ====================

    /**
     * Encrypt a message using XChaCha20-Poly1305
     * @param plaintext The message to encrypt
     * @param recipientPublicKey The recipient's Ed25519 public key (32 bytes)
     * @return Encrypted message bytes
     */
    external fun encryptMessage(plaintext: String, recipientPublicKey: ByteArray): ByteArray

    /**
     * Decrypt a message using XChaCha20-Poly1305
     * @param ciphertext The encrypted message
     * @param senderPublicKey The sender's Ed25519 public key (32 bytes)
     * @return Decrypted plaintext string
     */
    external fun decryptMessage(ciphertext: ByteArray, senderPublicKey: ByteArray): String

    /**
     * Generate a new Ed25519 keypair
     * @return Keypair as ByteArray (first 32 bytes = private key, next 32 bytes = public key)
     */
    external fun generateKeypair(): ByteArray

    /**
     * Sign data with Ed25519 private key
     * @param data The data to sign
     * @param privateKey The Ed25519 private key (32 bytes)
     * @return Signature (64 bytes)
     */
    external fun signData(data: ByteArray, privateKey: ByteArray): ByteArray

    /**
     * Verify Ed25519 signature
     * @param data The original data
     * @param signature The signature to verify (64 bytes)
     * @param publicKey The Ed25519 public key (32 bytes)
     * @return True if signature is valid
     */
    external fun verifySignature(data: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean

    /**
     * Hash a password using Argon2id
     * @param password The password to hash
     * @param salt The salt (16 bytes recommended)
     * @return Password hash
     */
    external fun hashPassword(password: String, salt: ByteArray): ByteArray

    // ==================== TOR NETWORK ====================

    /**
     * Initialize Tor client and bootstrap connection to Tor network
     * This must be called before any other Tor operations
     * @return Status message
     */
    external fun initializeTor(): String

    /**
     * Create a hidden service and get the .onion address
     * @param servicePort The virtual port on the .onion address (default 9150)
     * @param localPort The local port to forward connections to (default 9150)
     * @return The .onion address for receiving connections
     */
    external fun createHiddenService(servicePort: Int = 9150, localPort: Int = 9150): String

    /**
     * Get the current hidden service .onion address (if created)
     * @return The .onion address or null if not created yet
     */
    external fun getHiddenServiceAddress(): String?

    /**
     * Start the hidden service listener on the specified port
     * This enables receiving incoming Ping tokens
     * @param port The local port to listen on (default 9150)
     * @return True if listener started successfully
     */
    external fun startHiddenServiceListener(port: Int = 9150): Boolean

    /**
     * Stop the hidden service listener
     */
    external fun stopHiddenServiceListener()

    /**
     * Poll for an incoming Ping token (non-blocking)
     * @return The Ping token bytes or null if no ping available
     */
    external fun pollIncomingPing(): ByteArray?

    // ==================== PING-PONG PROTOCOL ====================

    /**
     * Send a Ping token to a recipient
     * @param recipientPublicKey The recipient's Ed25519 public key
     * @param recipientOnion The recipient's .onion address
     * @return Ping ID for tracking
     */
    external fun sendPing(recipientPublicKey: ByteArray, recipientOnion: String): String

    /**
     * Wait for a Pong response
     * @param pingId The Ping ID returned from sendPing
     * @param timeoutSeconds Timeout in seconds
     * @return True if Pong received and authenticated
     */
    external fun waitForPong(pingId: String, timeoutSeconds: Int): Boolean

    /**
     * Respond to an incoming Ping with a Pong
     * @param pingId The Ping ID
     * @param authenticated Whether user successfully authenticated
     * @return Pong token bytes
     */
    external fun respondToPing(pingId: String, authenticated: Boolean): ByteArray

    // ==================== HELPER FUNCTIONS ====================

    /**
     * Check if the Rust library loaded successfully
     */
    fun isLibraryLoaded(): Boolean {
        return try {
            // Try to call a simple native method
            initializeTor()
            true
        } catch (e: UnsatisfiedLinkError) {
            false
        } catch (e: Exception) {
            false
        }
    }
}
