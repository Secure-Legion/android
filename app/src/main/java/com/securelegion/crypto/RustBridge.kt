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

    // ==================== RESULT WRAPPER CLASSES ====================

    /**
     * Result of encryption with atomic key evolution
     * Signal-like approach: encryption and key evolution happen atomically
     */
    data class EncryptionResult(
        val ciphertext: ByteArray,
        val evolvedChainKey: ByteArray
    )

    /**
     * Result of decryption with atomic key evolution
     * Signal-like approach: decryption and key evolution happen atomically
     */
    data class DecryptionResult(
        val plaintext: String,
        val evolvedChainKey: ByteArray
    )

    // ==================== CRYPTOGRAPHY ====================

    /**
     * Encrypt a message using XChaCha20-Poly1305 with X25519 ECDH
     * Uses proper ECDH to derive shared secret for encryption
     * Wire format: [Our X25519 Public Key - 32 bytes][Encrypted Message]
     * @param plaintext The message to encrypt
     * @param recipientX25519PublicKey The recipient's X25519 public key (32 bytes)
     * @return Wire message bytes (our X25519 public key + encrypted data)
     */
    external fun encryptMessage(plaintext: String, recipientX25519PublicKey: ByteArray): ByteArray

    /**
     * Decrypt a message using XChaCha20-Poly1305 with X25519 ECDH
     * Uses proper ECDH to derive shared secret for decryption
     * Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Message]
     * @param wireMessage The wire message (sender X25519 public key + encrypted data)
     * @param senderPublicKey DEPRECATED - not used (kept for API compatibility)
     * @param privateKey DEPRECATED - not used (kept for API compatibility)
     * @return Decrypted plaintext string, or null if decryption fails
     */
    external fun decryptMessage(wireMessage: ByteArray, senderPublicKey: ByteArray, privateKey: ByteArray): String?

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

    // ==================== POST-QUANTUM CRYPTOGRAPHY (Hybrid X25519 + ML-KEM-1024) ====================

    /**
     * Generate hybrid post-quantum KEM keypair from seed (deterministic)
     * Combines X25519 (classical ECDH) with ML-KEM-1024 (NIST FIPS 203)
     * Security: Protected if EITHER X25519 OR Kyber-1024 remains unbroken
     * @param seed 32-byte seed for deterministic key derivation
     * @return Serialized keypair bytes: [x25519_pub:32][x25519_sec:32][kyber_pub:1568][kyber_sec:3168]
     */
    external fun generateHybridKEMKeypairFromSeed(seed: ByteArray): ByteArray

    /**
     * Hybrid KEM encapsulation - generate shared secret for recipient
     * Combines X25519 ECDH with Kyber-1024 encapsulation using HKDF-SHA256
     * @param theirX25519Public Recipient's X25519 public key (32 bytes)
     * @param theirKyberPublic Recipient's Kyber-1024 public key (1568 bytes)
     * @return Result bytes: [combined_secret:64][x25519_ephemeral:32][kyber_ciphertext:1568]
     */
    external fun hybridEncapsulate(theirX25519Public: ByteArray, theirKyberPublic: ByteArray): ByteArray

    /**
     * Hybrid KEM decapsulation - recover shared secret from ciphertext
     * Decapsulates both X25519 and Kyber-1024 components and combines using HKDF
     * @param ourX25519Secret Our X25519 secret key (32 bytes)
     * @param ourKyberSecret Our Kyber-1024 secret key (3168 bytes)
     * @param ciphertext Hybrid ciphertext: [x25519_ephemeral:32][kyber_ciphertext:1568]
     * @return Combined shared secret (64 bytes), or null if decapsulation fails
     */
    external fun hybridDecapsulate(ourX25519Secret: ByteArray, ourKyberSecret: ByteArray, ciphertext: ByteArray): ByteArray?

    // ==================== KEY EVOLUTION (Progressive Ephemeral Keys) ====================

    /**
     * Derive X25519 shared secret using ECDH
     * @param ourPrivateKey Our 32-byte X25519 private key
     * @param theirPublicKey Their 32-byte X25519 public key
     * @return 32-byte shared secret
     */
    external fun deriveSharedSecret(ourPrivateKey: ByteArray, theirPublicKey: ByteArray): ByteArray

    /**
     * Derive root key from X25519 shared secret using HKDF-SHA256
     * Initializes the key chain for a contact
     * @param sharedSecret 32-byte X25519 shared secret
     * @param info Context string (e.g., "SecureLegion-RootKey-v1")
     * @return 32-byte root key
     */
    external fun deriveRootKey(sharedSecret: ByteArray, info: String): ByteArray

    /**
     * Evolve chain key forward using HMAC-SHA256 (one-way function)
     * Provides forward secrecy - old chain keys cannot be recovered from new ones
     * @param chainKey Current 32-byte chain key (will be zeroized in Rust)
     * @return Next chain key (32 bytes)
     */
    external fun evolveChainKey(chainKey: ByteArray): ByteArray

    /**
     * Derive ephemeral message key from chain key
     * @param chainKey Current 32-byte chain key
     * @return 32-byte message key for encrypting/decrypting this message
     */
    external fun deriveMessageKey(chainKey: ByteArray): ByteArray

    /**
     * Derive receive chain key for a specific sender sequence (out-of-order decryption)
     * Two-stage derivation: direction key + evolution to sender's sequence
     * Allows decrypting messages from any past sequence (fixes "Cache miss" errors)
     * @param rootKey 32-byte root key (same for both parties)
     * @param senderSequence The sequence number the sender used to encrypt
     * @param ourOnion Our .onion address (for direction mapping)
     * @param theirOnion Their .onion address (for direction mapping)
     * @return 32-byte chain key at sender's sequence (for decrypting their message), or null on error
     */
    external fun deriveReceiveKeyAtSequence(
        rootKey: ByteArray,
        senderSequence: Long,
        ourOnion: String,
        theirOnion: String
    ): ByteArray?

    // ==================== PROTOCOL SECURITY FIXES (FIX #6, #7, #9) ====================

    /**
     * FIX #6: Deferred encryption result for two-phase ratchet commit
     * Contains both ciphertext and uncommitted next ratchet state
     */
    data class DeferredEncryptionResult(
        val ciphertext: ByteArray,
        val nextChainKey: ByteArray,
        val nextSequence: Long
    )

    /**
     * FIX #6: Committed ratchet state after PING_ACK
     * Contains the new chain key and sequence to commit
     */
    data class CommittedRatchet(
        val nextChainKey: ByteArray,
        val nextSequence: Long
    )

    /**
     * FIX #6 Phase 1: Encrypt message with deferred ratchet commitment
     * Encrypts the message but does NOT modify the chain key yet
     * Returns both ciphertext and the UNCOMMITTED next ratchet state
     *
     * CRITICAL: This prevents crypto desync when message sends fail
     *
     * @param plaintext Message to encrypt
     * @param chainKey Current chain key (NOT modified)
     * @param sequence Current sequence number
     * @return JSON string: {"ciphertext":"base64","nextChainKey":"base64","nextSequence":123}
     */
    external fun encryptMessageDeferred(
        plaintext: String,
        chainKey: ByteArray,
        sequence: Long
    ): String

    /**
     * FIX #6: Store pending ratchet advancement
     * After encrypting with deferred mode, store the uncommitted ratchet state
     * Will be committed when PING_ACK arrives, or rolled back on failure
     *
     * @param contactId Contact identifier
     * @param messageId Message identifier
     * @param nextChainKey The next chain key from encryptMessageDeferred
     * @param nextSequence The next sequence from encryptMessageDeferred
     * @return True if stored successfully
     */
    external fun storePendingRatchetAdvancement(
        contactId: String,
        messageId: String,
        nextChainKey: ByteArray,
        nextSequence: Long
    ): Boolean

    /**
     * FIX #6 Phase 2: Commit ratchet advancement after PING_ACK received
     * Call this when PING_ACK arrives to finalize the ratchet advancement
     * Returns the stored next ratchet state so caller can update their chain key
     *
     * @param contactId Contact identifier
     * @return JSON string: {"nextChainKey":"base64","nextSequence":123}, or null if not found
     */
    external fun commitRatchetAdvancement(contactId: String): String?

    /**
     * FIX #6: Rollback pending ratchet advancement
     * Call this when message send fails (no PING_ACK received within timeout)
     * This discards the uncommitted ratchet state, keeping the old chain key
     *
     * @param contactId Contact identifier
     * @return True if rollback succeeded
     */
    external fun rollbackRatchetAdvancement(contactId: String): Boolean

    /**
     * FIX #9: Check if PING is a replay attack
     * Uses Blake3 hash of PING wire bytes + sender pubkey for deduplication
     * LRU cache of 10,000 entries prevents memory exhaustion
     *
     * @param senderPubkey Sender's Ed25519 public key (32 bytes)
     * @param pingBytes Full PING wire bytes (will be hashed)
     * @return True if PING is NEW (should process), False if REPLAY (should drop)
     */
    external fun checkPingReplay(
        senderPubkey: ByteArray,
        pingBytes: ByteArray
    ): Boolean

    /**
     * FIX #7: Validate ACK ordering
     * Enforces state machine: PING_ACK → PONG_ACK → MESSAGE_ACK
     * Rejects out-of-order ACKs to prevent protocol violations
     *
     * @param contactId Contact identifier
     * @param ackType ACK type: 0=PING_ACK, 1=PONG_ACK, 2=MESSAGE_ACK
     * @return True if ACK is valid and accepted, False if rejected
     */
    external fun validateAckOrdering(
        contactId: String,
        ackType: Int
    ): Boolean

    /**
     * FIX #7: Reset ACK state for a contact
     * Call this after completing a message exchange to reset the state machine
     *
     * @param contactId Contact identifier
     */
    external fun resetAckState(contactId: String)

    /**
     * Kotlin wrapper for encryptMessageDeferred with JSON parsing
     * Parses the JSON result into a DeferredEncryptionResult object
     */
    fun encryptMessageDeferredParsed(
        plaintext: String,
        chainKey: ByteArray,
        sequence: Long
    ): DeferredEncryptionResult {
        val jsonStr = encryptMessageDeferred(plaintext, chainKey, sequence)
        val json = org.json.JSONObject(jsonStr)

        val ciphertext = android.util.Base64.decode(
            json.getString("ciphertext"),
            android.util.Base64.NO_WRAP
        )
        val nextChainKey = android.util.Base64.decode(
            json.getString("nextChainKey"),
            android.util.Base64.NO_WRAP
        )
        val nextSequence = json.getLong("nextSequence")

        return DeferredEncryptionResult(ciphertext, nextChainKey, nextSequence)
    }

    /**
     * Kotlin wrapper for commitRatchetAdvancement with JSON parsing
     * Returns null if no pending ratchet found
     */
    fun commitRatchetAdvancementParsed(contactId: String): CommittedRatchet? {
        val jsonStr = commitRatchetAdvancement(contactId) ?: return null
        val json = org.json.JSONObject(jsonStr)

        val nextChainKey = android.util.Base64.decode(
            json.getString("nextChainKey"),
            android.util.Base64.NO_WRAP
        )
        val nextSequence = json.getLong("nextSequence")

        return CommittedRatchet(nextChainKey, nextSequence)
    }

    // ==================== NATIVE JNI FUNCTIONS (PRIVATE) ====================

    /**
     * Native JNI function for encryption with key evolution
     * Returns: [evolved_chain_key:32][ciphertext]
     */
    private external fun encryptMessageWithEvolutionJNI(
        plaintext: String,
        chainKey: ByteArray,
        sequence: Long
    ): ByteArray

    /**
     * Native JNI function for decryption with key evolution
     * Returns: [evolved_chain_key:32][plaintext_utf8], or null if decryption fails
     */
    private external fun decryptMessageWithEvolutionJNI(
        encryptedData: ByteArray,
        chainKey: ByteArray,
        expectedSequence: Long
    ): ByteArray?

    // ==================== PUBLIC WRAPPER FUNCTIONS ====================

    /**
     * Encrypt message with atomic key evolution
     * ATOMIC OPERATION like Signal's Double Ratchet
     *
     * Returns both encrypted message AND evolved key in one indivisible operation.
     * This prevents encryption/key-state desync bugs.
     *
     * @param plaintext Message to encrypt
     * @param chainKey Current chain key
     * @param sequence Message sequence number
     * @return EncryptionResult containing both ciphertext and evolved chain key
     */
    fun encryptMessageWithEvolution(
        plaintext: String,
        chainKey: ByteArray,
        sequence: Long
    ): EncryptionResult {
        // Call JNI function that returns [evolved_key:32][ciphertext]
        val result = encryptMessageWithEvolutionJNI(plaintext, chainKey, sequence)

        // Split result: first 32 bytes = evolved key, rest = ciphertext
        val evolvedKey = result.copyOfRange(0, 32)
        val ciphertext = result.copyOfRange(32, result.size)

        return EncryptionResult(ciphertext, evolvedKey)
    }

    /**
     * Decrypt message with atomic key evolution
     * ATOMIC OPERATION like Signal's Double Ratchet
     *
     * Returns both decrypted message AND evolved key in one indivisible operation.
     * This prevents decryption/key-state desync bugs.
     *
     * @param encryptedData Encrypted message with wire format header
     * @param chainKey Current chain key
     * @param expectedSequence Expected sequence number (for replay protection)
     * @return DecryptionResult containing both plaintext and evolved chain key, or null if decryption fails
     */
    fun decryptMessageWithEvolution(
        encryptedData: ByteArray,
        chainKey: ByteArray,
        expectedSequence: Long
    ): DecryptionResult? {
        // Call JNI function that returns [evolved_key:32][plaintext_utf8]
        val result = decryptMessageWithEvolutionJNI(encryptedData, chainKey, expectedSequence)
            ?: return null

        // Split result: first 32 bytes = evolved key, rest = plaintext
        val evolvedKey = result.copyOfRange(0, 32)
        val plaintextBytes = result.copyOfRange(32, result.size)
        val plaintext = String(plaintextBytes, Charsets.UTF_8)

        return DecryptionResult(plaintext, evolvedKey)
    }

    /**
     * Decrypt message using a pre-derived message key
     * Used for decrypting skipped messages that arrive out-of-order
     *
     * @param ciphertext Encrypted message with wire format header
     * @param messageKey Pre-derived 32-byte message key for this specific sequence
     * @return Decrypted plaintext string, or null if decryption fails
     */
    external fun decryptWithMessageKey(
        ciphertext: ByteArray,
        messageKey: ByteArray
    ): String?

    // ==================== TOR NETWORK & MESSAGING ====================

    /**
     * Send encrypted message via Tor using Ping-Pong wake protocol
     * @param recipientEd25519PublicKey Recipient's Ed25519 public key (32 bytes)
     * @param recipientX25519PublicKey Recipient's X25519 public key (32 bytes)
     * @param recipientOnion Recipient's .onion address
     * @param encryptedMessage Pre-encrypted message bytes
     * @return True if message sent successfully
     */
    external fun sendDirectMessage(
        recipientEd25519PublicKey: ByteArray,
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        encryptedMessage: ByteArray
    ): Boolean

    /**
     * Receive incoming message after Pong is sent
     * @param connectionId Connection ID from Ping-Pong handshake
     * @return Encrypted message bytes, or null if no message
     */
    external fun receiveIncomingMessage(connectionId: Long): ByteArray?

    /**
     * Initialize Tor client and bootstrap connection to Tor network
     * This must be called before any other Tor operations
     * @return Status message
     */
    external fun initializeTor(): String

    /**
     * Initialize VOICE Tor control connection (port 9052)
     * Must be called AFTER voice Tor daemon is started by TorManager
     * Voice Tor runs with Single Onion Service configuration for reduced latency
     * @return Status message
     */
    external fun initializeVoiceTorControl(): String

    /**
     * Create a hidden service and get the .onion address
     * @param servicePort The virtual port on the .onion address (default 9150)
     * @param localPort The local port to forward connections to (default 9150)
     * @return The .onion address for receiving connections
     */
    external fun createHiddenService(servicePort: Int = 9150, localPort: Int = 9150): String

    /**
     * Clear all ephemeral hidden services from Tor control port
     * This removes orphaned services from previous failed account creation attempts
     * @return The number of services deleted, or -1 on error
     */
    external fun clearAllEphemeralServices(): Int

    /**
     * Get the current hidden service .onion address (if created)
     * @return The .onion address or null if not created yet
     */
    external fun getHiddenServiceAddress(): String?

    // ==================== NEW v2.0: Friend Request System ====================

    /**
     * Create a second hidden service specifically for friend requests (v2.0)
     * The existing createHiddenService() is for messaging
     * @param servicePort The virtual port on the .onion address (default 9151)
     * @param localPort The local port to forward connections to (default 8081)
     * @param directory Subdirectory name (default "friend_requests")
     * @return The friend request .onion address
     */
    external fun createFriendRequestHiddenService(
        servicePort: Int = 9151,
        localPort: Int = 8081,
        directory: String = "friend_requests"
    ): String

    /**
     * Start contact exchange endpoint for friend request handling (v2.0)
     * Listens on localPort and serves:
     * - GET /contact-card
     * - POST /friend-request
     * - POST /friend-response
     * @param port The local port to listen on (default 8081)
     * @return True if endpoint started successfully
     */
    external fun startFriendRequestServer(port: Int = 8081): Boolean

    /**
     * Stop contact exchange endpoint (v2.0)
     */
    external fun stopFriendRequestServer()

    /**
     * Serve encrypted contact card at GET /contact-card (v2.0)
     * @param encryptedCard The encrypted contact card bytes
     * @param cardLength The length of the encrypted card (for JNI)
     * @param cid The IPFS CID for this card
     */
    external fun serveContactCard(encryptedCard: ByteArray, cardLength: Int, cid: String)

    /**
     * Serve contact list on contact exchange endpoint (v5 architecture)
     * @param cid The IPFS CID for this contact list
     * @param encryptedList The encrypted contact list data
     * @param listLength Length of the encrypted data
     */
    external fun serveContactList(cid: String, encryptedList: ByteArray, listLength: Int)

    /**
     * Create voice hidden service for voice calling (v2.0)
     * Uses seed-derived voice service Ed25519 key from KeyManager
     * Returns the .onion address (port 9152)
     * @return The voice .onion address for receiving voice calls
     */
    external fun createVoiceHiddenService(): String

    /**
     * Make HTTP GET request via Tor SOCKS5 proxy (v2.0)
     * @param url The URL to fetch
     * @return Response body or null on error
     */
    external fun httpGetViaTor(url: String): String?

    /**
     * Make HTTP POST request via Tor SOCKS5 proxy (v2.0)
     * @param url The URL to post to
     * @param body The POST body (JSON string)
     * @return Response body or null on error
     */
    external fun httpPostViaTor(url: String, body: String): String?

    // ==================== END v2.0: Friend Request System ====================

    /**
     * Start the hidden service listener on the specified port
     * This enables receiving incoming Ping tokens
     * @param port The local port to listen on (default 8080, NOT 9150 which is SOCKS!)
     * @return True if listener started successfully
     */
    external fun startHiddenServiceListener(port: Int = 8080): Boolean

    /**
     * Start the tap listener on the specified port
     * This enables receiving incoming tap notifications
     * @param port The local port to listen on (default 9151)
     * @return True if listener started successfully
     */
    external fun startTapListener(port: Int = 9151): Boolean

    /**
     * Start the friend request listener (separate from TAP to avoid interference)
     * Initializes dedicated channel for 0x07/0x08 wire protocol messages
     * @return True if listener started successfully
     */
    external fun startFriendRequestListener(): Boolean

    /**
     * Start the pong listener on the specified port
     * This enables receiving incoming pong responses
     * @param port The local port to listen on (default 9152)
     * @return True if listener started successfully
     */
    external fun startPongListener(port: Int = 9152): Boolean

    /**
     * Stop the hidden service listener
     */
    external fun stopHiddenServiceListener()

    /**
     * Start SOCKS5 proxy on 127.0.0.1:9050
     * Routes all HTTP traffic (wallet RPC, IPFS) through Tor for privacy
     * @return True if proxy started successfully
     */
    external fun startSocksProxy(): Boolean

    /**
     * Stop SOCKS5 proxy
     */
    external fun stopSocksProxy()

    /**
     * Check if SOCKS5 proxy is currently running
     * @return True if proxy is active
     */
    external fun isSocksProxyRunning(): Boolean

    /**
     * Test SOCKS5 proxy connectivity
     * Attempts a test connection through the SOCKS proxy
     * @return True if SOCKS proxy is functional
     */
    external fun testSocksConnectivity(): Boolean

    /**
     * Start the Tor bootstrap event listener
     * This should be called early, before Tor initialization
     */
    external fun startBootstrapListener()

    /**
     * Get Tor bootstrap status (0-100%)
     * @return Bootstrap percentage (0-100), or -1 on error
     */
    external fun getBootstrapStatus(): Int

    /**
     * Stop all listeners (hidden service listener, tap listener, ping listener)
     */
    external fun stopListeners()

    /**
     * Poll for an incoming Ping token (non-blocking)
     * @return Encoded data: [connection_id (8 bytes)][encrypted_ping_bytes] or null if no ping available
     */
    external fun pollIncomingPing(): ByteArray?

    /**
     * Poll for incoming MESSAGE (TEXT/VOICE/IMAGE/PAYMENT) from listener
     * Returns encoded data: [connection_id (8 bytes)][encrypted message blob]
     * @return Encoded data or null if no message available
     */
    external fun pollIncomingMessage(): ByteArray?

    /**
     * Poll for incoming VOICE call signaling (CALL_SIGNALING) from listener
     * Returns encoded data: [connection_id (8 bytes)][encrypted call signaling blob]
     * Completely separate from MESSAGE channel to allow simultaneous text messaging during voice calls
     * @return Encoded data or null if no message available
     */
    external fun pollVoiceMessage(): ByteArray?

    // ========== Opus Audio Codec (Voice Calling) ==========

    /**
     * Create Opus encoder for voice calling
     * @param bitrate Bitrate in bits per second (e.g., 24000 for 24kbps)
     * @return Encoder handle or -1 on error
     */
    external fun opusEncoderCreate(bitrate: Int): Long

    /**
     * Destroy Opus encoder
     * @param handle Encoder handle from opusEncoderCreate
     */
    external fun opusEncoderDestroy(handle: Long)

    /**
     * Encode PCM audio to Opus
     * @param handle Encoder handle
     * @param pcmData 16-bit PCM audio samples (little-endian)
     * @return Opus-encoded bytes or null on error
     */
    external fun opusEncode(handle: Long, pcmData: ByteArray): ByteArray?

    /**
     * Create Opus decoder for voice calling
     * @return Decoder handle or -1 on error
     */
    external fun opusDecoderCreate(): Long

    /**
     * Destroy Opus decoder
     * @param handle Decoder handle from opusDecoderCreate
     */
    external fun opusDecoderDestroy(handle: Long)

    /**
     * Decode Opus to PCM audio
     * @param handle Decoder handle
     * @param opusData Opus-encoded bytes
     * @return 16-bit PCM audio samples (little-endian) or null on error
     */
    external fun opusDecode(handle: Long, opusData: ByteArray): ByteArray?

    /**
     * Decode Opus with FEC to recover missing frame
     * Uses in-band Forward Error Correction data from packet N+1 to recover frame N
     * @param handle Decoder handle
     * @param opusData Opus-encoded bytes of packet N+1 (contains FEC data for frame N)
     * @return 16-bit PCM audio samples for the PREVIOUS frame (N) or null if FEC failed
     */
    external fun opusDecodeFEC(handle: Long, opusData: ByteArray): ByteArray?

    /**
     * Get Opus library version string
     * Returns version like "libopus 1.4" or "libopus 1.6"
     * @return Opus version string
     */
    external fun getOpusVersion(): String

    // ========== Voice Streaming (v2.0) ==========

    /**
     * Callback interface for receiving voice packets from Rust
     */
    interface VoicePacketCallback {
        /**
         * Called when a voice packet is received from the network
         * @param callId The call ID for this packet
         * @param sequence Packet sequence number
         * @param timestamp Packet timestamp in milliseconds
         * @param circuitIndex Which circuit this packet came from (v2)
         * @param ptype Packet type: 0x01=AUDIO, 0x02=CONTROL (v2)
         * @param audioData Opus-encoded audio data
         */
        fun onVoicePacket(callId: String, sequence: Int, timestamp: Long, circuitIndex: Byte, ptype: Byte, audioData: ByteArray)
    }

    /**
     * Callback interface for incoming signaling messages over voice onion (v2.0)
     * Handles CALL_OFFER, CALL_ANSWER, etc received via HTTP POST
     */
    interface VoiceSignalingCallback {
        /**
         * Called when a signaling message is received
         * @param senderPubkey Sender's X25519 public key (32 bytes)
         * @param wireMessage Full wire message including type byte
         */
        fun onSignalingMessage(senderPubkey: ByteArray, wireMessage: ByteArray)
    }

    /**
     * Set callback handler for incoming voice packets (v2.0)
     * Must be called before starting voice streaming listener
     * @param callback The callback that will receive packets
     */
    external fun setVoicePacketCallback(callback: VoicePacketCallback)

    /**
     * Set callback handler for incoming signaling messages (v2.0)
     * Handles CALL_OFFER, CALL_ANSWER, etc received via HTTP POST to voice onion
     * Must be called before starting voice streaming listener
     * @param callback The callback that will receive signaling messages
     */
    external fun setVoiceSignalingCallback(callback: VoiceSignalingCallback)

    /**
     * Start voice streaming listener on port 9152 (v2.0)
     * Must be called before accepting or creating voice sessions
     * Runs in background and accepts incoming voice connections
     */
    external fun startVoiceStreamingServer()

    /**
     * Create outgoing voice session to peer's voice .onion with multiple circuits (v2.0)
     * Connects to peer's voice hidden service on port 9152
     * @param callId Unique call ID (UUID string)
     * @param peerVoiceOnion Peer's voice .onion address
     * @param numCircuits Number of parallel Tor circuits to create (typically 3)
     * @return True if session created successfully
     */
    external fun createVoiceSession(callId: String, peerVoiceOnion: String, numCircuits: Int): Boolean

    /**
     * Send audio packet to peer in active voice session on specific circuit (v2.0)
     * Audio data should be Opus-encoded
     * @param callId Call ID for this session
     * @param sequence Packet sequence number
     * @param timestamp Timestamp in milliseconds since call start
     * @param audioData Opus-encoded audio bytes
     * @param circuitIndex Which circuit to use (0 to numCircuits-1)
     * @param ptype Packet type: 0x01=AUDIO, 0x02=CONTROL
     * @return True if packet sent successfully
     */
    external fun sendAudioPacket(
        callId: String,
        sequence: Int,
        timestamp: Long,
        audioData: ByteArray,
        circuitIndex: Int,
        ptype: Int
    ): Boolean

    /**
     * End voice session and close connection (v2.0)
     * @param callId Call ID to end
     */
    external fun endVoiceSession(callId: String)

    /**
     * Get number of active voice sessions (v2.0)
     * @return Count of active voice streaming sessions
     */
    external fun getActiveVoiceSessions(): Int

    /**
     * Rebuild a specific voice circuit (close and reconnect with fresh Tor path)
     * When a circuit has persistent packet loss, this closes it and creates a new one
     * with incremented rebuild_epoch, forcing Tor to select a different relay path
     * @param callId Active call session ID
     * @param circuitIndex Circuit to rebuild (0-2)
     * @param rebuildEpoch Incremented counter (forces fresh SOCKS5 isolation)
     * @return True if rebuild succeeded, false if failed
     */
    external fun rebuildVoiceCircuit(
        callId: String,
        circuitIndex: Int,
        rebuildEpoch: Int
    ): Boolean

    /**
     * Check if a connection is still alive and responsive
     * @param connectionId The connection ID to check
     * @return True if connection is alive and can send/receive data
     */
    external fun isConnectionAlive(connectionId: Long): Boolean

    /**
     * Send encrypted Pong response back to a pending connection and receive the message
     * @param connectionId The connection ID extracted from pollIncomingPing
     * @param encryptedPongBytes The encrypted Pong token bytes (from respondToPing)
     * @return The encrypted message bytes sent by the sender, or null on error/timeout
     */
    external fun sendPongBytes(connectionId: Long, encryptedPongBytes: ByteArray): ByteArray?

    /**
     * Send encrypted Pong over a NEW connection to sender's .onion address
     * Used when original connection has closed (e.g., downloading message hours later)
     * @param senderOnionAddress The sender's .onion address
     * @param encryptedPongBytes The encrypted Pong token bytes (from respondToPing)
     * @return True if Pong sent successfully
     */
    external fun sendPongToNewConnection(senderOnionAddress: String, encryptedPongBytes: ByteArray): Boolean

    /**
     * Send encrypted Pong to sender's Pong listener (port 9152)
     * Used for delayed downloads - sends pong to sender's listening port
     * @param senderOnionAddress The sender's .onion address
     * @param encryptedPongBytes The encrypted Pong token bytes (from respondToPing)
     * @return True if Pong sent successfully to listener
     */
    external fun sendPongToListener(senderOnionAddress: String, encryptedPongBytes: ByteArray): Boolean

    /**
     * Decrypt an incoming encrypted Ping token and store it
     * Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Ping Token]
     * @param encryptedPingWire The encrypted wire message from pollIncomingPing
     * @return Ping ID (String) to pass to respondToPing, or null on failure
     */
    external fun decryptIncomingPing(encryptedPingWire: ByteArray): String?

    /**
     * Get the sender's Ed25519 public key from a stored Ping
     * @param pingId The Ping ID from decryptIncomingPing
     * @return Sender's Ed25519 public key (32 bytes), or null if not found
     */
    external fun getPingSenderPublicKey(pingId: String): ByteArray?

    /**
     * Decrypt an incoming encrypted Pong token and store it
     * Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Pong Token]
     * @param encryptedPongWire The encrypted wire message
     * @return Ping ID (String) that the Pong is responding to, or null on failure
     */
    external fun decryptIncomingPong(encryptedPongWire: ByteArray): String?

    // ==================== PING-PONG PROTOCOL ====================

    /**
     * Send an encrypted Ping token to a recipient
     * @param recipientEd25519PublicKey The recipient's Ed25519 public key (for signature verification)
     * @param recipientX25519PublicKey The recipient's X25519 public key (for encryption)
     * @param recipientOnion The recipient's .onion address
     * @param encryptedMessage The encrypted message to send after Pong
     * @param messageTypeByte The message type (0x03 = TEXT, 0x04 = VOICE)
     * @param pingId The ping ID (hex-encoded 24-byte nonce) - generated once in Kotlin, never changes
     * @param pingTimestamp The timestamp when ping was created (epoch millis) - also from Kotlin
     * @return JSON string: {"pingId":"...","wireBytes":"..."} for tracking and retry
     */
    external fun sendPing(recipientEd25519PublicKey: ByteArray, recipientX25519PublicKey: ByteArray, recipientOnion: String, encryptedMessage: ByteArray, messageTypeByte: Byte, pingId: String, pingTimestamp: Long): String

    /**
     * Resend a Ping using stored wire bytes (for retry without regenerating nonce)
     * This prevents ghost pings by ensuring retries use the SAME Ping ID
     * @param wireBytesBase64 Base64-encoded encrypted Ping wire bytes from sendPing response
     * @param recipientOnion The recipient's .onion address
     * @return True if sent successfully
     */
    external fun resendPingWithWireBytes(wireBytesBase64: String, recipientOnion: String): Boolean

    /**
     * Wait for a Pong response
     * @param pingId The Ping ID returned from sendPing
     * @param timeoutSeconds Timeout in seconds
     * @return True if Pong received and authenticated
     */
    external fun waitForPong(pingId: String, timeoutSeconds: Int): Boolean

    /**
     * Check if a Pong has been received (non-blocking)
     * @param pingId The Ping ID to check
     * @return True if Pong has been received and is waiting
     */
    external fun pollForPong(pingId: String): Boolean

    /**
     * Remove Pong session after message blob is sent
     * Call this immediately after successfully sending message to prevent memory leak
     * @param pingId The Ping ID associated with the Pong
     */
    external fun removePongSession(pingId: String)

    /**
     * Remove Ping session after Pong is sent
     * Call this immediately after successfully sending Pong to prevent memory leak
     * @param pingId The Ping ID
     */
    external fun removePingSession(pingId: String)

    /**
     * Remove ACK session after processing
     * Call this immediately after processing ACK to prevent memory leak
     * @param itemId The Ping ID or Message ID that was acknowledged
     */
    external fun removeAckSession(itemId: String)

    /**
     * Clean up expired Ping/Pong/ACK sessions (older than 5 minutes)
     * Call this periodically as a safety net for orphaned entries from crashes
     */
    external fun cleanupExpiredSessions()

    /**
     * Send encrypted message blob after Pong is received
     * Used for persistent messaging - after Pong arrives, send the actual message
     * @param recipientOnion The recipient's .onion address
     * @param encryptedMessage The encrypted message bytes
     * @param messageTypeByte The message type (0x03 = TEXT, 0x04 = VOICE)
     * @return True if message sent successfully
     */
    external fun sendMessageBlob(recipientOnion: String, encryptedMessage: ByteArray, messageTypeByte: Byte): Boolean

    /**
     * Send call signaling message via HTTP POST to voice .onion
     * This bypasses the VOICE channel routing and sends directly to the voice streaming listener
     * @param voiceOnion Recipient's voice .onion address
     * @param senderX25519Pubkey Our X25519 public key (32 bytes) - included in wire format
     * @param encryptedMessage The encrypted call signaling message
     * @return True if HTTP POST successful (200 OK received)
     */
    external fun sendHttpToVoiceOnion(voiceOnion: String, senderX25519Pubkey: ByteArray, encryptedMessage: ByteArray): Boolean

    /**
     * Respond to an incoming Ping with a Pong
     * @param pingId The Ping ID from decryptIncomingPing
     * @param authenticated Whether user successfully authenticated
     * @return Encrypted Pong wire message to send via sendPongBytes, or null if denied
     */
    external fun respondToPing(pingId: String, authenticated: Boolean): ByteArray?

    /**
     * Send a "tap" (presence notification) to a contact
     * Tap tells the contact "I'm online now, retry any pending operations"
     * @param recipientEd25519PublicKey Recipient's Ed25519 public key (32 bytes)
     * @param recipientX25519PublicKey Recipient's X25519 public key (32 bytes)
     * @param recipientOnion Recipient's .onion address
     * @return True if tap sent successfully
     */
    external fun sendTap(
        recipientEd25519PublicKey: ByteArray,
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String
    ): Boolean

    /**
     * Send a friend request notification to a contact (fire-and-forget)
     * Friend requests contain minimal info (username + IPFS CID) for privacy
     * Recipient must enter PIN to download full contact card from IPFS
     * @param recipientOnion Recipient's .onion address
     * @param encryptedFriendRequest Pre-encrypted friend request data (with wire type byte 0x07)
     * @return True if friend request sent successfully
     */
    external fun sendFriendRequest(
        recipientOnion: String,
        encryptedFriendRequest: ByteArray
    ): Boolean

    /**
     * Send friend request accepted notification via Tor
     * Notifies the original requester that you've accepted their friend request
     * @param recipientOnion Recipient's .onion address
     * @param encryptedAcceptance Pre-encrypted acceptance notification (with wire type byte 0x08)
     * @return True if notification sent successfully
     */
    external fun sendFriendRequestAccepted(
        recipientOnion: String,
        encryptedAcceptance: ByteArray
    ): Boolean

    /**
     * Poll for an incoming tap (non-blocking)
     * Wire format from sender: [Sender X25519 Public Key - 32 bytes][Encrypted Tap]
     * @return Tap wire message bytes, or null if no tap available
     */
    external fun pollIncomingTap(): ByteArray?

    /**
     * Poll for an incoming friend request (non-blocking)
     * Wire protocol messages (0x07 FRIEND_REQUEST or 0x08 FRIEND_REQUEST_ACCEPTED)
     * Returns raw encrypted bytes - Kotlin will decrypt based on message type
     * @return Raw encrypted friend request bytes, or null if no request available
     */
    external fun pollFriendRequest(): ByteArray?

    /**
     * Decrypt an incoming tap and get sender's Ed25519 public key
     * @param tapWire The tap wire message from pollIncomingTap
     * @return Sender's Ed25519 public key (32 bytes), or null if decryption fails
     */
    external fun decryptIncomingTap(tapWire: ByteArray): ByteArray?

    /**
     * Poll for an incoming pong (non-blocking)
     * Wire format from recipient: [Recipient X25519 Public Key - 32 bytes][Encrypted Pong]
     * @return Pong wire message bytes, or null if no pong available
     */
    external fun pollIncomingPong(): ByteArray?

    /**
     * Decrypt incoming pong from listener and store in GLOBAL_PONG_SESSIONS
     * Wire format: [Recipient X25519 Public Key - 32 bytes][Encrypted Pong]
     * @param pongWire The encrypted pong wire message from pollIncomingPong
     * @return True if decryption and storage succeeded
     */
    external fun decryptAndStorePongFromListener(pongWire: ByteArray): Boolean

    /**
     * Decrypt incoming pong from listener and return ping_id for PONG_ACK sending
     * Wire format: [Recipient X25519 Public Key - 32 bytes][Encrypted Pong]
     * @param pongWire The encrypted pong wire message from pollIncomingPong
     * @return ping_id as String, or null on failure
     */
    external fun decryptPongAndGetPingId(pongWire: ByteArray): String?

    // ==================== DELIVERY ACK (CONFIRMATION) ====================

    /**
     * Send a delivery ACK (confirmation) to recipient
     * @param itemId The ping_id, message_id, tap_nonce, or pong_nonce being acknowledged
     * @param ackType "PING_ACK", "MESSAGE_ACK", "TAP_ACK", or "PONG_ACK"
     * @param recipientEd25519Pubkey Recipient's Ed25519 signing public key (32 bytes)
     * @param recipientX25519Pubkey Recipient's X25519 encryption public key (32 bytes)
     * @param recipientOnion Recipient's .onion address
     * @return True if ACK was sent successfully
     */
    external fun sendDeliveryAck(
        itemId: String,
        ackType: String,
        recipientEd25519Pubkey: ByteArray,
        recipientX25519Pubkey: ByteArray,
        recipientOnion: String
    ): Boolean

    /**
     * Send ACK on an existing connection (instant reply)
     * Avoids SOCKS5 connection failures when sender's hidden service isn't reachable yet
     * @param connectionId The connection ID to send ACK on
     * @param itemId The item ID (ping ID or message ID)
     * @param ackType The ACK type (PING_ACK, MESSAGE_ACK, etc.)
     * @param recipientX25519Pubkey Recipient's X25519 encryption public key (32 bytes)
     * @return True if ACK was sent successfully on the connection
     */
    external fun sendAckOnConnection(
        connectionId: Long,
        itemId: String,
        ackType: String,
        recipientX25519Pubkey: ByteArray
    ): Boolean

    /**
     * Start ACK listener on port 9153
     * @param port Port number
     * @return True if listener started successfully
     */
    external fun startAckListener(port: Int): Boolean

    /**
     * Poll for an incoming ACK (non-blocking)
     * Wire format from sender: [Sender X25519 Public Key - 32 bytes][Encrypted ACK]
     * @return ACK wire message bytes, or null if no ACK available
     */
    external fun pollIncomingAck(): ByteArray?

    /**
     * Decrypt incoming ACK from listener and store in GLOBAL_ACK_SESSIONS
     * Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted ACK]
     * @param ackWire The encrypted ACK wire message from pollIncomingAck
     * @return JSON string with item_id and ack_type: {"item_id":"...","ack_type":"PING_ACK|MESSAGE_ACK|TAP_ACK|PONG_ACK"}, or null if failed
     */
    external fun decryptAndStoreAckFromListener(ackWire: ByteArray): String?

    // ==================== NLx402 PAYMENT PROTOCOL ====================

    /**
     * Create a payment quote for NLx402 protocol
     * @param recipient Recipient wallet address (Solana/Zcash)
     * @param amount Amount in smallest unit (lamports/zatoshis)
     * @param token Token type (SOL, ZEC, USDC, etc.)
     * @param description Optional human-readable description (empty string for none)
     * @param senderHandle Optional sender's handle (empty string for none)
     * @param recipientHandle Optional recipient's handle (empty string for none)
     * @param expirySecs Quote expiration time in seconds (e.g., 86400 for 24 hours)
     * @return JSON string containing the quote
     */
    external fun createPaymentQuote(
        recipient: String,
        amount: Long,
        token: String,
        description: String,
        senderHandle: String,
        recipientHandle: String,
        expirySecs: Long
    ): String

    /**
     * Get the memo string for a payment quote (for embedding in transaction)
     * @param quoteJson The quote JSON from createPaymentQuote
     * @return Memo string to embed in transaction (format: "NLx402:hash")
     */
    external fun getQuoteMemo(quoteJson: String): String

    /**
     * Verify a payment against a quote
     * Checks memo hash, amount, recipient, and token match
     * NOTE: Replay protection (tx signature checking) should be done in Kotlin with local DB
     * @param quoteJson The quote JSON to verify against
     * @param txMemo Transaction memo containing the quote hash
     * @param txAmount Amount sent in the transaction (in smallest unit)
     * @param txRecipient Recipient address in the transaction
     * @param txToken Token type in the transaction
     * @return True if payment is valid
     */
    external fun verifyPayment(
        quoteJson: String,
        txMemo: String,
        txAmount: Long,
        txRecipient: String,
        txToken: String
    ): Boolean

    /**
     * Check if a quote has expired
     * @param quoteJson The quote JSON to check
     * @return True if the quote has expired
     */
    external fun isQuoteExpired(quoteJson: String): Boolean

    /**
     * Extract quote hash from a transaction memo
     * @param memo Transaction memo string
     * @return The quote hash hex string, or empty string if memo is not valid NLx402 format
     */
    external fun extractQuoteHashFromMemo(memo: String): String

    /**
     * Get the NLx402 protocol version
     * @return Version string (e.g., "1.0.0")
     */
    external fun getNLx402Version(): String

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
