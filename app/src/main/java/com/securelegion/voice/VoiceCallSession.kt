package com.securelegion.voice

import android.content.Context
import android.util.Log
import com.securelegion.crypto.RustBridge
import com.securelegion.voice.crypto.VoiceCallCrypto
import kotlinx.coroutines.*
import java.util.UUID

/**
 * VoiceCallSession manages a single voice call with one contact
 *
 * Responsibilities:
 * - Ephemeral key exchange
 * - Key derivation (master + per-circuit keys)
 * - Audio capture and encoding
 * - Audio decryption and playback
 * - Sending/receiving encrypted voice frames
 * - Call lifecycle management
 *
 * Phase 1 (Current): Single-circuit voice call
 * Phase 2 (Future): MCP-TV multi-circuit parallelization
 */
class VoiceCallSession(
    private val context: Context,
    private val contactOnion: String,
    private val contactVoiceOnion: String,
    private val contactEd25519PublicKey: ByteArray,
    private val isOutgoing: Boolean,
    private val callId: String = UUID.randomUUID().toString(), // Generate new ID for outgoing, pass from CALL_OFFER for incoming
    private val contactX25519PublicKey: ByteArray? = null // For sending CALL_END notifications
) : RustBridge.VoicePacketCallback {
    companion object {
        private const val TAG = "VoiceCallSession"

        // Voice call ports (use same messaging port for now, will add dedicated voice ports later)
        private const val VOICE_PORT = 9150

        // Call states
        enum class CallState {
            IDLE,           // Not yet started
            CONNECTING,     // Establishing Tor circuit and key exchange
            RINGING,        // Waiting for answer (outgoing) or alerting user (incoming)
            ACTIVE,         // Call in progress
            ENDING,         // Gracefully terminating
            ENDED           // Call finished
        }
    }

    // Call state
    @Volatile
    private var callState = CallState.IDLE

    // Call ID getter (needed for logging and signaling)
    fun getCallId(): String = callId

    init {
        Log.d(TAG, "VoiceCallSession created with callId=$callId (length=${callId.length})")
    }

    // Call ID as bytes for local crypto operations
    private val callIdBytes = callId.replace("-", "").take(16).toByteArray()

    // Crypto components
    private val crypto = VoiceCallCrypto()
    private var masterKey: ByteArray? = null
    private var circuitKeys = mutableMapOf<Int, ByteArray>()

    // Audio components
    private val opusCodec = OpusCodec()
    private lateinit var audioCaptureManager: AudioCaptureManager
    private lateinit var audioPlaybackManager: AudioPlaybackManager

    // Network components (Rust handles transport, Kotlin handles encryption)
    private val numCircuits = 3 // Multi-circuit for resilience against TCP head-of-line blocking

    // Sequence tracking
    private var sendSeqNum: Long = 0
    private var direction: Byte = if (isOutgoing) 0 else 1

    // Coroutine scope for call session
    private val callScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Callbacks
    var onCallStateChanged: ((CallState) -> Unit)? = null
    var onCallEnded: ((reason: String) -> Unit)? = null

    /**
     * Start outgoing call
     * @param theirEphemeralPublicKey Their ephemeral public key from CALL_ANSWER
     * @param ourEphemeralSecretKey Our ephemeral secret key (generated before calling this, matches CALL_OFFER)
     * 1. Exchange keys with recipient (via existing Ping-Pong protocol)
     * 2. Derive encryption keys
     * 3. Establish Tor circuits
     * 4. Start audio capture and transmission
     */
    suspend fun startOutgoingCall(theirEphemeralPublicKey: ByteArray, ourEphemeralSecretKey: ByteArray) {
        try {
            setState(CallState.CONNECTING)

            Log.i(TAG, "Starting outgoing call to $contactOnion")

            // Initialize Opus codec (blocking native calls - run on IO thread)
            withContext(Dispatchers.IO) {
                opusCodec.initEncoder()
                opusCodec.initDecoder()
            }

            Log.d(TAG, "Using provided ephemeral keypair for outgoing call")

            // Compute shared secret using our secret key
            val sharedSecret = crypto.computeSharedSecret(
                ourEphemeralSecretKey,
                theirEphemeralPublicKey
            )

            // Derive master call key
            masterKey = crypto.deriveMasterKey(sharedSecret, callIdBytes)

            // Derive per-circuit keys
            for (i in 0 until numCircuits) {
                circuitKeys[i] = crypto.deriveCircuitKey(masterKey!!, i)
            }

            Log.d(TAG, "Derived encryption keys: master + $numCircuits circuit keys")

            // Create voice session via Rust streaming with multiple circuits
            // IMPORTANT: This is a blocking JNI call that creates multiple Tor circuits (~5 seconds)
            // Must run on IO dispatcher to avoid blocking UI thread
            Log.i(TAG, "Creating Rust voice session to $contactVoiceOnion with $numCircuits circuits...")
            Log.d(TAG, "This will establish $numCircuits Tor circuits - may take 5-15 seconds")
            val sessionCreated = withContext(Dispatchers.IO) {
                RustBridge.createVoiceSession(callId, contactVoiceOnion, numCircuits)
            }
            if (!sessionCreated) {
                Log.e(TAG, "RustBridge.createVoiceSession returned false")
                throw Exception("Failed to create voice session to $contactVoiceOnion")
            }
            Log.i(TAG, "✓ Created Rust voice session with $numCircuits circuits to $contactVoiceOnion")

            // Initialize audio managers (blocking native calls - run on IO thread)
            withContext(Dispatchers.IO) {
                audioCaptureManager = AudioCaptureManager(context, opusCodec)
                audioPlaybackManager = AudioPlaybackManager(context, opusCodec)

                audioCaptureManager.initialize()
                audioPlaybackManager.initialize()
            }

            // Set capture callback
            audioCaptureManager.onFrameEncoded = { opusFrame ->
                sendVoiceFrame(opusFrame)
            }

            // Start audio capture and playback
            audioCaptureManager.startCapture(callScope)
            audioPlaybackManager.startPlayback(callScope)

            // Note: Receiving is now handled via onVoicePacket callback (no startReceiving needed)

            setState(CallState.ACTIVE)

            Log.i(TAG, "Call active")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start outgoing call", e)
            endCall("Connection failed: ${e.message}")
        }
    }

    /**
     * Answer incoming call
     * @param theirEphemeralPublicKey Their ephemeral public key from CALL_OFFER
     * @param ourEphemeralSecretKey Our ephemeral secret key (generated before calling this)
     */
    suspend fun answerIncomingCall(theirEphemeralPublicKey: ByteArray, ourEphemeralSecretKey: ByteArray) {
        try {
            Log.i(TAG, "Answering incoming call from $contactOnion")
            setState(CallState.CONNECTING)

            // Direction = 1 for incoming calls
            direction = 1

            // Initialize Opus codec (blocking native calls - run on IO thread)
            withContext(Dispatchers.IO) {
                opusCodec.initEncoder()
                opusCodec.initDecoder()
            }

            Log.d(TAG, "Using provided ephemeral keypair for answering call")

            // Compute shared secret using our secret key
            val sharedSecret = crypto.computeSharedSecret(
                ourEphemeralSecretKey,
                theirEphemeralPublicKey
            )

            // Derive master call key
            masterKey = crypto.deriveMasterKey(sharedSecret, callIdBytes)

            // Derive per-circuit keys
            for (i in 0 until numCircuits) {
                circuitKeys[i] = crypto.deriveCircuitKey(masterKey!!, i)
            }

            Log.d(TAG, "Derived encryption keys: master + $numCircuits circuit keys")

            // Create voice session via Rust streaming with multiple circuits
            // IMPORTANT: This is a blocking JNI call that creates multiple Tor circuits (~5 seconds)
            // Must run on IO dispatcher to avoid blocking UI thread
            Log.i(TAG, "Creating Rust voice session to $contactVoiceOnion with $numCircuits circuits...")
            Log.d(TAG, "This will establish $numCircuits Tor circuits - may take 5-15 seconds")
            val sessionCreated = withContext(Dispatchers.IO) {
                RustBridge.createVoiceSession(callId, contactVoiceOnion, numCircuits)
            }
            if (!sessionCreated) {
                Log.e(TAG, "RustBridge.createVoiceSession returned false")
                throw Exception("Failed to create voice session to $contactVoiceOnion")
            }
            Log.i(TAG, "✓ Created Rust voice session with $numCircuits circuits to $contactVoiceOnion")

            // Initialize audio managers (blocking native calls - run on IO thread)
            withContext(Dispatchers.IO) {
                audioCaptureManager = AudioCaptureManager(context, opusCodec)
                audioPlaybackManager = AudioPlaybackManager(context, opusCodec)

                audioCaptureManager.initialize()
                audioPlaybackManager.initialize()
            }

            // Set capture callback
            audioCaptureManager.onFrameEncoded = { opusFrame ->
                sendVoiceFrame(opusFrame)
            }

            // Start audio capture and playback
            audioCaptureManager.startCapture(callScope)
            audioPlaybackManager.startPlayback(callScope)

            // Note: Receiving is now handled via onVoicePacket callback (no startReceiving needed)

            setState(CallState.ACTIVE)

            Log.i(TAG, "Incoming call active")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to answer incoming call", e)
            endCall("Connection failed: ${e.message}")
        }
    }

    /**
     * Send voice frame (encrypted)
     * For Phase 1: sends on circuit 0
     * For Phase 2: round-robin across circuits
     */
    private fun sendVoiceFrame(opusFrame: ByteArray) {
        if (callState != CallState.ACTIVE) {
            return
        }

        callScope.launch {
            try {
                // Select circuit using round-robin distribution
                val circuitIndex = (sendSeqNum % numCircuits).toInt()
                val circuitKey = circuitKeys[circuitIndex]

                if (circuitKey == null) {
                    Log.e(TAG, "Circuit $circuitIndex not available")
                    return@launch
                }

                // Get current sequence number and increment
                val currentSeq = sendSeqNum++

                // Create VoiceFrame for AAD encoding
                val frame = VoiceFrame(
                    callId = callIdBytes,
                    sequenceNumber = currentSeq,
                    direction = direction,
                    circuitIndex = circuitIndex,
                    encryptedPayload = ByteArray(0) // Placeholder, will encrypt below
                )

                // Derive nonce
                val nonce = crypto.deriveNonce(callIdBytes, currentSeq)

                // Encode AAD
                val aad = frame.encodeAAD()

                // Encrypt Opus frame
                val encryptedPayload = crypto.encryptFrame(
                    opusFrame,
                    circuitKey,
                    nonce,
                    aad
                )

                // Send encrypted payload via Rust voice streaming
                // Timestamp is currentSeq * 20ms (assuming 20ms Opus frames)
                val timestamp = currentSeq * 20

                val success = RustBridge.sendAudioPacket(
                    callId,
                    currentSeq.toInt(),
                    timestamp,
                    encryptedPayload,
                    circuitIndex
                )

                if (!success) {
                    Log.w(TAG, "Failed to send voice packet seq=$currentSeq")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error sending voice frame", e)
            }
        }
    }


    /**
     * End the call
     * Can be called from any thread - cleanup runs on background thread
     */
    fun endCall(reason: String = "User ended call") {
        if (callState == CallState.ENDED || callState == CallState.ENDING) {
            return
        }

        setState(CallState.ENDING)

        Log.i(TAG, "Ending call: $reason")

        // Send CALL_END notification to the other person
        contactX25519PublicKey?.let { x25519Key ->
            try {
                val sent = CallSignaling.sendCallEnd(
                    recipientX25519PublicKey = x25519Key,
                    recipientOnion = contactOnion,
                    callId = callId,
                    reason = reason
                )
                if (sent) {
                    Log.i(TAG, "✓ Sent CALL_END notification to $contactOnion")
                } else {
                    Log.w(TAG, "✗ Failed to send CALL_END notification")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error sending CALL_END notification", e)
            }
        } ?: Log.w(TAG, "Cannot send CALL_END - no X25519 public key available")

        // Create a new scope for cleanup (independent of callScope which might be hung)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Wrap cleanup in timeout to prevent hanging forever
                withTimeout(5000L) {  // 5 second timeout for cleanup
                    // Stop audio (blocking operations)
                    if (::audioCaptureManager.isInitialized) {
                        audioCaptureManager.stopCapture()
                    }
                    if (::audioPlaybackManager.isInitialized) {
                        audioPlaybackManager.stopPlayback()
                    }

                    // End voice session via Rust (blocking JNI call)
                    try {
                        RustBridge.endVoiceSession(callId)
                    } catch (e: Exception) {
                        Log.w(TAG, "Error ending Rust voice session (might not have been created yet)", e)
                    }

                    // Wipe keys
                    masterKey?.let { crypto.wipeKey(it) }
                    for (key in circuitKeys.values) {
                        crypto.wipeKey(key)
                    }
                    circuitKeys.clear()

                    // Release resources (blocking native calls)
                    if (::audioCaptureManager.isInitialized) {
                        audioCaptureManager.release()
                    }
                    if (::audioPlaybackManager.isInitialized) {
                        audioPlaybackManager.release()
                    }

                    // Only release codec if it was initialized
                    try {
                        opusCodec.release()
                    } catch (e: Exception) {
                        Log.w(TAG, "Error releasing Opus codec (might not have been initialized)", e)
                    }
                }

            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                Log.w(TAG, "Cleanup timed out after 5 seconds - forcing end")
            } catch (e: Exception) {
                Log.e(TAG, "Error during call cleanup", e)
            } finally {
                // Always set state to ENDED and notify
                setState(CallState.ENDED)
                onCallEnded?.invoke(reason)
                Log.i(TAG, "Call ended")

                // Cancel original call scope (will terminate any hung operations)
                try {
                    callScope.cancel()
                } catch (e: Exception) {
                    Log.w(TAG, "Error cancelling call scope", e)
                }
            }
        }
    }

    /**
     * Mute/unmute microphone
     */
    fun setMuted(muted: Boolean) {
        audioCaptureManager.setMuted(muted)
    }

    /**
     * Enable/disable speaker
     */
    fun setSpeakerEnabled(enabled: Boolean) {
        audioPlaybackManager.setSpeakerEnabled(enabled)
    }

    /**
     * Get call quality stats
     */
    fun getCallQualityStats(): AudioPlaybackManager.CallQualityStats {
        return audioPlaybackManager.getStats()
    }

    /**
     * Update call state and notify
     */
    private fun setState(newState: CallState) {
        callState = newState
        onCallStateChanged?.invoke(newState)
    }

    /**
     * Get current call state
     */
    fun getState(): CallState = callState

    /**
     * VoicePacketCallback implementation
     * Receives encrypted voice packets from Rust and decrypts them
     */
    override fun onVoicePacket(callId: String, sequence: Int, timestamp: Long, audioData: ByteArray) {
        // Verify this packet is for our call
        if (callId != this.callId) {
            Log.w(TAG, "Received packet for wrong call: received='$callId' (len=${callId.length}), expected='${this.callId}' (len=${this.callId.length})")
            return
        }

        // Only process packets when call is active
        if (callState != CallState.ACTIVE) {
            return
        }

        callScope.launch {
            try {
                // Derive circuit index from sequence (must match sender's round-robin logic)
                val circuitIndex = (sequence % numCircuits)
                val circuitKey = circuitKeys[circuitIndex]

                if (circuitKey == null) {
                    Log.e(TAG, "No key for circuit $circuitIndex")
                    return@launch
                }

                // Derive nonce from callId and sequence
                val nonce = crypto.deriveNonce(callIdBytes, sequence.toLong())

                // Reconstruct AAD (Additional Authenticated Data)
                // AAD format: callId (16) || sequenceNumber (8) || direction (1) || circuitIndex (1) = 26 bytes
                val aad = java.nio.ByteBuffer.allocate(26)
                aad.put(callIdBytes)                                    // 16 bytes
                aad.putLong(sequence.toLong())                          // 8 bytes
                aad.put(if (direction == 0.toByte()) 1.toByte() else 0.toByte()) // 1 byte - opposite direction
                aad.put(circuitIndex.toByte())                          // 1 byte

                // Decrypt the encrypted Opus frame
                val opusFrame = crypto.decryptFrame(
                    audioData,
                    circuitKey,
                    nonce,
                    aad.array()
                )

                // Add to jitter buffer for playback
                audioPlaybackManager.addFrame(sequence.toLong(), opusFrame)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt voice packet seq=$sequence", e)
            }
        }
    }
}
