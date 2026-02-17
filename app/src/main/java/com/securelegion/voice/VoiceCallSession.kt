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
            IDLE, // Not yet started
            CONNECTING, // Establishing Tor circuit and key exchange
            RINGING, // Waiting for answer (outgoing) or alerting user (incoming)
            ACTIVE, // Call in progress
            ENDING, // Gracefully terminating
            ENDED // Call finished
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
    private val numCircuits = 6 // Phase 1: Increased from 3 to 6 circuits

    // Call quality telemetry (v2)
    private val telemetry = CallQualityTelemetry()

    // Adaptive circuit scheduler (replaces round-robin in v2)
    private val circuitScheduler = CircuitScheduler(numCircuits, telemetry)

    // Pending speaker state (for setting speaker before AudioPlaybackManager is initialized)
    private var pendingSpeakerEnabled: Boolean? = null

    init {
        // Set up circuit rebuild callback
        circuitScheduler.onCircuitRebuildRequested = { circuitIndex, rebuildEpoch ->
            Log.w(TAG, "REBUILD_REQUESTED circuit=$circuitIndex epoch=$rebuildEpoch")
            callScope.launch(Dispatchers.IO) {
                try {
                    val success = RustBridge.rebuildVoiceCircuit(
                        callId = callId,
                        circuitIndex = circuitIndex,
                        rebuildEpoch = rebuildEpoch
                    )

                    if (success) {
                        Log.i(TAG, "Circuit $circuitIndex rebuild SUCCESS (epoch=$rebuildEpoch)")
                        circuitScheduler.onCircuitRebuilt(circuitIndex, rebuildEpoch)
                    } else {
                        Log.e(TAG, "Circuit $circuitIndex rebuild FAILED (epoch=$rebuildEpoch)")
                        circuitScheduler.onCircuitRebuildFailed(circuitIndex)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Exception during circuit rebuild: ${e.message}", e)
                    circuitScheduler.onCircuitRebuildFailed(circuitIndex)
                }
            }
        }
    }

    // Call start time for duration tracking
    private var callStartTime: Long = 0

    // Sequence tracking
    private var sendSeqNum: Long = 0
    private var direction: Byte = if (isOutgoing) 0 else 1

    // Coroutine scope for call session
    private val callScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Periodic stats feedback job
    private var statsFeedbackJob: Job? = null

    // Callbacks
    var onCallStateChanged: ((CallState) -> Unit)? = null
    var onCallEnded: ((reason: String) -> Unit)? = null
    var onTelemetryUpdate: ((CallQualityTelemetry.TelemetrySnapshot) -> Unit)? = null

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
            Log.i(TAG, "Created Rust voice session with $numCircuits circuits to $contactVoiceOnion")

            // Initialize audio managers (blocking native calls - run on IO thread)
            withContext(Dispatchers.IO) {
                audioCaptureManager = AudioCaptureManager(context, opusCodec)
                audioPlaybackManager = AudioPlaybackManager(context, opusCodec)

                // Initialize capture first to get audio session ID
                audioCaptureManager.initialize()

                // Pass audio session ID to playback for AEC to work
                val sessionId = audioCaptureManager.getAudioSessionId()
                audioPlaybackManager.initialize(sessionId)
                Log.d(TAG, "Audio managers initialized with shared session ID: $sessionId")

                // Apply pending speaker state if user pressed speaker button during "Calling..." phase
                pendingSpeakerEnabled?.let { enabled ->
                    audioPlaybackManager.setSpeakerEnabled(enabled)
                    Log.d(TAG, "Applied pending speaker state: $enabled")
                    pendingSpeakerEnabled = null // Clear pending state
                }
            }

            // Set capture callback
            audioCaptureManager.onFrameEncoded = { opusFrame ->
                sendVoiceFrame(opusFrame)
            }

            // Start audio capture and playback
            audioCaptureManager.startCapture(callScope)
            audioPlaybackManager.startPlayback(callScope)

            // Note: Receiving is now handled via onVoicePacket callback (no startReceiving needed)

            // Start telemetry monitoring
            telemetry.start(callScope)
            audioPlaybackManager.setTelemetry(telemetry)

            // Start periodic stats feedback (every 500ms as per spec)
            startStatsFeedback()

            // Mark call start time for duration tracking
            callStartTime = System.currentTimeMillis()

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
            Log.i(TAG, "Created Rust voice session with $numCircuits circuits to $contactVoiceOnion")

            // Initialize audio managers (blocking native calls - run on IO thread)
            withContext(Dispatchers.IO) {
                audioCaptureManager = AudioCaptureManager(context, opusCodec)
                audioPlaybackManager = AudioPlaybackManager(context, opusCodec)

                // Initialize capture first to get audio session ID
                audioCaptureManager.initialize()

                // Pass audio session ID to playback for AEC to work
                val sessionId = audioCaptureManager.getAudioSessionId()
                audioPlaybackManager.initialize(sessionId)
                Log.d(TAG, "Audio managers initialized with shared session ID: $sessionId")

                // Apply pending speaker state if user pressed speaker button during ringing
                pendingSpeakerEnabled?.let { enabled ->
                    audioPlaybackManager.setSpeakerEnabled(enabled)
                    Log.d(TAG, "Applied pending speaker state: $enabled")
                    pendingSpeakerEnabled = null // Clear pending state
                }
            }

            // Set capture callback
            audioCaptureManager.onFrameEncoded = { opusFrame ->
                sendVoiceFrame(opusFrame)
            }

            // Start audio capture and playback
            audioCaptureManager.startCapture(callScope)
            audioPlaybackManager.startPlayback(callScope)

            // Note: Receiving is now handled via onVoicePacket callback (no startReceiving needed)

            // Start telemetry monitoring
            telemetry.start(callScope)
            audioPlaybackManager.setTelemetry(telemetry)

            // Start periodic stats feedback (every 500ms as per spec)
            startStatsFeedback()

            // Mark call start time for duration tracking
            callStartTime = System.currentTimeMillis()

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
                // MVP: Single-circuit send (no DOUBLE-SEND, no multipath)
                val circuit = circuitScheduler.selectCircuit()

                // Get current sequence number and increment
                val currentSeq = sendSeqNum++

                // Timestamp is currentSeq * 40ms (MVP: 40ms Opus frames)
                val timestamp = currentSeq * 40

                // Send on selected circuit only
                val key = circuitKeys[circuit]
                if (key != null) {
                    // Create VoiceFrame for AAD encoding
                    val frame = VoiceFrame(
                        callId = callIdBytes,
                        sequenceNumber = currentSeq,
                        direction = direction,
                        circuitIndex = circuit,
                        encryptedPayload = ByteArray(0)
                    )

                    val nonce = crypto.deriveNonce(callIdBytes, currentSeq)
                    val aad = frame.encodeAAD()
                    val encrypted = crypto.encryptFrame(opusFrame, key, nonce, aad)

                    val success = RustBridge.sendAudioPacket(
                        callId, currentSeq.toInt(), timestamp, encrypted, circuit, 0x01
                    )

                    if (success) {
                        circuitScheduler.reportSendSuccess(circuit)
                        telemetry.reportFrameSent(circuit)
                    } else {
                        circuitScheduler.reportSendFailure(circuit)
                        Log.w(TAG, "Send failed: seq=$currentSeq circuit=$circuit")
                    }
                } else {
                    circuitScheduler.reportSendFailure(circuit)
                    Log.e(TAG, "No key for circuit $circuit")
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

        // Send CALL_END notification to the other person via HTTP POST to voice onion
        contactX25519PublicKey?.let { x25519Key ->
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    // Get our X25519 public key for HTTP wire format
                    val keyManager = com.securelegion.crypto.KeyManager.getInstance(context)
                    val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                    val sent = CallSignaling.sendCallEnd(
                        recipientX25519PublicKey = x25519Key,
                        recipientOnion = contactVoiceOnion, // Use voice onion for HTTP POST
                        callId = callId,
                        reason = reason,
                        ourX25519PublicKey = ourX25519PublicKey
                    )
                    if (sent) {
                        Log.i(TAG, "Sent CALL_END notification via HTTP POST to voice onion")
                    } else {
                        Log.w(TAG, "Failed to send CALL_END notification")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending CALL_END notification", e)
                }
            }
        } ?: Log.w(TAG, "Cannot send CALL_END - no X25519 public key available")

        // Create a new scope for cleanup (independent of callScope which might be hung)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Wrap cleanup in timeout to prevent hanging forever
                withTimeout(5000L) { // 5 second timeout for cleanup
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

                    // Stop telemetry and save to database
                    telemetry.stop()
                    if (callStartTime > 0) {
                        val durationSeconds = ((System.currentTimeMillis() - callStartTime) / 1000).toInt()
                        telemetry.saveToDatabase(
                            context = context,
                            callId = callId,
                            contactName = contactOnion.take(16), // Use truncated onion as name for now
                            durationSeconds = durationSeconds
                        )
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
        // Check if audioPlaybackManager is initialized (may not be during RINGING state)
        if (::audioPlaybackManager.isInitialized) {
            audioPlaybackManager.setSpeakerEnabled(enabled)
        } else {
            // Save pending speaker state to apply when AudioPlaybackManager initializes
            pendingSpeakerEnabled = enabled
            Log.d(TAG, "Saved pending speaker state: $enabled (will apply when call connects)")
        }
    }

    /**
     * Get call quality stats
     */
    fun getCallQualityStats(): AudioPlaybackManager.CallQualityStats {
        return audioPlaybackManager.getStats()
    }

    /**
     * Get telemetry snapshot (v2 - comprehensive quality metrics)
     */
    fun getTelemetrySnapshot(): CallQualityTelemetry.TelemetrySnapshot {
        return telemetry.getSnapshot()
    }

    /**
     * Get call quality score (0-5 bars)
     * Used for real-time signal quality display in UI
     */
    fun getCallQualityScore(): Int {
        return telemetry.getQualityScore()
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
    override fun onVoicePacket(callId: String, sequence: Int, timestamp: Long, circuitIndex: Byte, ptype: Byte, audioData: ByteArray) {
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
                // Use circuit index from packet header (v2) - NO LONGER DERIVE FROM SEQUENCE
                val circuitKey = circuitKeys[circuitIndex.toInt()]

                if (circuitKey == null) {
                    Log.e(TAG, "No key for circuit $circuitIndex")
                    return@launch
                }

                // Derive nonce from callId and sequence
                val nonce = crypto.deriveNonce(callIdBytes, sequence.toLong())

                // Reconstruct AAD (Additional Authenticated Data)
                // AAD format: callId (16) || sequenceNumber (8) || direction (1) || circuitIndex (1) = 26 bytes
                // CRITICAL: Use circuitIndex from header, not derived from sequence!
                val aad = java.nio.ByteBuffer.allocate(26)
                aad.put(callIdBytes) // 16 bytes
                aad.putLong(sequence.toLong()) // 8 bytes
                aad.put(if (direction == 0.toByte()) 1.toByte() else 0.toByte()) // 1 byte - opposite direction
                aad.put(circuitIndex) // 1 byte - FROM HEADER, NOT seq % numCircuits

                // Decrypt the payload
                val decryptedPayload = crypto.decryptFrame(
                    audioData,
                    circuitKey,
                    nonce,
                    aad.array()
                )

                // Report frame received to telemetry
                telemetry.reportFrameReceived(sequence.toLong(), circuitIndex.toInt())

                // Handle based on packet type
                when (ptype.toInt()) {
                    0x01 -> {
                        // AUDIO packet - add to playback buffer
                        audioPlaybackManager.addFrame(sequence.toLong(), decryptedPayload, circuitIndex.toInt())
                    }
                    0x02 -> {
                        // CONTROL packet - parse stats and update scheduler
                        handleControlPacket(decryptedPayload)
                    }
                    else -> {
                        Log.w(TAG, "Unknown packet type: $ptype")
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to process packet seq=$sequence circuit=$circuitIndex ptype=$ptype", e)
            }
        }
    }

    /**
     * Start periodic stats feedback to peer
     * Sends CONTROL packets every 500ms with per-circuit late frame stats
     */
    private fun startStatsFeedback() {
        statsFeedbackJob = callScope.launch {
            while (isActive && callState == CallState.ACTIVE) {
                delay(500) // Send every 500ms as per spec
                sendStatsPacket()
            }
        }
        Log.d(TAG, "Started periodic stats feedback (500ms interval)")
    }

    /**
     * Stop periodic stats feedback
     */
    private fun stopStatsFeedback() {
        statsFeedbackJob?.cancel()
        statsFeedbackJob = null
    }

    /**
     * Send receiver stats feedback to sender (v2)
     * Called periodically to update sender's circuit scheduler
     */
    private fun sendStatsPacket() {
        if (callState != CallState.ACTIVE) return

        callScope.launch {
            try {
                // Get per-circuit late frame stats from playback manager
                val circuitLatePercent = audioPlaybackManager.getPerCircuitLatePercent()

                if (circuitLatePercent.isEmpty()) {
                    return@launch // No stats yet
                }

                // Update our own scheduler with received stats (for debugging/monitoring)
                circuitScheduler.updateFromReceiverFeedback(circuitLatePercent)

                // Build CONTROL packet payload (simple binary format)
                val payload = buildStatsPayload(circuitLatePercent)

                // Select circuit for CONTROL packet (use scheduler)
                val circuitIndex = circuitScheduler.selectCircuit()
                val circuitKey = circuitKeys[circuitIndex] ?: return@launch

                // Get current sequence and increment
                val currentSeq = sendSeqNum++

                // Derive nonce
                val nonce = crypto.deriveNonce(callIdBytes, currentSeq)

                // Build AAD for CONTROL packet
                val frame = VoiceFrame(
                    callId = callIdBytes,
                    sequenceNumber = currentSeq,
                    direction = direction,
                    circuitIndex = circuitIndex,
                    encryptedPayload = ByteArray(0)
                )
                val aad = frame.encodeAAD()

                // Encrypt CONTROL payload
                val encryptedPayload = crypto.encryptFrame(payload, circuitKey, nonce, aad)

                // Send CONTROL packet
                val timestamp = currentSeq * 20
                val success = RustBridge.sendAudioPacket(
                    callId,
                    currentSeq.toInt(),
                    timestamp,
                    encryptedPayload,
                    circuitIndex,
                    0x02 // ptype = CONTROL
                )

                if (success) {
                    circuitScheduler.reportSendSuccess(circuitIndex)
                    Log.d(TAG, "Sent stats feedback: $circuitLatePercent")
                } else {
                    circuitScheduler.reportSendFailure(circuitIndex)
                }

                // Reset stats after sending
                audioPlaybackManager.resetCircuitStats()

            } catch (e: Exception) {
                Log.e(TAG, "Error sending stats packet", e)
            }
        }
    }

    /**
     * Build binary stats payload for CONTROL packet (v3 - enhanced with missing%, PLC%, received count)
     * Format per circuit:
     * [circuit_idx: u8][late_permille: u16][missing_permille: u16][plc_permille: u16][frames_received: u32]
     *
     * Total per circuit: 1 + 2 + 2 + 2 + 4 = 11 bytes
     * Header: [num_circuits: u8] = 1 byte
     * Total: 1 + (N * 11) bytes
     */
    private fun buildStatsPayload(circuitLatePercent: Map<Int, Double>): ByteArray {
        // Get telemetry snapshot for full circuit stats
        val snapshot = telemetry.getSnapshot()

        // Create map of circuit index to full stats
        val circuitStats = snapshot.perCircuitStats.associateBy { it.circuitIndex }

        // Size: 1 byte (num_circuits) + N * 11 bytes per circuit
        val buffer = java.nio.ByteBuffer.allocate(1 + (circuitStats.size * 11))
        buffer.put(circuitStats.size.toByte())

        for ((circuitIdx, stats) in circuitStats.entries.sortedBy { it.key }) {
            buffer.put(circuitIdx.toByte())

            // Late% as permille (0-1000)
            val latePermille = (stats.latePercent * 10.0).toInt().coerceIn(0, 1000).toShort()
            buffer.putShort(latePermille)

            // FIX #4: Missing% is NOT sent by receiver (receiver doesn't know sender's framesSent)
            // Sender will calculate missing% locally using: (framesSent - framesReceived) / framesSent
            // Send 0 as placeholder (receiver cannot calculate this metric correctly)
            val missingPermille = 0.toShort() // Receiver sends 0 (sender calculates locally)
            buffer.putShort(missingPermille)

            // FIX #4: PLC% as permille (0-1000)
            val plcPermille = (stats.plcPercent * 10.0).toInt().coerceIn(0, 1000).toShort()
            buffer.putShort(plcPermille)

            // FIX #4: Frames received count (u32)
            buffer.putInt(stats.framesReceived.toInt())
        }

        return buffer.array().copyOf(buffer.position())
    }

    /**
     * Parse received CONTROL packet and update scheduler (v3 - enhanced with missing%, PLC%)
     */
    private fun handleControlPacket(payload: ByteArray) {
        try {
            val buffer = java.nio.ByteBuffer.wrap(payload)
            val numCircuits = buffer.get().toInt()

            // Check packet format version by size
            val bytesPerCircuit = (payload.size - 1) / numCircuits
            val isEnhancedFormat = bytesPerCircuit >= 11 // v3 format with all metrics

            val feedback = mutableMapOf<Int, CircuitScheduler.CircuitFeedback>()

            for (i in 0 until numCircuits) {
                val circuitIdx = buffer.get().toInt()
                val latePermille = buffer.short.toInt()
                val latePct = latePermille / 10.0

                if (isEnhancedFormat) {
                    // FIX #4: Parse enhanced format with missing%, PLC%, received count
                    val missingPermille = buffer.short.toInt()
                    val plcPermille = buffer.short.toInt()
                    val framesReceived = buffer.int.toLong()

                    val missingPct = missingPermille / 10.0
                    val plcPct = plcPermille / 10.0

                    feedback[circuitIdx] = CircuitScheduler.CircuitFeedback(
                        latePercent = latePct,
                        missingPercent = missingPct,
                        plcPercent = plcPct,
                        framesReceived = framesReceived
                    )

                    // CRITICAL FIX: Update telemetry with peer's received count
                    // This allows correct missing% calculation: (sent - peerReceived) / sent
                    telemetry.updatePeerReceivedCount(circuitIdx, framesReceived)
                } else {
                    // Legacy format (v2) - only late%
                    feedback[circuitIdx] = CircuitScheduler.CircuitFeedback(
                        latePercent = latePct,
                        missingPercent = 0.0,
                        plcPercent = 0.0,
                        framesReceived = 0L
                    )
                }
            }

            // Update scheduler with enhanced feedback
            circuitScheduler.updateFromReceiverFeedback(feedback)
            Log.d(TAG, "Updated scheduler from peer feedback (enhanced): $feedback")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse CONTROL packet", e)
        }
    }
}
