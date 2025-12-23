package com.securelegion.voice

import android.content.Context
import android.util.Log
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
    private val contactEd25519PublicKey: ByteArray,
    private val isOutgoing: Boolean
) {
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

    // Call ID (unique for this call session)
    private val callId = UUID.randomUUID().toString().replace("-", "").take(16).toByteArray()

    // Crypto components
    private val crypto = VoiceCallCrypto()
    private var masterKey: ByteArray? = null
    private var circuitKeys = mutableMapOf<Int, ByteArray>()

    // Audio components
    private val opusCodec = OpusCodec()
    private lateinit var audioCaptureManager: AudioCaptureManager
    private lateinit var audioPlaybackManager: AudioPlaybackManager

    // Network components
    private val circuits = mutableListOf<TorVoiceSocket>()
    private val numCircuits = 1 // Phase 1: single circuit, Phase 2: 3-5 circuits

    // Sequence tracking
    private var sendSeqNum: Long = 0
    private var direction: Byte = if (isOutgoing) 0 else 1

    // Coroutine scope for call session
    private val callScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Jobs
    private var sendJob: Job? = null
    private var receiveJob: Job? = null

    // Callbacks
    var onCallStateChanged: ((CallState) -> Unit)? = null
    var onCallEnded: ((reason: String) -> Unit)? = null

    /**
     * Start outgoing call
     * 1. Generate ephemeral keys
     * 2. Exchange keys with recipient (via existing Ping-Pong protocol)
     * 3. Derive encryption keys
     * 4. Establish Tor circuits
     * 5. Start audio capture and transmission
     */
    suspend fun startOutgoingCall(theirEphemeralPublicKey: ByteArray) {
        try {
            setState(CallState.CONNECTING)

            Log.i(TAG, "Starting outgoing call to $contactOnion")

            // Initialize Opus codec
            opusCodec.initEncoder()
            opusCodec.initDecoder()

            // Generate our ephemeral keypair
            val ourEphemeralKeypair = crypto.generateEphemeralKeypair()

            Log.d(TAG, "Generated ephemeral keypair for call")

            // TODO: Send call offer with our ephemeral public key via Ping-Pong protocol
            // For now, assume keys are exchanged

            // Compute shared secret
            val sharedSecret = crypto.computeSharedSecret(
                ourEphemeralKeypair.secretKey.asBytes,
                theirEphemeralPublicKey
            )

            // Derive master call key
            masterKey = crypto.deriveMasterKey(sharedSecret, callId)

            // Derive per-circuit keys
            for (i in 0 until numCircuits) {
                circuitKeys[i] = crypto.deriveCircuitKey(masterKey!!, i)
            }

            Log.d(TAG, "Derived encryption keys: master + $numCircuits circuit keys")

            // Establish Tor circuits
            for (i in 0 until numCircuits) {
                val socket = TorVoiceSocket(i)
                socket.connect(contactOnion, VOICE_PORT)
                circuits.add(socket)
                Log.d(TAG, "Established circuit $i to $contactOnion")
            }

            // Initialize audio managers
            audioCaptureManager = AudioCaptureManager(context, opusCodec)
            audioPlaybackManager = AudioPlaybackManager(context, opusCodec)

            audioCaptureManager.initialize()
            audioPlaybackManager.initialize()

            // Set capture callback
            audioCaptureManager.onFrameEncoded = { opusFrame ->
                sendVoiceFrame(opusFrame)
            }

            // Start audio capture and playback
            audioCaptureManager.startCapture(callScope)
            audioPlaybackManager.startPlayback(callScope)

            // Start receiving frames
            startReceiving()

            setState(CallState.ACTIVE)

            Log.i(TAG, "Call active")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start outgoing call", e)
            endCall("Connection failed: ${e.message}")
        }
    }

    /**
     * Answer incoming call
     */
    suspend fun answerIncomingCall(theirEphemeralPublicKey: ByteArray) {
        try {
            Log.i(TAG, "Answering incoming call from $contactOnion")
            setState(CallState.CONNECTING)

            // Direction = 1 for incoming calls
            direction = 1

            // Initialize Opus codec
            opusCodec.initEncoder()
            opusCodec.initDecoder()

            // Generate our ephemeral keypair
            val ourEphemeralKeypair = crypto.generateEphemeralKeypair()

            Log.d(TAG, "Generated ephemeral keypair for answering call")

            // Compute shared secret
            val sharedSecret = crypto.computeSharedSecret(
                ourEphemeralKeypair.secretKey.asBytes,
                theirEphemeralPublicKey
            )

            // Derive master call key
            masterKey = crypto.deriveMasterKey(sharedSecret, callId)

            // Derive per-circuit keys
            for (i in 0 until numCircuits) {
                circuitKeys[i] = crypto.deriveCircuitKey(masterKey!!, i)
            }

            Log.d(TAG, "Derived encryption keys: master + $numCircuits circuit keys")

            // Establish Tor circuits
            for (i in 0 until numCircuits) {
                val socket = TorVoiceSocket(i)
                socket.connect(contactOnion, VOICE_PORT)
                circuits.add(socket)
                Log.d(TAG, "Established circuit $i to $contactOnion")
            }

            // Initialize audio managers
            audioCaptureManager = AudioCaptureManager(context, opusCodec)
            audioPlaybackManager = AudioPlaybackManager(context, opusCodec)

            audioCaptureManager.initialize()
            audioPlaybackManager.initialize()

            // Set capture callback
            audioCaptureManager.onFrameEncoded = { opusFrame ->
                sendVoiceFrame(opusFrame)
            }

            // Start audio capture and playback
            audioCaptureManager.startCapture(callScope)
            audioPlaybackManager.startPlayback(callScope)

            // Start receiving frames
            startReceiving()

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
                // Select circuit (Phase 1: always circuit 0)
                val circuitIndex = 0 // TODO Phase 2: (sendSeqNum % numCircuits).toInt()
                val socket = circuits.getOrNull(circuitIndex)
                val circuitKey = circuitKeys[circuitIndex]

                if (socket == null || circuitKey == null) {
                    Log.e(TAG, "Circuit $circuitIndex not available")
                    return@launch
                }

                // Create VoiceFrame
                val frame = VoiceFrame(
                    callId = callId,
                    sequenceNumber = sendSeqNum++,
                    direction = direction,
                    circuitIndex = circuitIndex,
                    encryptedPayload = ByteArray(0) // Placeholder, will encrypt below
                )

                // Derive nonce
                val nonce = crypto.deriveNonce(callId, frame.sequenceNumber)

                // Encode AAD
                val aad = frame.encodeAAD()

                // Encrypt Opus frame
                val encryptedPayload = crypto.encryptFrame(
                    opusFrame,
                    circuitKey,
                    nonce,
                    aad
                )

                // Create final encrypted frame
                val encryptedFrame = frame.copy(encryptedPayload = encryptedPayload)

                // Send over Tor
                val success = socket.sendFrame(encryptedFrame)

                if (!success) {
                    Log.w(TAG, "Failed to send frame seq=${frame.sequenceNumber}")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error sending voice frame", e)
            }
        }
    }

    /**
     * Start receiving voice frames from all circuits
     */
    private fun startReceiving() {
        for ((index, socket) in circuits.withIndex()) {
            receiveJob = callScope.launch {
                receiveLoop(socket, index)
            }
        }
    }

    /**
     * Receive loop for one circuit
     */
    private suspend fun receiveLoop(socket: TorVoiceSocket, circuitIndex: Int) {
        Log.d(TAG, "Starting receive loop for circuit $circuitIndex")

        try {
            while (callState == CallState.ACTIVE && socket.isConnected()) {
                // Receive encrypted frame
                val encryptedFrame = socket.receiveFrame()

                if (encryptedFrame == null) {
                    Log.w(TAG, "Circuit $circuitIndex closed")
                    break
                }

                // Decrypt frame
                val circuitKey = circuitKeys[encryptedFrame.circuitIndex]

                if (circuitKey == null) {
                    Log.e(TAG, "No key for circuit ${encryptedFrame.circuitIndex}")
                    continue
                }

                try {
                    // Derive nonce
                    val nonce = crypto.deriveNonce(encryptedFrame.callId, encryptedFrame.sequenceNumber)

                    // Encode AAD
                    val aad = encryptedFrame.encodeAAD()

                    // Decrypt payload
                    val opusFrame = crypto.decryptFrame(
                        encryptedFrame.encryptedPayload,
                        circuitKey,
                        nonce,
                        aad
                    )

                    // Add to jitter buffer for playback
                    audioPlaybackManager.addFrame(encryptedFrame.sequenceNumber, opusFrame)

                } catch (e: Exception) {
                    Log.e(TAG, "Failed to decrypt frame seq=${encryptedFrame.sequenceNumber}", e)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Receive loop error on circuit $circuitIndex", e)
        } finally {
            Log.d(TAG, "Receive loop ended for circuit $circuitIndex")
        }
    }

    /**
     * End the call
     */
    fun endCall(reason: String = "User ended call") {
        if (callState == CallState.ENDED || callState == CallState.ENDING) {
            return
        }

        setState(CallState.ENDING)

        Log.i(TAG, "Ending call: $reason")

        // Stop audio
        audioCaptureManager.stopCapture()
        audioPlaybackManager.stopPlayback()

        // Close circuits
        for (socket in circuits) {
            socket.close()
        }
        circuits.clear()

        // Wipe keys
        masterKey?.let { crypto.wipeKey(it) }
        for (key in circuitKeys.values) {
            crypto.wipeKey(key)
        }
        circuitKeys.clear()

        // Release resources
        audioCaptureManager.release()
        audioPlaybackManager.release()
        opusCodec.release()

        // Cancel coroutines
        callScope.cancel()

        setState(CallState.ENDED)

        onCallEnded?.invoke(reason)

        Log.i(TAG, "Call ended")
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
}
