package com.securelegion.voice

import android.content.Context
import android.util.Log
import com.securelegion.crypto.RustBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancel

/**
 * VoiceCallManager is the high-level API for voice calling
 *
 * Responsibilities:
 * - Manage active call sessions
 * - Handle incoming call notifications
 * - Coordinate with Ping-Pong protocol for call signaling
 * - Provide API for UI (start call, answer, end, mute, etc.)
 *
 * Usage:
 * ```
 * val callManager = VoiceCallManager.getInstance(context)
 *
 * // Start outgoing call
 * callManager.startCall(contact) { success, error ->
 * if (success) {
 * // Call started
 * }
 * }
 *
 * // Answer incoming call
 * callManager.answerCall(callId)
 *
 * // End call
 * callManager.endCall()
 * ```
 */
class VoiceCallManager private constructor(private val context: Context) : RustBridge.VoicePacketCallback {

    companion object {
        private const val TAG = "VoiceCallManager"

        @Volatile
        private var instance: VoiceCallManager? = null

        fun getInstance(context: Context): VoiceCallManager {
            return instance ?: synchronized(this) {
                instance ?: VoiceCallManager(context.applicationContext).also { instance = it }
            }
        }
    }

    // Application-scoped coroutine scope tied to the lifecycle of this singleton
    private val managerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Current active call (only one call at a time for now)
    private var activeCall: VoiceCallSession? = null

    // Incoming call queue (for notifications)
    private val incomingCalls = mutableMapOf<String, IncomingCallInfo>()

    // Pending outgoing calls (waiting for CALL_ANSWER)
    private val pendingOutgoingCalls = mutableMapOf<String, PendingOutgoingCallInfo>()

    // Answered calls (for idempotency - re-send CALL_ANSWER on duplicate offers)
    private val answeredCalls = mutableMapOf<String, AnsweredCallInfo>()

    // Callbacks
    var onIncomingCall: ((callId: String, contactOnion: String, contactName: String?) -> Unit)? = null
    var onCallStateChanged: ((VoiceCallSession.Companion.CallState) -> Unit)? = null
    var onCallEnded: ((reason: String) -> Unit)? = null
    var onAudioAmplitude: ((amplitude: Float) -> Unit)? = null // Audio amplitude for waveform visualization

    /**
     * Call state for idempotency
     */
    enum class CallState {
        RINGING, // Received CALL_OFFER, showing incoming call UI
        ANSWER_SENT, // User pressed Answer, sent CALL_ANSWER
        ACTIVE // Voice call connected
    }

    /**
     * Data class for incoming call information
     */
    data class IncomingCallInfo(
        val callId: String,
        val contactOnion: String,
        val contactEd25519PublicKey: ByteArray,
        val contactName: String?,
        val ephemeralPublicKey: ByteArray,
        val timestamp: Long = System.currentTimeMillis(),
        var state: CallState = CallState.RINGING
    )

    /**
     * Data class for answered call info (for re-sending CALL_ANSWER on duplicate offers)
     */
    data class AnsweredCallInfo(
        val callId: String,
        val contactOnion: String,
        val contactX25519PublicKey: ByteArray,
        val ourEphemeralPublicKey: ByteArray,
        val myVoiceOnion: String,
        val ourX25519PublicKey: ByteArray
    )

    /**
     * Data class for pending outgoing call information
     */
    data class PendingOutgoingCallInfo(
        val callId: String,
        val contactOnion: String,
        val contactEd25519PublicKey: ByteArray,
        val contactName: String?,
        val ourEphemeralPublicKey: ByteArray,
        val onAnswered: (ByteArray) -> Unit, // Called with their ephemeral key
        val onRejected: (String) -> Unit, // Called with rejection reason
        val onBusy: () -> Unit, // Called when contact is busy
        val onTimeout: () -> Unit, // Called after 30 seconds
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Start outgoing voice call to a contact
     * @param contactOnion Contact's .onion address
     * @param contactVoiceOnion Contact's voice .onion address
     * @param contactEd25519PublicKey Contact's Ed25519 public key
     * @param contactName Contact's display name (optional)
     * @param theirEphemeralPublicKey Ephemeral key received from CALL_ANSWER
     * @param ourEphemeralSecretKey Our ephemeral secret key (to match public key sent in CALL_OFFER)
     * @param callId Call ID from CALL_OFFER (must match the ID used in signaling)
     */
    suspend fun startCall(
        contactOnion: String,
        contactVoiceOnion: String,
        contactEd25519PublicKey: ByteArray,
        contactName: String?,
        theirEphemeralPublicKey: ByteArray,
        ourEphemeralSecretKey: ByteArray,
        callId: String,
        contactX25519PublicKey: ByteArray
    ): Result<VoiceCallSession> {
        if (activeCall != null) {
            return Result.failure(IllegalStateException("Call already in progress"))
        }

        try {
            Log.i(TAG, "Starting call to $contactName ($contactOnion) with callId=$callId")

            val callSession = VoiceCallSession(
                context = context,
                contactOnion = contactOnion,
                contactVoiceOnion = contactVoiceOnion,
                contactEd25519PublicKey = contactEd25519PublicKey,
                isOutgoing = true,
                callId = callId,
                contactX25519PublicKey = contactX25519PublicKey
            )

            // Set callbacks
            callSession.onCallStateChanged = { state ->
                onCallStateChanged?.invoke(state)
            }

            callSession.onCallEnded = { reason ->
                activeCall = null
                onCallEnded?.invoke(reason)
            }

            activeCall = callSession

            // Start the call with our ephemeral secret key
            callSession.startOutgoingCall(theirEphemeralPublicKey, ourEphemeralSecretKey)

            return Result.success(callSession)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start call", e)
            activeCall = null
            return Result.failure(e)
        }
    }

    /**
     * Handle incoming call offer (called by message receiver)
     * @param callId Unique call ID
     * @param contactOnion Caller's .onion address
     * @param contactEd25519PublicKey Caller's Ed25519 public key
     * @param contactName Caller's display name (optional)
     * @param ephemeralPublicKey Caller's ephemeral public key
     * @return true if this is a new call (should show UI), false if duplicate (ignore)
     */
    fun handleIncomingCallOffer(
        callId: String,
        contactOnion: String,
        contactEd25519PublicKey: ByteArray,
        contactName: String?,
        ephemeralPublicKey: ByteArray
    ): Boolean {
        Log.i(TAG, "Incoming CALL_OFFER from $contactName ($contactOnion), callId=$callId")

        // Idempotency: Check if this call already exists
        val existingCall = incomingCalls[callId]
        if (existingCall != null) {
            when (existingCall.state) {
                CallState.RINGING -> {
                    Log.i(TAG, "Duplicate CALL_OFFER for call $callId while RINGING - ignoring (idempotent)")
                    return false // Duplicate - don't show UI again
                }
                CallState.ANSWER_SENT, CallState.ACTIVE -> {
                    Log.w(TAG, "Duplicate CALL_OFFER for call $callId after answering - this shouldn't happen")
                    return false // Duplicate - don't show UI
                }
            }
        }

        // Idempotency: Check if we already answered this call
        val answeredCall = answeredCalls[callId]
        if (answeredCall != null) {
            Log.i(TAG, "Duplicate CALL_OFFER for answered call $callId - re-sending CALL_ANSWER via HTTP POST (idempotent)")
            managerScope.launch(Dispatchers.IO) {
                // Re-send CALL_ANSWER via HTTP POST to voice .onion
                val success = CallSignaling.sendCallAnswer(
                    recipientX25519PublicKey = answeredCall.contactX25519PublicKey,
                    recipientOnion = answeredCall.contactOnion,
                    callId = callId,
                    ephemeralPublicKey = answeredCall.ourEphemeralPublicKey,
                    voiceOnion = answeredCall.myVoiceOnion,
                    ourX25519PublicKey = answeredCall.ourX25519PublicKey
                )
                if (success) {
                    Log.i(TAG, "Re-sent CALL_ANSWER for duplicate offer")
                } else {
                    Log.w(TAG, "Failed to re-send CALL_ANSWER for duplicate offer")
                }
            }
            return false // Duplicate - don't show UI again
        }

        // New call - store it
        Log.d(TAG, "New incoming call - storing with state=RINGING")
        incomingCalls[callId] = IncomingCallInfo(
            callId = callId,
            contactOnion = contactOnion,
            contactEd25519PublicKey = contactEd25519PublicKey,
            contactName = contactName,
            ephemeralPublicKey = ephemeralPublicKey,
            state = CallState.RINGING
        )

        Log.d(TAG, "Incoming call stored. Total incoming calls: ${incomingCalls.size}")

        // Notify UI (this will trigger the ringtone)
        onIncomingCall?.invoke(callId, contactOnion, contactName)

        return true // New call - show UI
    }

    /**
     * Answer incoming call
     * @param callId The incoming call ID
     * @param contactVoiceOnion Contact's voice .onion address
     * @param ourEphemeralSecretKey Our ephemeral secret key (to match the public key we'll send in CALL_ANSWER)
     * @param contactX25519PublicKey Contact's X25519 public key (for re-sending CALL_ANSWER if needed)
     * @param contactMessagingOnion Contact's messaging .onion address (for re-sending CALL_ANSWER if needed)
     * @param ourEphemeralPublicKey Our ephemeral public key (for re-sending CALL_ANSWER if needed)
     * @param myVoiceOnion Our voice .onion address (for re-sending CALL_ANSWER if needed)
     */
    suspend fun answerCall(
        callId: String,
        contactVoiceOnion: String,
        ourEphemeralSecretKey: ByteArray,
        contactX25519PublicKey: ByteArray,
        contactMessagingOnion: String,
        ourEphemeralPublicKey: ByteArray,
        myVoiceOnion: String
    ): Result<VoiceCallSession> {
        if (activeCall != null) {
            return Result.failure(IllegalStateException("Call already in progress"))
        }

        Log.d(TAG, "answerCall called with callId: $callId")
        Log.d(TAG, "Current incoming calls: ${incomingCalls.keys.joinToString(", ")}")

        val callInfo = incomingCalls.remove(callId)
        if (callInfo == null) {
            Log.e(TAG, "Cannot answer call - unknown call ID: $callId")
            Log.e(TAG, "Available call IDs: ${incomingCalls.keys.joinToString(", ")}")
            return Result.failure(IllegalArgumentException("Unknown call ID: $callId"))
        }

        // Get our X25519 public key for HTTP wire format
        val keyManager = com.securelegion.crypto.KeyManager.getInstance(context)
        val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

        // Store answered call info for idempotency (re-send CALL_ANSWER on duplicate offers)
        answeredCalls[callId] = AnsweredCallInfo(
            callId = callId,
            contactOnion = contactMessagingOnion,
            contactX25519PublicKey = contactX25519PublicKey,
            ourEphemeralPublicKey = ourEphemeralPublicKey,
            myVoiceOnion = myVoiceOnion,
            ourX25519PublicKey = ourX25519PublicKey
        )
        Log.d(TAG, "Stored answered call info for idempotency")

        try {
            Log.i(TAG, "Answering call from ${callInfo.contactName}")

            val callSession = VoiceCallSession(
                context = context,
                contactOnion = callInfo.contactOnion,
                contactVoiceOnion = contactVoiceOnion,
                contactEd25519PublicKey = callInfo.contactEd25519PublicKey,
                isOutgoing = false,
                callId = callInfo.callId, // Use call ID from CALL_OFFER (critical for audio routing!)
                contactX25519PublicKey = contactX25519PublicKey // For sending CALL_END notification
            )

            // Set callbacks
            callSession.onCallStateChanged = { state ->
                onCallStateChanged?.invoke(state)
            }

            callSession.onCallEnded = { reason ->
                activeCall = null
                onCallEnded?.invoke(reason)
            }

            activeCall = callSession

            // Answer the call with our ephemeral secret key
            callSession.answerIncomingCall(callInfo.ephemeralPublicKey, ourEphemeralSecretKey)

            return Result.success(callSession)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to answer call", e)
            activeCall = null
            return Result.failure(e)
        }
    }

    /**
     * Reject incoming call
     * @param callId The incoming call ID
     */
    fun rejectCall(callId: String) {
        val callInfo = incomingCalls.remove(callId)
        if (callInfo != null) {
            Log.i(TAG, "Rejected call from ${callInfo.contactName}")
            // TODO: Send rejection notification to caller via Ping-Pong protocol
        }
    }

    /**
     * End current active call
     */
    fun endCall(reason: String = "User ended call") {
        activeCall?.endCall(reason)
        activeCall = null
    }

    /**
     * Mute/unmute microphone
     */
    fun setMuted(muted: Boolean) {
        activeCall?.setMuted(muted)
    }

    /**
     * Enable/disable speaker
     */
    fun setSpeakerEnabled(enabled: Boolean) {
        activeCall?.setSpeakerEnabled(enabled)
    }

    /**
     * Get active call session (if any)
     */
    fun getActiveCall(): VoiceCallSession? = activeCall

    /**
     * Check if there's an active call
     */
    fun hasActiveCall(): Boolean = activeCall != null

    /**
     * Get current call state (or IDLE if no active call)
     */
    fun getCurrentCallState(): VoiceCallSession.Companion.CallState {
        return activeCall?.getState() ?: VoiceCallSession.Companion.CallState.IDLE
    }

    /**
     * Get call quality stats for active call
     */
    fun getCallQualityStats(): AudioPlaybackManager.CallQualityStats? {
        return activeCall?.getCallQualityStats()
    }

    /**
     * Get list of incoming calls waiting for answer
     */
    fun getIncomingCalls(): List<IncomingCallInfo> {
        return incomingCalls.values.toList()
    }

    /**
     * Clean up old incoming calls (older than 60 seconds)
     */
    fun cleanupOldIncomingCalls() {
        val now = System.currentTimeMillis()
        val timeout = 60000L // 60 seconds

        val iterator = incomingCalls.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.timestamp > timeout) {
                Log.d(TAG, "Removing expired incoming call: ${entry.key}")
                iterator.remove()
            }
        }
    }

    /**
     * Register a pending outgoing call (waiting for CALL_ANSWER)
     * Called by ChatActivity after sending CALL_OFFER
     */
    fun registerPendingOutgoingCall(
        callId: String,
        contactOnion: String,
        contactEd25519PublicKey: ByteArray,
        contactName: String?,
        ourEphemeralPublicKey: ByteArray,
        onAnswered: (ByteArray) -> Unit,
        onRejected: (String) -> Unit,
        onBusy: () -> Unit,
        onTimeout: () -> Unit
    ) {
        Log.i(TAG, "Registered pending outgoing call: $callId to $contactName")

        pendingOutgoingCalls[callId] = PendingOutgoingCallInfo(
            callId = callId,
            contactOnion = contactOnion,
            contactEd25519PublicKey = contactEd25519PublicKey,
            contactName = contactName,
            ourEphemeralPublicKey = ourEphemeralPublicKey,
            onAnswered = onAnswered,
            onRejected = onRejected,
            onBusy = onBusy,
            onTimeout = onTimeout
        )
    }

    /**
     * Handle CALL_ANSWER response
     * Called by MessageService when CALL_ANSWER is received
     */
    fun handleCallAnswer(callId: String, theirEphemeralPublicKey: ByteArray) {
        val pendingCall = pendingOutgoingCalls.remove(callId)
        if (pendingCall != null) {
            Log.i(TAG, "Call answered by ${pendingCall.contactName}")
            pendingCall.onAnswered(theirEphemeralPublicKey)
        } else {
            Log.w(TAG, "Received CALL_ANSWER for unknown call ID: $callId")
        }
    }

    /**
     * Handle CALL_REJECT response
     * Called by MessageService when CALL_REJECT is received
     */
    fun handleCallReject(callId: String, reason: String) {
        val pendingCall = pendingOutgoingCalls.remove(callId)
        if (pendingCall != null) {
            Log.i(TAG, "Call rejected by ${pendingCall.contactName}: $reason")
            pendingCall.onRejected(reason)
        } else {
            Log.w(TAG, "Received CALL_REJECT for unknown call ID: $callId")
        }
    }

    /**
     * Handle CALL_BUSY response
     * Called by MessageService when CALL_BUSY is received
     */
    fun handleCallBusy(callId: String) {
        val pendingCall = pendingOutgoingCalls.remove(callId)
        if (pendingCall != null) {
            Log.i(TAG, "Contact ${pendingCall.contactName} is busy")
            pendingCall.onBusy()
        } else {
            Log.w(TAG, "Received CALL_BUSY for unknown call ID: $callId")
        }
    }

    /**
     * Check for and handle timeout on pending outgoing calls
     * Should be called periodically (every second)
     */
    fun checkPendingCallTimeouts() {
        val now = System.currentTimeMillis()
        val timeout = 60000L // 60 seconds (increased from 30 to account for Tor circuit creation)

        val iterator = pendingOutgoingCalls.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            val pendingCall = entry.value
            if (now - pendingCall.timestamp > timeout) {
                Log.w(TAG, "Outgoing call to ${pendingCall.contactName} timed out")
                iterator.remove()
                pendingCall.onTimeout()
            }
        }
    }

    /**
     * VoicePacketCallback implementation
     * Routes incoming voice packets from Rust to the active call session
     */
    override fun onVoicePacket(callId: String, sequence: Int, timestamp: Long, circuitIndex: Byte, ptype: Byte, audioData: ByteArray) {
        // Route packet to the active call session
        val session = activeCall
        if (session != null) {
            // Forward packet to the active session's callback
            session.onVoicePacket(callId, sequence, timestamp, circuitIndex, ptype, audioData)

            // Calculate audio amplitude for waveform visualization (only for audio packets, not FEC)
            if (ptype.toInt() == 0 && audioData.isNotEmpty()) {
                val amplitude = calculateAudioAmplitude(audioData)
                onAudioAmplitude?.invoke(amplitude)
            }
        } else {
            Log.w(TAG, "Received voice packet for callId=$callId but no active call session")
        }
    }

    /**
     * Calculate audio amplitude from PCM audio data
     * Returns normalized amplitude (0.0 to 1.0)
     */
    private fun calculateAudioAmplitude(audioData: ByteArray): Float {
        if (audioData.isEmpty()) return 0f

        // Calculate RMS (Root Mean Square) of audio samples
        // Audio is 16-bit PCM, so 2 bytes per sample
        var sum = 0L
        var sampleCount = 0

        var i = 0
        while (i < audioData.size - 1) {
            // Combine two bytes into a 16-bit signed sample (little-endian)
            val sample = ((audioData[i + 1].toInt() shl 8) or (audioData[i].toInt() and 0xFF)).toShort()
            sum += (sample * sample).toLong()
            sampleCount++
            i += 2
        }

        if (sampleCount == 0) return 0f

        // Calculate RMS
        val rms = kotlin.math.sqrt((sum.toDouble() / sampleCount))

        // Normalize to 0.0-1.0 range (assuming 16-bit PCM max value is 32767)
        return (rms / 32767.0).toFloat().coerceIn(0f, 1f)
    }
}
