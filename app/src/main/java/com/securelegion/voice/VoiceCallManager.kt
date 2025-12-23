package com.securelegion.voice

import android.content.Context
import android.util.Log

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
 *     if (success) {
 *         // Call started
 *     }
 * }
 *
 * // Answer incoming call
 * callManager.answerCall(callId)
 *
 * // End call
 * callManager.endCall()
 * ```
 */
class VoiceCallManager private constructor(private val context: Context) {

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

    // Current active call (only one call at a time for now)
    private var activeCall: VoiceCallSession? = null

    // Incoming call queue (for notifications)
    private val incomingCalls = mutableMapOf<String, IncomingCallInfo>()

    // Pending outgoing calls (waiting for CALL_ANSWER)
    private val pendingOutgoingCalls = mutableMapOf<String, PendingOutgoingCallInfo>()

    // Callbacks
    var onIncomingCall: ((callId: String, contactOnion: String, contactName: String?) -> Unit)? = null
    var onCallStateChanged: ((VoiceCallSession.Companion.CallState) -> Unit)? = null
    var onCallEnded: ((reason: String) -> Unit)? = null

    /**
     * Data class for incoming call information
     */
    data class IncomingCallInfo(
        val callId: String,
        val contactOnion: String,
        val contactEd25519PublicKey: ByteArray,
        val contactName: String?,
        val ephemeralPublicKey: ByteArray,
        val timestamp: Long = System.currentTimeMillis()
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
        val onRejected: (String) -> Unit,     // Called with rejection reason
        val onBusy: () -> Unit,               // Called when contact is busy
        val onTimeout: () -> Unit,            // Called after 30 seconds
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Start outgoing voice call to a contact
     * @param contactOnion Contact's .onion address
     * @param contactEd25519PublicKey Contact's Ed25519 public key
     * @param contactName Contact's display name (optional)
     * @param theirEphemeralPublicKey Ephemeral key received from call offer/answer
     */
    suspend fun startCall(
        contactOnion: String,
        contactEd25519PublicKey: ByteArray,
        contactName: String?,
        theirEphemeralPublicKey: ByteArray
    ): Result<VoiceCallSession> {
        if (activeCall != null) {
            return Result.failure(IllegalStateException("Call already in progress"))
        }

        try {
            Log.i(TAG, "Starting call to $contactName ($contactOnion)")

            val callSession = VoiceCallSession(
                context = context,
                contactOnion = contactOnion,
                contactEd25519PublicKey = contactEd25519PublicKey,
                isOutgoing = true
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

            // Start the call
            callSession.startOutgoingCall(theirEphemeralPublicKey)

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
     */
    fun handleIncomingCallOffer(
        callId: String,
        contactOnion: String,
        contactEd25519PublicKey: ByteArray,
        contactName: String?,
        ephemeralPublicKey: ByteArray
    ) {
        Log.i(TAG, "Incoming call from $contactName ($contactOnion)")

        // Store incoming call info
        incomingCalls[callId] = IncomingCallInfo(
            callId = callId,
            contactOnion = contactOnion,
            contactEd25519PublicKey = contactEd25519PublicKey,
            contactName = contactName,
            ephemeralPublicKey = ephemeralPublicKey
        )

        // Notify UI
        onIncomingCall?.invoke(callId, contactOnion, contactName)
    }

    /**
     * Answer incoming call
     * @param callId The incoming call ID
     */
    suspend fun answerCall(callId: String): Result<VoiceCallSession> {
        if (activeCall != null) {
            return Result.failure(IllegalStateException("Call already in progress"))
        }

        val callInfo = incomingCalls.remove(callId)
            ?: return Result.failure(IllegalArgumentException("Unknown call ID"))

        try {
            Log.i(TAG, "Answering call from ${callInfo.contactName}")

            val callSession = VoiceCallSession(
                context = context,
                contactOnion = callInfo.contactOnion,
                contactEd25519PublicKey = callInfo.contactEd25519PublicKey,
                isOutgoing = false
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

            // Answer the call
            callSession.answerIncomingCall(callInfo.ephemeralPublicKey)

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
        val timeout = 30000L // 30 seconds

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
}
