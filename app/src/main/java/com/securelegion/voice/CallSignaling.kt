package com.securelegion.voice

import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import org.json.JSONObject

/**
 * CallSignaling handles voice call signaling messages via one-way MESSAGE protocol
 *
 * Message types:
 * - CALL_OFFER: Initiate voice call with ephemeral public key
 * - CALL_ANSWER: Accept call with ephemeral public key
 * - CALL_REJECT: Reject incoming call
 * - CALL_END: End active call
 * - CALL_BUSY: Recipient is busy on another call
 *
 * Messages are sent as encrypted JSON via MSG_TYPE_CALL_SIGNALING (0x0D)
 * These are not stored in the messages database (ephemeral signaling only)
 */
object CallSignaling {
    private const val TAG = "CallSignaling"

    // Message type for Rust protocol
    private const val MSG_TYPE_CALL_SIGNALING: Byte = 0x0D

    // Wire protocol codes (for future binary protocol optimization)
    const val CODE_CALL_OFFER = 0x10    // 16: Initiate voice call
    const val CODE_CALL_ANSWER = 0x11   // 17: Accept incoming call
    const val CODE_CALL_REJECT = 0x12   // 18: Decline incoming call
    const val CODE_CALL_END = 0x13      // 19: Hang up active call
    const val CODE_CALL_BUSY = 0x14     // 20: Recipient busy on another call

    // Message type constants (JSON strings, currently used)
    const val TYPE_CALL_OFFER = "CALL_OFFER"
    const val TYPE_CALL_ANSWER = "CALL_ANSWER"
    const val TYPE_CALL_REJECT = "CALL_REJECT"
    const val TYPE_CALL_END = "CALL_END"
    const val TYPE_CALL_BUSY = "CALL_BUSY"

    /**
     * Send call offer to recipient via HTTP POST to voice .onion
     * @param recipientX25519PublicKey Recipient's X25519 public key (for message encryption)
     * @param recipientOnion Recipient's VOICE .onion address (for HTTP POST delivery)
     * @param callId Unique call ID
     * @param ephemeralPublicKey Our ephemeral X25519 public key for this call
     * @param voiceOnion Our voice .onion address (for voice streaming connection)
     * @param ourX25519PublicKey Our X25519 public key (for wire message format)
     * @param numCircuits Number of Tor circuits to use (1 for Phase 1, 3-5 for Phase 2)
     * @return True if offer sent successfully
     */
    suspend fun sendCallOffer(
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        callId: String,
        ephemeralPublicKey: ByteArray,
        voiceOnion: String,
        ourX25519PublicKey: ByteArray,
        numCircuits: Int = 1
    ): Boolean {
        return try {
            Log.d(TAG, "sendCallOffer called:")
            Log.d(TAG, "  recipientOnion: $recipientOnion")
            Log.d(TAG, "  callId: $callId")

            // Create call offer JSON
            val offerJson = JSONObject().apply {
                put("type", TYPE_CALL_OFFER)
                put("callId", callId)
                put("ephemeralPublicKey", Base64.encodeToString(ephemeralPublicKey, Base64.NO_WRAP))
                put("voiceOnion", voiceOnion)
                put("numCircuits", numCircuits)
                put("timestamp", System.currentTimeMillis())
            }

            val message = offerJson.toString()
            Log.d(TAG, "Message JSON created: ${message.length} bytes")

            // Encrypt message
            val encryptedMessage = RustBridge.encryptMessage(message, recipientX25519PublicKey)
            Log.d(TAG, "Message encrypted: ${encryptedMessage.size} bytes")

            Log.d(TAG, "Calling RustBridge.sendHttpToVoiceOnion to $recipientOnion...")
            Log.i(TAG, "Sending CALL_OFFER via HTTP POST to voice .onion (port 9152)")

            // Send via HTTP POST to voice .onion on IO thread
            val success = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                try {
                    val result = RustBridge.sendHttpToVoiceOnion(
                        recipientOnion,
                        ourX25519PublicKey,
                        encryptedMessage
                    )
                    Log.d(TAG, "RustBridge.sendHttpToVoiceOnion returned: $result")
                    result
                } catch (e: Exception) {
                    Log.e(TAG, "Exception in sendHttpToVoiceOnion", e)
                    false
                }
            }

            if (success) {
                Log.i(TAG, "✓ Call offer sent via HTTP POST successfully: $callId")
            } else {
                Log.e(TAG, "✗ RustBridge.sendHttpToVoiceOnion failed for call: $callId")
                Log.e(TAG, "  HTTP POST to voice .onion failed - check Tor connection and voice service")
            }

            success

        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            Log.e(TAG, "⏱ Timeout sending call offer for call $callId - Tor circuit not ready")
            Log.e(TAG, "  sendMessageBlob took longer than 10 seconds - circuit establishment failed")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Exception in sendCallOffer for call $callId", e)
            false
        }
    }

    /**
     * Send call answer (accept call) via HTTP POST to voice .onion with timeout and retry logic
     * @param recipientX25519PublicKey Recipient's X25519 public key
     * @param recipientOnion Recipient's VOICE .onion address (for HTTP POST delivery)
     * @param callId Call ID from the offer
     * @param ephemeralPublicKey Our ephemeral X25519 public key for this call
     * @param voiceOnion Our voice .onion address (for voice streaming connection)
     * @param ourX25519PublicKey Our X25519 public key (for wire message format)
     * @return True if answer sent successfully
     */
    suspend fun sendCallAnswer(
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        callId: String,
        ephemeralPublicKey: ByteArray,
        voiceOnion: String,
        ourX25519PublicKey: ByteArray
    ): Boolean {
        return try {
            Log.d(TAG, "sendCallAnswer called:")
            Log.d(TAG, "  recipientOnion: $recipientOnion")
            Log.d(TAG, "  callId: $callId")
            Log.d(TAG, "  voiceOnion: $voiceOnion")
            Log.d(TAG, "  recipientX25519PublicKey size: ${recipientX25519PublicKey.size}")
            Log.d(TAG, "  ephemeralPublicKey size: ${ephemeralPublicKey.size}")

            val answerJson = JSONObject().apply {
                put("type", TYPE_CALL_ANSWER)
                put("callId", callId)
                put("ephemeralPublicKey", Base64.encodeToString(ephemeralPublicKey, Base64.NO_WRAP))
                put("voiceOnion", voiceOnion)
                put("timestamp", System.currentTimeMillis())
            }

            val message = answerJson.toString()
            Log.d(TAG, "Message JSON created: ${message.length} bytes")

            val encryptedMessage = RustBridge.encryptMessage(message, recipientX25519PublicKey)
            Log.d(TAG, "Message encrypted: ${encryptedMessage.size} bytes")

            // Retry logic for CALL_ANSWER over Tor
            // Balance between reliability and UX
            // Most Tor connections complete in <10s, but some take longer
            // 5 attempts with 15-second timeout = max 75 seconds worst case
            // But successful attempts will complete much faster (typically 2-10 seconds)
            val maxRetries = 5
            val timeoutMs = 15000L  // 15 seconds per attempt
            val baseBackoffMs = 500L
            val maxBackoffMs = 2000L
            val totalStartTime = System.currentTimeMillis()

            repeat(maxRetries) { attempt ->
                val attemptNum = attempt + 1
                val attemptStartTime = System.currentTimeMillis()

                try {
                    Log.i(TAG, "CALL_ANSWER_SEND_ATTEMPT $attemptNum start (timeout=${timeoutMs}ms) via HTTP POST")

                    // Try to send with timeout via HTTP POST to voice .onion
                    val success = kotlinx.coroutines.withTimeout(timeoutMs) {
                        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                            try {
                                val result = RustBridge.sendHttpToVoiceOnion(
                                    recipientOnion,
                                    ourX25519PublicKey,
                                    encryptedMessage
                                )
                                result
                            } catch (e: Exception) {
                                Log.e(TAG, "CALL_ANSWER_SEND_FAIL $attemptNum error_code=EXCEPTION elapsed_ms=${System.currentTimeMillis() - attemptStartTime}", e)
                                false
                            }
                        }
                    }

                    val elapsedMs = System.currentTimeMillis() - attemptStartTime

                    if (success) {
                        Log.i(TAG, "CALL_ANSWER_SEND_SUCCESS $attemptNum elapsed_ms=$elapsedMs")
                        return true
                    } else {
                        Log.w(TAG, "CALL_ANSWER_SEND_FAIL $attemptNum error_code=FALSE_RETURN elapsed_ms=$elapsedMs")
                        if (attemptNum < maxRetries) {
                            // Exponential backoff: 200ms * 2^(i-1), capped at 2000ms
                            val backoffMs = kotlin.math.min(baseBackoffMs * (1 shl (attemptNum - 1)), maxBackoffMs)
                            Log.i(TAG, "Backoff ${backoffMs}ms before retry...")
                            kotlinx.coroutines.delay(backoffMs)
                        }
                    }

                } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                    val elapsedMs = System.currentTimeMillis() - attemptStartTime
                    Log.w(TAG, "CALL_ANSWER_SEND_TIMEOUT $attemptNum elapsed_ms=$elapsedMs")
                    if (attemptNum < maxRetries) {
                        // Exponential backoff
                        val backoffMs = kotlin.math.min(baseBackoffMs * (1 shl (attemptNum - 1)), maxBackoffMs)
                        Log.i(TAG, "Backoff ${backoffMs}ms before retry...")
                        kotlinx.coroutines.delay(backoffMs)
                    }
                } catch (e: Exception) {
                    val elapsedMs = System.currentTimeMillis() - attemptStartTime
                    Log.e(TAG, "CALL_ANSWER_SEND_FAIL $attemptNum error_code=EXCEPTION elapsed_ms=$elapsedMs", e)
                    if (attemptNum < maxRetries) {
                        val backoffMs = kotlin.math.min(baseBackoffMs * (1 shl (attemptNum - 1)), maxBackoffMs)
                        Log.i(TAG, "Backoff ${backoffMs}ms before retry...")
                        kotlinx.coroutines.delay(backoffMs)
                    }
                }
            }

            // All retries exhausted
            val totalElapsedMs = System.currentTimeMillis() - totalStartTime
            Log.e(TAG, "CALL_ANSWER_SEND_GIVEUP attempts=$maxRetries total_elapsed_ms=$totalElapsedMs")
            false

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected exception in sendCallAnswer for call $callId", e)
            false
        }
    }

    /**
     * Send call rejection
     */
    fun sendCallReject(
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        callId: String,
        reason: String = "User declined"
    ): Boolean {
        try {
            val rejectJson = JSONObject().apply {
                put("type", TYPE_CALL_REJECT)
                put("callId", callId)
                put("reason", reason)
                put("timestamp", System.currentTimeMillis())
            }

            val message = rejectJson.toString()
            val encryptedMessage = RustBridge.encryptMessage(message, recipientX25519PublicKey)

            val success = RustBridge.sendMessageBlob(
                recipientOnion,
                encryptedMessage,
                MSG_TYPE_CALL_SIGNALING
            )

            if (success) {
                Log.i(TAG, "Call reject sent: $callId")
            }

            return success

        } catch (e: Exception) {
            Log.e(TAG, "Error sending call reject", e)
            return false
        }
    }

    /**
     * Send call end notification
     */
    fun sendCallEnd(
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        callId: String,
        reason: String = "Call ended"
    ): Boolean {
        try {
            val endJson = JSONObject().apply {
                put("type", TYPE_CALL_END)
                put("callId", callId)
                put("reason", reason)
                put("timestamp", System.currentTimeMillis())
            }

            val message = endJson.toString()
            val encryptedMessage = RustBridge.encryptMessage(message, recipientX25519PublicKey)

            val success = RustBridge.sendMessageBlob(
                recipientOnion,
                encryptedMessage,
                MSG_TYPE_CALL_SIGNALING
            )

            if (success) {
                Log.i(TAG, "Call end sent: $callId")
            }

            return success

        } catch (e: Exception) {
            Log.e(TAG, "Error sending call end", e)
            return false
        }
    }

    /**
     * Send "busy" response (already on another call)
     */
    fun sendCallBusy(
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        callId: String
    ): Boolean {
        try {
            val busyJson = JSONObject().apply {
                put("type", TYPE_CALL_BUSY)
                put("callId", callId)
                put("timestamp", System.currentTimeMillis())
            }

            val message = busyJson.toString()
            val encryptedMessage = RustBridge.encryptMessage(message, recipientX25519PublicKey)

            val success = RustBridge.sendMessageBlob(
                recipientOnion,
                encryptedMessage,
                MSG_TYPE_CALL_SIGNALING
            )

            if (success) {
                Log.i(TAG, "Call busy sent: $callId")
            }

            return success

        } catch (e: Exception) {
            Log.e(TAG, "Error sending call busy", e)
            return false
        }
    }

    /**
     * Parse call signaling message
     * @param decryptedMessage The decrypted message JSON string
     * @return CallSignalingMessage or null if not a call signaling message
     */
    fun parseCallMessage(decryptedMessage: String): CallSignalingMessage? {
        try {
            val json = JSONObject(decryptedMessage)

            val type = json.optString("type")
            if (type !in listOf(TYPE_CALL_OFFER, TYPE_CALL_ANSWER, TYPE_CALL_REJECT, TYPE_CALL_END, TYPE_CALL_BUSY)) {
                return null // Not a call signaling message
            }

            val callId = json.getString("callId")
            val timestamp = json.getLong("timestamp")

            return when (type) {
                TYPE_CALL_OFFER -> {
                    val ephemeralKeyBase64 = json.getString("ephemeralPublicKey")
                    val ephemeralKey = Base64.decode(ephemeralKeyBase64, Base64.NO_WRAP)
                    val voiceOnion = json.getString("voiceOnion")
                    val numCircuits = json.getInt("numCircuits")

                    CallSignalingMessage.CallOffer(
                        callId = callId,
                        ephemeralPublicKey = ephemeralKey,
                        voiceOnion = voiceOnion,
                        numCircuits = numCircuits,
                        timestamp = timestamp
                    )
                }

                TYPE_CALL_ANSWER -> {
                    val ephemeralKeyBase64 = json.getString("ephemeralPublicKey")
                    val ephemeralKey = Base64.decode(ephemeralKeyBase64, Base64.NO_WRAP)
                    val voiceOnion = json.getString("voiceOnion")

                    CallSignalingMessage.CallAnswer(
                        callId = callId,
                        ephemeralPublicKey = ephemeralKey,
                        voiceOnion = voiceOnion,
                        timestamp = timestamp
                    )
                }

                TYPE_CALL_REJECT -> {
                    val reason = json.optString("reason", "User declined")

                    CallSignalingMessage.CallReject(
                        callId = callId,
                        reason = reason,
                        timestamp = timestamp
                    )
                }

                TYPE_CALL_END -> {
                    val reason = json.optString("reason", "Call ended")

                    CallSignalingMessage.CallEnd(
                        callId = callId,
                        reason = reason,
                        timestamp = timestamp
                    )
                }

                TYPE_CALL_BUSY -> {
                    CallSignalingMessage.CallBusy(
                        callId = callId,
                        timestamp = timestamp
                    )
                }

                else -> null
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error parsing call message", e)
            return null
        }
    }

    /**
     * Sealed class representing call signaling messages
     */
    sealed class CallSignalingMessage {
        data class CallOffer(
            val callId: String,
            val ephemeralPublicKey: ByteArray,
            val voiceOnion: String,
            val numCircuits: Int,
            val timestamp: Long
        ) : CallSignalingMessage() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as CallOffer

                if (callId != other.callId) return false
                if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
                if (voiceOnion != other.voiceOnion) return false
                if (numCircuits != other.numCircuits) return false
                if (timestamp != other.timestamp) return false

                return true
            }

            override fun hashCode(): Int {
                var result = callId.hashCode()
                result = 31 * result + ephemeralPublicKey.contentHashCode()
                result = 31 * result + voiceOnion.hashCode()
                result = 31 * result + numCircuits
                result = 31 * result + timestamp.hashCode()
                return result
            }
        }

        data class CallAnswer(
            val callId: String,
            val ephemeralPublicKey: ByteArray,
            val voiceOnion: String,
            val timestamp: Long
        ) : CallSignalingMessage() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as CallAnswer

                if (callId != other.callId) return false
                if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
                if (voiceOnion != other.voiceOnion) return false
                if (timestamp != other.timestamp) return false

                return true
            }

            override fun hashCode(): Int {
                var result = callId.hashCode()
                result = 31 * result + ephemeralPublicKey.contentHashCode()
                result = 31 * result + voiceOnion.hashCode()
                result = 31 * result + timestamp.hashCode()
                return result
            }
        }

        data class CallReject(
            val callId: String,
            val reason: String,
            val timestamp: Long
        ) : CallSignalingMessage()

        data class CallEnd(
            val callId: String,
            val reason: String,
            val timestamp: Long
        ) : CallSignalingMessage()

        data class CallBusy(
            val callId: String,
            val timestamp: Long
        ) : CallSignalingMessage()
    }
}
