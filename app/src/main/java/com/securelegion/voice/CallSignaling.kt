package com.securelegion.voice

import android.util.Base64
import android.util.Log
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
     * Send call offer to recipient
     * @param recipientX25519PublicKey Recipient's X25519 public key (for message encryption)
     * @param recipientOnion Recipient's .onion address
     * @param callId Unique call ID
     * @param ephemeralPublicKey Our ephemeral X25519 public key for this call
     * @param numCircuits Number of Tor circuits to use (1 for Phase 1, 3-5 for Phase 2)
     * @return True if offer sent successfully
     */
    fun sendCallOffer(
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        callId: String,
        ephemeralPublicKey: ByteArray,
        numCircuits: Int = 1
    ): Boolean {
        try {
            // Create call offer JSON
            val offerJson = JSONObject().apply {
                put("type", TYPE_CALL_OFFER)
                put("callId", callId)
                put("ephemeralPublicKey", Base64.encodeToString(ephemeralPublicKey, Base64.NO_WRAP))
                put("numCircuits", numCircuits)
                put("timestamp", System.currentTimeMillis())
            }

            val message = offerJson.toString()

            // Encrypt message
            val encryptedMessage = RustBridge.encryptMessage(message, recipientX25519PublicKey)

            // Send via MESSAGE protocol with CALL_SIGNALING type
            val success = RustBridge.sendMessageBlob(
                recipientOnion,
                encryptedMessage,
                MSG_TYPE_CALL_SIGNALING
            )

            if (success) {
                Log.i(TAG, "Call offer sent: $callId")
            } else {
                Log.e(TAG, "Failed to send call offer: $callId")
            }

            return success

        } catch (e: Exception) {
            Log.e(TAG, "Error sending call offer", e)
            return false
        }
    }

    /**
     * Send call answer (accept call)
     * @param recipientX25519PublicKey Recipient's X25519 public key
     * @param recipientOnion Recipient's .onion address
     * @param callId Call ID from the offer
     * @param ephemeralPublicKey Our ephemeral X25519 public key for this call
     * @return True if answer sent successfully
     */
    fun sendCallAnswer(
        recipientX25519PublicKey: ByteArray,
        recipientOnion: String,
        callId: String,
        ephemeralPublicKey: ByteArray
    ): Boolean {
        try {
            val answerJson = JSONObject().apply {
                put("type", TYPE_CALL_ANSWER)
                put("callId", callId)
                put("ephemeralPublicKey", Base64.encodeToString(ephemeralPublicKey, Base64.NO_WRAP))
                put("timestamp", System.currentTimeMillis())
            }

            val message = answerJson.toString()
            val encryptedMessage = RustBridge.encryptMessage(message, recipientX25519PublicKey)

            val success = RustBridge.sendMessageBlob(
                recipientOnion,
                encryptedMessage,
                MSG_TYPE_CALL_SIGNALING
            )

            if (success) {
                Log.i(TAG, "Call answer sent: $callId")
            } else {
                Log.e(TAG, "Failed to send call answer: $callId")
            }

            return success

        } catch (e: Exception) {
            Log.e(TAG, "Error sending call answer", e)
            return false
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
                    val numCircuits = json.getInt("numCircuits")

                    CallSignalingMessage.CallOffer(
                        callId = callId,
                        ephemeralPublicKey = ephemeralKey,
                        numCircuits = numCircuits,
                        timestamp = timestamp
                    )
                }

                TYPE_CALL_ANSWER -> {
                    val ephemeralKeyBase64 = json.getString("ephemeralPublicKey")
                    val ephemeralKey = Base64.decode(ephemeralKeyBase64, Base64.NO_WRAP)

                    CallSignalingMessage.CallAnswer(
                        callId = callId,
                        ephemeralPublicKey = ephemeralKey,
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
            val numCircuits: Int,
            val timestamp: Long
        ) : CallSignalingMessage() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as CallOffer

                if (callId != other.callId) return false
                if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
                if (numCircuits != other.numCircuits) return false
                if (timestamp != other.timestamp) return false

                return true
            }

            override fun hashCode(): Int {
                var result = callId.hashCode()
                result = 31 * result + ephemeralPublicKey.contentHashCode()
                result = 31 * result + numCircuits
                result = 31 * result + timestamp.hashCode()
                return result
            }
        }

        data class CallAnswer(
            val callId: String,
            val ephemeralPublicKey: ByteArray,
            val timestamp: Long
        ) : CallSignalingMessage() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as CallAnswer

                if (callId != other.callId) return false
                if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
                if (timestamp != other.timestamp) return false

                return true
            }

            override fun hashCode(): Int {
                var result = callId.hashCode()
                result = 31 * result + ephemeralPublicKey.contentHashCode()
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
