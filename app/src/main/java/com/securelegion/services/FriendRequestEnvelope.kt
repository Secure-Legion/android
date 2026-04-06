package com.securelegion.services

import android.util.Base64
import org.json.JSONObject

/**
 * Phase 1 friend-request envelope (schema version 2).
 *
 * Carries the recipient's invite_token (echoed back from their QR) + a fresh nonce + timestamp,
 * wrapped INSIDE the existing PIN-encrypted blob on the wire. Sender builds the envelope string,
 * then the caller PIN-encrypts it. Receiver PIN-decrypts and then calls parse() on the plaintext.
 */
data class FriendRequestEnvelope(
    val inviteToken: String,
    val nonce: String,
    val timestampSec: Long,
    val senderCardJson: String
) {
    companion object {
        const val TYPE = "friend_request"
        const val VERSION = 2
        const val NONCE_SIZE_BYTES = 24

        /**
         * Build and serialize an envelope. Generates a fresh CSPRNG nonce.
         *
         * @param recipientInviteToken the token copied from the recipient's QR (32 hex chars).
         * @param senderCardJson the sender's own ContactCard v4 JSON string.
         * @param timestampSec unix seconds (caller can inject for tests).
         */
        fun build(
            recipientInviteToken: String,
            senderCardJson: String,
            timestampSec: Long = System.currentTimeMillis() / 1000
        ): String {
            val nonceBytes = ByteArray(NONCE_SIZE_BYTES)
            java.security.SecureRandom().nextBytes(nonceBytes)
            val nonceB64 = Base64.encodeToString(nonceBytes, Base64.NO_WRAP)

            val json = JSONObject()
            json.put("type", TYPE)
            json.put("version", VERSION)
            json.put("invite_token", recipientInviteToken)
            json.put("nonce", nonceB64)
            json.put("timestamp", timestampSec)
            json.put("sender_card", JSONObject(senderCardJson))
            return json.toString()
        }

        /**
         * Parse an envelope JSON string. Returns null on any schema violation — no detailed
         * error reporting to avoid leaking info to attackers.
         */
        fun parse(jsonString: String): FriendRequestEnvelope? {
            return try {
                val json = JSONObject(jsonString)
                if (json.optString("type") != TYPE) return null
                if (json.optInt("version", 0) != VERSION) return null
                val token = json.optString("invite_token", "")
                if (token.length != 32) return null
                val nonce = json.optString("nonce", "")
                if (nonce.isBlank()) return null
                val ts = json.optLong("timestamp", -1L)
                if (ts < 0) return null
                val senderCard = json.optJSONObject("sender_card") ?: return null
                FriendRequestEnvelope(token, nonce, ts, senderCard.toString())
            } catch (e: Exception) {
                null
            }
        }
    }
}
