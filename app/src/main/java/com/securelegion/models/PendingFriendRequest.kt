package com.securelegion.models

import org.json.JSONObject
import java.util.UUID

/**
 * Local tracking of friend requests (both outgoing and incoming)
 * This is different from FriendRequest which is just the wire protocol message
 */
data class PendingFriendRequest(
    val displayName: String,
    val ipfsCid: String,
    val direction: String, // "outgoing" or "incoming"
    val status: String, // "pending", "accepted", "failed", "sending"
    val timestamp: Long = System.currentTimeMillis(),
    // Store contact card data for outgoing requests (so we can add to Contacts when accepted)
    val contactCardJson: String? = null,
    val id: String = UUID.randomUUID().toString()
) {
    companion object {
        const val DIRECTION_OUTGOING = "outgoing"
        const val DIRECTION_INCOMING = "incoming"

        const val STATUS_PENDING = "pending"
        const val STATUS_ACCEPTED = "accepted"
        const val STATUS_FAILED = "failed"
        const val STATUS_SENDING = "sending"

        fun fromJson(json: String): PendingFriendRequest {
            val obj = JSONObject(json)
            return PendingFriendRequest(
                displayName = obj.getString("display_name"),
                ipfsCid = obj.getString("ipfs_cid"),
                direction = obj.getString("direction"),
                status = obj.getString("status"),
                timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
                contactCardJson = if (obj.has("contact_card_json")) obj.getString("contact_card_json") else null,
                id = obj.optString("id", UUID.randomUUID().toString())
            )
        }
    }

    fun toJson(): String {
        return JSONObject().apply {
            put("id", id)
            put("display_name", displayName)
            put("ipfs_cid", ipfsCid)
            put("direction", direction)
            put("status", status)
            put("timestamp", timestamp)
            if (contactCardJson != null) {
                put("contact_card_json", contactCardJson)
            }
        }.toString()
    }
}
