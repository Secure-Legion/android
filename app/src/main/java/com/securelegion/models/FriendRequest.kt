package com.securelegion.models

import org.json.JSONObject

/**
 * Friend request data sent when someone adds you as a contact
 * Contains minimal info - just username and CID
 * Receiver must enter PIN to download full contact card from IPFS
 */
data class FriendRequest(
    val displayName: String,
    val ipfsCid: String,
    val timestamp: Long = System.currentTimeMillis()
) {
    companion object {
        // Wire protocol type byte for FRIEND_REQUEST
        const val WIRE_TYPE_FRIEND_REQUEST: Byte = 0x07

        /**
         * Deserialize from JSON
         */
        fun fromJson(json: String): FriendRequest {
            val obj = JSONObject(json)
            return FriendRequest(
                displayName = obj.getString("display_name"),
                ipfsCid = obj.getString("ipfs_cid"),
                timestamp = obj.optLong("timestamp", System.currentTimeMillis())
            )
        }
    }

    /**
     * Serialize to JSON for transmission
     */
    fun toJson(): String {
        return JSONObject().apply {
            put("display_name", displayName)
            put("ipfs_cid", ipfsCid)
            put("timestamp", timestamp)
        }.toString()
    }
}
