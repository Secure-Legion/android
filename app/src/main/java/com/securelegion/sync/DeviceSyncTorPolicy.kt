package com.securelegion.sync

import org.json.JSONObject

/** Build-49 direct live lane; callers may set livePeer only after mutual HELLO negotiation. */
internal object DeviceSyncTorPolicy {
    const val LIVE_CAPABILITY = "live_message_sync_v1"
    const val LIVE_MODE = "live_v1"
    val metadataTopics = setOf("contacts", "settings")
    val liveTopics = setOf("messages", "receipts")

    fun allows(kind: DeviceSyncFrameV2.Kind, payload: JSONObject, livePeer: Boolean): Boolean {
        if (payload.has("group_action_v")) return false
        return when (kind) {
            DeviceSyncFrameV2.Kind.PUSH -> {
                val topic = payload.optString("topic")
                topic in metadataTopics && !payload.has("sync_mode") ||
                    topic in liveTopics && livePeer &&
                    payload.optString("sync_mode") == LIVE_MODE &&
                    payload.opt("history_v") is Int && payload.optInt("history_v") == 2
            }
            DeviceSyncFrameV2.Kind.PULL_RESPONSE -> when (payload.optString("kind")) {
                "transport_skipped" -> true
                "settled" -> payload.optString("topic") in metadataTopics ||
                    livePeer && payload.optString("topic") in liveTopics
                else -> false
            }
            DeviceSyncFrameV2.Kind.HELLO, DeviceSyncFrameV2.Kind.HELLO_ACK,
            DeviceSyncFrameV2.Kind.BYE -> true
            DeviceSyncFrameV2.Kind.PULL_REQUEST -> false
        }
    }

    /** Routing marker is never part of the canonical delta or its digest. */
    fun stripLiveMarker(payload: JSONObject): JSONObject {
        require(payload.optString("topic") in liveTopics &&
            payload.optString("sync_mode") == LIVE_MODE &&
            payload.opt("history_v") is Int && payload.optInt("history_v") == 2)
        return JSONObject(payload.toString()).apply { remove("sync_mode") }
    }
}
