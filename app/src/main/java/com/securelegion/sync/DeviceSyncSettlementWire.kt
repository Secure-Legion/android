package com.securelegion.sync

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** Exact build-48 application response, parsed after authenticated frame decode. */
internal object DeviceSyncSettlementWire {
    enum class Kind { SETTLED, TRANSPORT_SKIPPED }
    data class Response(val kind: Kind, val topic: String, val objectId: String,
                        val eventId: String, val digestHex: String, val eventTimeMs: Long)

    private val settledFields = setOf("kind", "history_v", "event_id", "digest",
        "topic", "object_id", "event_ts")
    private val skippedFields = settledFields + "policy"
    private val topics = setOf("messages", "receipts", "contacts", "settings", "groups", "group_links")
    private val torTopics = setOf("contacts", "settings", "group_links")
    private val hex64 = Regex("[0-9a-f]{64}")

    fun parse(payload: JSONObject): Response {
        val kind = when (payload.optString("kind")) {
            "settled" -> Kind.SETTLED
            "transport_skipped" -> Kind.TRANSPORT_SKIPPED
            else -> throw IllegalArgumentException("Unknown sync response")
        }
        require(payload.keys().asSequence().toSet() ==
            if (kind == Kind.SETTLED) settledFields else skippedFields)
        require(payload.opt("history_v") == 2 && payload.opt("history_v") is Int)
        if (kind == Kind.TRANSPORT_SKIPPED) {
            require(payload.getString("policy") == "tor_metadata_only_v1")
        }
        val topic = payload.getString("topic")
        val objectId = payload.getString("object_id")
        val eventId = payload.getString("event_id")
        val digest = payload.getString("digest")
        val time = payload.opt("event_ts")
        require(topic in topics && (kind != Kind.TRANSPORT_SKIPPED || topic !in torTopics))
        require(objectId.isNotEmpty() && objectId.length <= 256)
        require(hex64.matches(eventId) && hex64.matches(digest))
        require(time is Int || time is Long)
        val timestamp = (time as Number).toLong()
        require(timestamp in 1..9_007_199_254_740_991L)
        val transcript = JSONArray().put("secure-sync-history-v2").put(topic)
            .put(objectId).put(timestamp).put(digest).toString().toByteArray(Charsets.UTF_8)
        val expected = MessageDigest.getInstance("SHA-256").digest(transcript)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        require(expected == eventId)
        return Response(kind, topic, objectId, eventId, digest, timestamp)
    }
}
