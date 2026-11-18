package com.securelegion.sync

import com.securelegion.database.DeviceSyncChunkStore
import org.json.JSONObject
import java.util.Base64

/** Exact authenticated history-v2 PUSH envelope. Application import is separate. */
internal object DeviceSyncPushWire {
    private val base = setOf("history_v", "event_id", "digest", "topic", "object_id",
        "event_ts", "seq")
    private val single = base + "delta"
    private val chunk = base + setOf("chunk_id", "chunk_seq", "chunk_total", "chunk_bytes")
    private val hex64 = Regex("[0-9a-f]{64}")

    fun parse(frame: DeviceSyncFrameV2.Frame, liveNegotiated: Boolean,
              nowMs: Long = System.currentTimeMillis()): DeviceSyncChunkStore.Part {
        require(frame.kind == DeviceSyncFrameV2.Kind.PUSH)
        val payload = frame.payload
        val topic = payload.getString("topic")
        val live = topic in DeviceSyncTorPolicy.liveTopics
        require(topic in DeviceSyncTorPolicy.metadataTopics || live)
        require(!live || liveNegotiated)
        val fields = payload.keys().asSequence().toSet()
        val expected = if (payload.has("chunk_id")) chunk else single
        require(fields == if (live) expected + "sync_mode" else expected)
        if (live) require(payload.getString("sync_mode") == DeviceSyncTorPolicy.LIVE_MODE)
        require(integer(payload.opt("history_v")) == 2L)
        val eventId = payload.getString("event_id")
        val digest = payload.getString("digest")
        val objectId = payload.getString("object_id")
        val eventTime = integer(payload.opt("event_ts"))
        val sequence = integer(payload.opt("seq"))
        require(hex64.matches(eventId) && hex64.matches(digest) &&
            objectId.isNotEmpty() && objectId.length <= 256 && sequence > 0 &&
            eventTime in 1..9_007_199_254_740_991L && eventTime <= nowMs + 300_000)
        val index: Int
        val total: Int
        val data: ByteArray
        if (payload.has("chunk_id")) {
            require(payload.getString("chunk_id") == "hist:$eventId")
            index = integer(payload.opt("chunk_seq")).toIntExact()
            total = integer(payload.opt("chunk_total")).toIntExact()
            val encoded = payload.getString("chunk_bytes")
            require(encoded.length <= 174_764)
            data = Base64.getDecoder().decode(encoded)
            require(data.isNotEmpty() && data.size <= 128 * 1024 &&
                Base64.getEncoder().encodeToString(data) == encoded)
        } else {
            index = 0
            total = 1
            data = payload.getJSONObject("delta").toString().toByteArray(Charsets.UTF_8)
            require(data.size in 2..128 * 1024)
        }
        require(total in 1..64 && index in 0 until total)
        return DeviceSyncChunkStore.Part(frame.sender, topic, objectId, eventId, digest,
            eventTime, sequence, index, total, data)
    }

    fun settled(part: DeviceSyncChunkStore.Part): JSONObject = JSONObject()
        .put("kind", "settled").put("history_v", 2).put("event_id", part.eventId)
        .put("digest", part.digestHex).put("topic", part.topic)
        .put("object_id", part.objectId).put("event_ts", part.eventTimeMs)
        .also { DeviceSyncSettlementWire.parse(it) }

    fun transportSkipped(payload: JSONObject, nowMs: Long = System.currentTimeMillis()): JSONObject {
        val response = JSONObject().put("kind", "transport_skipped")
            .put("policy", "tor_metadata_only_v1").put("history_v", payload.opt("history_v"))
            .put("event_id", payload.opt("event_id")).put("digest", payload.opt("digest"))
            .put("topic", payload.opt("topic")).put("object_id", payload.opt("object_id"))
            .put("event_ts", payload.opt("event_ts"))
        val parsed = DeviceSyncSettlementWire.parse(response)
        require(parsed.eventTimeMs <= nowMs + 300_000L)
        return response
    }

    private fun integer(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong()
    }

    private fun Long.toIntExact(): Int {
        require(this in Int.MIN_VALUE..Int.MAX_VALUE)
        return toInt()
    }
}
