package com.securelegion.sync

import com.securelegion.database.DeviceSyncOutboxStore
import org.json.JSONObject
import java.util.Base64

/** Immutable history-v2 PUSH payloads derived from one persisted outbox revision. */
internal object DeviceSyncOutboundWire {
    private const val CHUNK_BYTES = 128 * 1024

    fun payloads(event: DeviceSyncOutboxStore.Event): List<JSONObject> {
        require(event.eventId.matches(Regex("[0-9a-f]{64}")) &&
            event.digest.size == 32 && event.objectId.isNotEmpty() &&
            event.objectId.length <= 256 && event.sequence > 0 &&
            event.eventTimeMs > 0 && event.canonicalDelta.size in 2..8 * 1024 * 1024)
        val base = { JSONObject().put("history_v", 2).put("event_id", event.eventId)
            .put("digest", event.digest.toHex()).put("topic", event.topic)
            .put("object_id", event.objectId).put("event_ts", event.eventTimeMs)
            .put("seq", event.sequence) }
        if (event.canonicalDelta.size <= CHUNK_BYTES) {
            return listOf(base().put("delta", JSONObject(
                event.canonicalDelta.toString(Charsets.UTF_8))))
        }
        val count = (event.canonicalDelta.size + CHUNK_BYTES - 1) / CHUNK_BYTES
        require(count in 2..64)
        return (0 until count).map { index ->
            val start = index * CHUNK_BYTES
            val end = minOf(event.canonicalDelta.size, start + CHUNK_BYTES)
            val part = event.canonicalDelta.copyOfRange(start, end)
            base().put("chunk_id", "hist:${event.eventId}")
                .put("chunk_seq", index).put("chunk_total", count)
                .put("chunk_bytes", Base64.getEncoder().encodeToString(part))
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
