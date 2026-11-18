package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceSyncPushWireTest {
    private val peer = "P".repeat(43)
    private val local = "L".repeat(43)
    private val now = 1_792_400_000_000L

    @Test fun liveReceiptRequiresNegotiationAndExactMarker() {
        val payload = base("receipts").put("sync_mode", "live_v1")
            .put("delta", JSONObject().put("message_id", "m1").put("status", 2))
        val part = DeviceSyncPushWire.parse(frame(payload), true, now)
        assertEquals("receipts", part.topic)
        assertEquals("m1", part.objectId)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncPushWire.parse(frame(payload), false, now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncPushWire.parse(frame(JSONObject(payload.toString()).apply {
                remove("sync_mode")
            }), true, now)
        }
    }

    @Test fun rejectsBulkMessageAndMalformedChunk() {
        val bulk = base("messages").put("delta", JSONObject().put("message_id", "m1"))
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncPushWire.parse(frame(bulk), true, now)
        }
        val chunk = base("receipts").put("sync_mode", "live_v1")
            .put("chunk_id", "wrong").put("chunk_seq", 0)
            .put("chunk_total", 1).put("chunk_bytes", "e30=")
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncPushWire.parse(frame(chunk), true, now)
        }
    }

    private fun base(topic: String) = JSONObject().put("history_v", 2)
        .put("event_id", "a".repeat(64)).put("digest", "b".repeat(64))
        .put("topic", topic).put("object_id", "m1")
        .put("event_ts", now).put("seq", 1)

    private fun frame(payload: JSONObject) = DeviceSyncFrameV2.Frame(
        DeviceSyncFrameV2.Kind.PUSH, peer, local, now, payload, ByteArray(32))
}
