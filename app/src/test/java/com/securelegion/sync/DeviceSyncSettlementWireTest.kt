package com.securelegion.sync

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.MessageDigest

class DeviceSyncSettlementWireTest {
    private val time = 1_792_400_000_000L
    private val digest = "a".repeat(64)
    private fun payload(topic: String, kind: String): JSONObject {
        val event = MessageDigest.getInstance("SHA-256").digest(
            JSONArray().put("secure-sync-history-v2").put(topic).put("object:1")
                .put(time).put(digest).toString().toByteArray()
        ).joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return JSONObject().put("kind", kind).put("history_v", 2)
            .put("event_id", event).put("digest", digest).put("topic", topic)
            .put("object_id", "object:1").put("event_ts", time)
    }

    @Test fun exactSkipAndSettlement() {
        assertEquals(DeviceSyncSettlementWire.Kind.SETTLED,
            DeviceSyncSettlementWire.parse(payload("contacts", "settled")).kind)
        assertEquals(DeviceSyncSettlementWire.Kind.TRANSPORT_SKIPPED,
            DeviceSyncSettlementWire.parse(payload("messages", "transport_skipped")
                .put("policy", "tor_metadata_only_v1")).kind)
    }

    @Test fun forgedOrMisclassifiedResponsesFail() {
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncSettlementWire.parse(payload("messages", "transport_skipped")
                .put("policy", "tor_metadata_only_v1").put("digest", "b".repeat(64)))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncSettlementWire.parse(payload("contacts", "transport_skipped")
                .put("policy", "tor_metadata_only_v1"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncSettlementWire.parse(payload("messages", "settled").put("extra", true))
        }
    }
}
