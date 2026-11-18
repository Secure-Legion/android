package com.securelegion.sync

import com.securelegion.database.DeviceSyncOutboxStore
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceSyncOutboundWireTest {
    private val peer = "P".repeat(43)
    private val local = "L".repeat(43)
    private val now = 1_792_400_000_000L

    @Test fun singleAndChunkedSettingsKeepTheSameRevision() {
        val small = event(JSONObject().put("settings_id", "account:name")
            .put("version", 1).put("value", "Eddie").toString().toByteArray())
        val single = DeviceSyncOutboundWire.payloads(small)
        assertEquals(1, single.size)
        assertEquals("account:name", DeviceSyncPushWire.parse(frame(single[0]),
            false, now).objectId)

        val large = event(JSONObject().put("settings_id", "account:photo")
            .put("version", 1).put("value", "x".repeat(180_000))
            .toString().toByteArray(), "account:photo")
        val chunks = DeviceSyncOutboundWire.payloads(large)
        assertEquals(2, chunks.size)
        val parts = chunks.map { DeviceSyncPushWire.parse(frame(it), false, now) }
        assertEquals(listOf(0, 1), parts.map { it.index })
        assertArrayEquals(large.canonicalDelta, parts.flatMap { it.bytes.asIterable() }
            .toByteArray())
    }

    private fun event(delta: ByteArray, id: String = "account:name") =
        DeviceSyncOutboxStore.Event(peer, "settings", id, "a".repeat(64), now,
            ByteArray(32) { 0x31 }, 1, delta,
            DeviceSyncOutboxStore.Transport.TOR, 0, false)

    private fun frame(payload: JSONObject) = DeviceSyncFrameV2.Frame(
        DeviceSyncFrameV2.Kind.PUSH, peer, local, now, payload, ByteArray(32))
}
