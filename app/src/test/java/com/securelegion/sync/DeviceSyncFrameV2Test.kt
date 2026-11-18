package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceSyncFrameV2Test {
    private val local = "L".repeat(43)
    private val peer = "P".repeat(43)
    private val now = 1_792_400_000_000L
    private val wire = byteArrayOf(0xB7.toByte(), 0, 0, 0, 1, 2)

    @Test fun authenticatedV2FrameRoundTrips() {
        val plain = DeviceSyncFrameV2.encode(DeviceSyncFrameV2.Kind.PUSH,
            peer, local, JSONObject().put("topic", "contacts"), now)
        val result = DeviceSyncFrameV2.decode(plain, peer, local, wire, now)
        assertEquals(DeviceSyncFrameV2.Kind.PUSH, result.kind)
        assertEquals("contacts", result.payload.getString("topic"))
        assertEquals(32, result.exactWireHash.size)
    }

    @Test fun typeSenderAndIntegerMustMatchNoiseContext() {
        val plain = DeviceSyncFrameV2.encode(DeviceSyncFrameV2.Kind.PUSH,
            peer, local, JSONObject(), now)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncFrameV2.decode(plain, local, peer, wire, now)
        }
        val wrongKind = plain.copyOf().also { it[0] = 0xB3.toByte() }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncFrameV2.decode(wrongKind, peer, local, wire, now)
        }
        val floatVersion = plain.toString(Charsets.UTF_8).replace("\"v\":2", "\"v\":2.0")
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncFrameV2.decode(floatVersion.toByteArray(), peer, local, wire, now)
        }
    }
}
