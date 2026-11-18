package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceSyncHelloWireTest {
    @Test fun acceptsExactCapabilitiesAndCursorPayload() {
        val payload = DeviceSyncHelloWire.payload(setOf("tor_metadata_only_v1"),
            mapOf("contacts" to (3L to 5L)))
        val parsed = DeviceSyncHelloWire.parse(payload)
        assertEquals(setOf("tor_metadata_only_v1"), parsed.capabilities)
        assertEquals(5L, parsed.received["contacts"])
        assertEquals(0L, parsed.received["group_links"])
    }

    @Test fun rejectsDuplicateCapabilitiesAndFractionalCursor() {
        val duplicate = DeviceSyncHelloWire.payload(emptySet(), emptyMap())
        duplicate.getJSONArray("capabilities").put("x").put("x")
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncHelloWire.parse(duplicate)
        }
        val fractional = DeviceSyncHelloWire.payload(emptySet(), emptyMap())
        fractional.getJSONObject("cursors").getJSONObject("contacts").put("received", 1.5)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncHelloWire.parse(fractional)
        }
    }

    @Test fun oldPeerMayOmitOnlyGroupLinks() {
        val old = DeviceSyncHelloWire.payload(emptySet(), emptyMap())
        old.getJSONObject("cursors").remove("group_links")
        assertEquals(0L, DeviceSyncHelloWire.parse(old).received["group_links"])
        old.getJSONObject("cursors").remove("contacts")
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncHelloWire.parse(JSONObject(old.toString()))
        }
    }
}
