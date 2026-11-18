package com.securelegion.sync

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceSyncPeerHelloTest {
    @Test fun parsesExactIosCursorsAndMissingLegacyGroupLinks() {
        val payload = DeviceSyncPeerHello.emptyLocal()
        payload.getJSONArray("capabilities").put("tor_metadata_only_v1")
        payload.getJSONObject("cursors").remove("group_links")
        val peer = DeviceSyncPeerHello.parse(payload)
        assertEquals(setOf("tor_metadata_only_v1"), peer.capabilities)
        assertEquals(0L, peer.received["group_links"])
    }

    @Test fun rejectsDuplicateCapabilitiesAndNonintegerCursor() {
        val duplicate = DeviceSyncPeerHello.emptyLocal()
        duplicate.put("capabilities", JSONArray().put("live_message_sync_v1")
            .put("live_message_sync_v1"))
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncPeerHello.parse(duplicate)
        }
        val floatCursor = DeviceSyncPeerHello.emptyLocal()
        floatCursor.getJSONObject("cursors").getJSONObject("messages")
            .put("received", 1.5)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncPeerHello.parse(floatCursor)
        }
    }
}
