package com.securelegion.sync

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class DeviceSyncMessageDeltaTest {
    private val now = 1_792_400_000_000L

    @Test fun acceptsTextAndTombstoneWithoutDeliveryOwnership() {
        val parsed = DeviceSyncMessageDelta.parse(text(), now)
        assertEquals("msg-1", parsed.id)
        assertEquals("hello", parsed.content)
        assertEquals(false, parsed.deleted)
        assertEquals(true, parsed.sentByMe)
        assertEquals(true, DeviceSyncMessageDelta.parse(JSONObject()
            .put("message_id", "msg-1").put("deleted", true), now).deleted)
    }

    @Test fun rejectsUnvalidatedControlsAndInvalidMedia() {
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncMessageDelta.parse(text().put("control_versions",
                JSONArray().put(JSONObject().put("kind", 18))), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncMessageDelta.parse(text().put("message_type", "VOICE")
                .put("voice_data", "not base64"), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncMessageDelta.parse(text().put("status", 8), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncMessageDelta.parse(text().put("contact_x25519",
                Base64.getEncoder().encodeToString(ByteArray(31))), now)
        }
    }

    private fun text() = JSONObject().put("message_id", "msg-1")
        .put("contact_x25519", Base64.getEncoder().encodeToString(ByteArray(32) { 7 }))
        .put("message_type", "TEXT").put("is_sent_by_me", true)
        .put("timestamp", now - 1_000).put("status", 1).put("content", "hello")
        .put("attachment_type", JSONObject.NULL).put("attachment_data", JSONObject.NULL)
}
