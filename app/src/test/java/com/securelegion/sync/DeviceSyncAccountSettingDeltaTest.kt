package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceSyncAccountSettingDeltaTest {
    @Test fun acceptsNameAndRemovedPhoto() {
        assertEquals("Eddie", DeviceSyncAccountSettingDelta.parse(
            delta("account:name", "Eddie")).value)
        assertEquals(null, DeviceSyncAccountSettingDelta.parse(
            delta("account:photo", JSONObject.NULL)).value)
    }

    @Test fun rejectsLocalSettingAndInvalidName() {
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncAccountSettingDelta.parse(delta("device:tor_bridge", "x"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncAccountSettingDelta.parse(delta("account:name", " Eddie "))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncAccountSettingDelta.parse(delta("account:name", "Hi\nthere"))
        }
    }

    private fun delta(id: String, value: Any) = JSONObject().put("settings_id", id)
        .put("version", 1).put("value", value)
}
