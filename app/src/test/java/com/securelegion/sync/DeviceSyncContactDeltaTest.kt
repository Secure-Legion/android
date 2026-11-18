package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class DeviceSyncContactDeltaTest {
    private val now = 1_792_400_000_000L
    private val ed = Base64.getEncoder().encodeToString(ByteArray(32) { 1 })
    private val x = Base64.getEncoder().encodeToString(ByteArray(32) { 2 })

    @Test fun acceptsPinnedIdentityAndDeletion() {
        val contact = DeviceSyncContactDelta.parse(upsert(), now)
        assertEquals("Alice", contact.displayName)
        assertEquals(false, contact.deleted)
        val deletion = DeviceSyncContactDelta.parse(JSONObject().put("public_key", ed)
            .put("deleted", true), now)
        assertEquals(true, deletion.deleted)
    }

    @Test fun rejectsKeyRebindHintsAndExtraFields() {
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncContactDelta.parse(upsert().put("x25519_pub", ed.dropLast(1)), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncContactDelta.parse(upsert().put("solana_address", "invented"), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncContactDelta.parse(upsert().put("profile_version",
                JSONObject().put("timestamp", now).put("event_id", "v1")), now)
        }
    }

    @Test fun acceptsOnlyCanonicalBoundedPublicRosterBytes() {
        val roster = ByteArray(64) { it.toByte() }
        val encoded = Base64.getEncoder().encodeToString(roster)
        assertArrayEquals(roster, DeviceSyncContactDelta.parse(
            upsert().put("device_roster", encoded), now).deviceRoster)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncContactDelta.parse(upsert().put("device_roster", encoded.trimEnd('=')), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncContactDelta.parse(upsert().put("device_roster",
                Base64.getEncoder().encodeToString(ByteArray(32 * 1024 + 1))), now)
        }
    }

    private fun upsert() = JSONObject().put("public_key", ed).put("x25519_pub", x)
        .put("display_name", "Alice").put("messaging_onion", JSONObject.NULL)
        .put("friend_request_onion", JSONObject.NULL).put("friendship_status", 3)
        .put("created_at", now - 1_000)
}
