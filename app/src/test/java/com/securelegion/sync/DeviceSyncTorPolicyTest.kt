package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceSyncTorPolicyTest {
    private fun push(topic: String) = JSONObject().put("topic", topic).put("history_v", 2)

    @Test fun liveMessageRequiresExplicitModeAndNegotiation() {
        val live = push("messages").put("sync_mode", "live_v1")
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH, live, false))
        assertTrue(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH, live, true))
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("messages"), true))
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("messages").put("sync_mode", "live_v1").put("history_v", 1), true))
        assertFalse(DeviceSyncTorPolicy.stripLiveMarker(live).has("sync_mode"))
    }

    @Test fun groupRelayAndUnmarkedArchiveStayClosed() {
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("groups").put("sync_mode", "live_v1"), true))
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PULL_REQUEST,
            JSONObject().put("topic", "groups"), true))
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("contacts").put("group_action_v", 1), true))
        assertTrue(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("contacts"), false))
        assertTrue(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("group_links"), false))
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("group_links").put("sync_mode", "live_v1"), true))
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PUSH,
            push("contacts").put("sync_mode", "live_v1"), true))
    }

    @Test fun settledLiveReplyRequiresNegotiation() {
        val settled = JSONObject().put("kind", "settled").put("topic", "messages")
        assertFalse(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PULL_RESPONSE, settled, false))
        assertTrue(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PULL_RESPONSE, settled, true))
        val skipped = JSONObject().put("kind", "transport_skipped").put("topic", "messages")
        assertTrue(DeviceSyncTorPolicy.allows(DeviceSyncFrameV2.Kind.PULL_RESPONSE, skipped, false))
    }
}
