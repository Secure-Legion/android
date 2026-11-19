package com.securelegion.services

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OwnDeviceSyncPolicyTest {
    @Test fun reservedDeviceFramesCannotEnterContactParser() {
        for (type in 0xA3..0xA5) assertTrue(OwnDeviceSyncPolicy.isReservedNetworkType(type))
        for (type in 0xB0..0xB7) assertTrue(OwnDeviceSyncPolicy.isReservedNetworkType(type))
        assertTrue(OwnDeviceSyncPolicy.isReservedNetworkType(0xC0))
        assertTrue(OwnDeviceSyncPolicy.isReservedNetworkType(0xC2))
        for (type in listOf(0x03, 0x07, 0x30, 0x82))
            assertFalse(OwnDeviceSyncPolicy.isReservedNetworkType(type))
    }

    @Test fun torOnlyCarriesMetadataAndNeverFakesHistorySettlement() {
        for (topic in listOf("contacts", "settings", "group_links")) {
            assertTrue(OwnDeviceSyncPolicy.canSendTorTopic(topic))
            assertTrue(OwnDeviceSyncPolicy.canSettleTorEvent(topic, "settled"))
            assertFalse(OwnDeviceSyncPolicy.canSettleTorEvent(topic, "transport_skipped"))
        }
        for (topic in listOf("messages", "receipts", "groups", "typing", "media")) {
            assertFalse(OwnDeviceSyncPolicy.canSendTorTopic(topic))
            assertFalse(OwnDeviceSyncPolicy.canSettleTorEvent(topic, "settled"))
        }
    }

    @Test fun signedGroupMessageOperationsCannotMasqueradeAsLinks() {
        for (type in listOf("GroupCreate", "GroupDelete", "MemberInvite", "MemberAccept",
            "MemberRemove", "MemberUnban", "MetadataSet", "RoleSet"))
            assertTrue(OwnDeviceSyncPolicy.canRelayGroupOperation(type))
        for (type in listOf("MsgAdd", "MsgEdit", "MsgDelete", "ReactionSet", "PinSet",
            "GroupLinkSync", "unknown"))
            assertFalse(OwnDeviceSyncPolicy.canRelayGroupOperation(type))
    }
}
