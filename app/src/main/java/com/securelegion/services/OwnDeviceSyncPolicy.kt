package com.securelegion.services

/** Fail-closed policy for the reserved independent-device protocol namespace. */
internal object OwnDeviceSyncPolicy {
    private val torTopics = setOf("contacts", "settings", "group_links")
    private val groupConnectionOperations = setOf(
        "GroupCreate", "GroupDelete", "MemberInvite", "MemberAccept",
        "MemberRemove", "MemberUnban", "MetadataSet", "RoleSet"
    )

    fun isReservedNetworkType(type: Int): Boolean =
        type in 0xA3..0xA5 || type in 0xB0..0xB7 || type == 0xC0 || type == 0xC2

    fun canSendTorTopic(topic: String): Boolean = topic in torTopics

    /** Check the signed operation type, not a local storage label or enclosing topic. */
    fun canRelayGroupOperation(signedType: String): Boolean = signedType in groupConnectionOperations

    /** A policy skip, or a settlement for Wi-Fi history, never clears durable work. */
    fun canSettleTorEvent(topic: String, resultKind: String): Boolean =
        topic in torTopics && resultKind == "settled"
}
