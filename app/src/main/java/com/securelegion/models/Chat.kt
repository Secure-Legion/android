package com.securelegion.models

/**
 * Represents a chat conversation with a contact
 */
data class Chat(
    val id: String,
    val nickname: String,
    val unreadCount: Int = 0,
    val isOnline: Boolean = false,
    val avatar: String = "",
    val securityBadge: String = "",
    val lastMessage: String = "",
    val time: String = "",
    val lastMessageStatus: Int = 0,
    val lastMessageIsSent: Boolean = false,
    val lastMessagePingDelivered: Boolean = false,
    val lastMessageMessageDelivered: Boolean = false,
    val isPinned: Boolean = false,
    val profilePictureBase64: String? = null,
    val isGroup: Boolean = false,
    val groupId: String? = null
)
