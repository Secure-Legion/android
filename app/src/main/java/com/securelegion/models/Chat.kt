package com.securelegion.models

data class Chat(
    val id: String,
    val nickname: String,
    val lastMessage: String,
    val time: String,
    val unreadCount: Int,
    val isOnline: Boolean,
    val avatar: String,
    val securityBadge: String,
    val lastMessageStatus: Int = 0,  // 0 = none (received message), otherwise use Message.STATUS_* constants
    val lastMessageIsSent: Boolean = false,  // true if last message was sent by us
    val lastMessagePingDelivered: Boolean = false,  // true if PING_ACK received for last sent message
    val lastMessageMessageDelivered: Boolean = false  // true if MESSAGE_ACK received for last sent message
)
