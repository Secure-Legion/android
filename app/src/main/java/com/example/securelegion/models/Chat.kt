package com.example.securelegion.models

data class Chat(
    val id: String,
    val nickname: String,
    val lastMessage: String,
    val time: String,
    val unreadCount: Int = 0,
    val isOnline: Boolean = false,
    val avatar: String = "",
    val securityBadge: String = "" // "DIRECT" or "RELAY"
)
