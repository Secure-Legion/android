package com.securelegion.models

data class Chat(
    val id: String,
    val nickname: String,
    val lastMessage: String,
    val time: String,
    val unreadCount: Int,
    val isOnline: Boolean,
    val avatar: String,
    val securityBadge: String
)
