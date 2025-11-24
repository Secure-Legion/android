package com.securelegion.models

data class Contact(
    val id: String,
    val name: String,
    val address: String,
    val friendshipStatus: String = "PENDING_SENT"
)
