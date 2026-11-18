package com.securelegion.sync

import android.graphics.BitmapFactory
import org.json.JSONObject
import java.util.Base64

/** Strict public contact snapshot. Missing Android-only card fields remain unresolved. */
internal object DeviceSyncContactDelta {
    data class Version(val timestampMs: Long, val eventId: String)
    data class Contact(val publicKey: ByteArray, val x25519Key: ByteArray?,
                       val displayName: String?, val messagingOnion: String?,
                       val friendRequestOnion: String?, val createdAtMs: Long?,
                       val avatar: String?, val avatarPresent: Boolean,
                       val profileVersion: Version?, val deviceRoster: ByteArray?,
                       val deleted: Boolean)

    private val upsertFields = setOf("public_key", "x25519_pub", "display_name",
        "messaging_onion", "friend_request_onion", "friendship_status", "created_at")
    private val onion = Regex("[a-z2-7]{56}\\.onion")

    fun parse(delta: JSONObject, nowMs: Long = System.currentTimeMillis()): Contact {
        val fields = delta.keys().asSequence().toSet()
        require(delta.opt("public_key") is String)
        val publicKey = decodeKey(delta.getString("public_key"))
        if (delta.opt("deleted") == true) {
            require(fields == setOf("public_key", "deleted"))
            return Contact(publicKey, null, null, null, null, null,
                null, false, null, null, true)
        }
        require(fields.containsAll(upsertFields) &&
            fields.all { it in upsertFields || it in setOf("avatar",
                "profile_version", "device_roster") })
        require(delta.opt("x25519_pub") is String && delta.opt("display_name") is String)
        val x = decodeKey(delta.getString("x25519_pub"))
        val name = delta.getString("display_name")
        require(name.isNotEmpty() && name.codePointCount(0, name.length) <= 128 &&
            name.toByteArray(Charsets.UTF_8).size <= 512)
        require(delta.opt("friendship_status") is Int &&
            delta.getInt("friendship_status") == 3)
        val createdAt = integer(delta.opt("created_at"))
        require(createdAt > 0 && createdAt <= nowMs + 300_000L)
        val messaging = optionalOnion(delta.opt("messaging_onion"))
        val friendRequest = optionalOnion(delta.opt("friend_request_onion"))
        val avatarPresent = delta.has("avatar")
        require(!delta.has("profile_version") || avatarPresent)
        val avatar = if (avatarPresent) {
            val value = delta.opt("avatar")
            if (value == JSONObject.NULL) null else {
                require(value is String && value.length <= 349_528)
                val bytes = Base64.getDecoder().decode(value)
                require(bytes.isNotEmpty() && bytes.size <= 256 * 1024 &&
                    Base64.getEncoder().encodeToString(bytes) == value)
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                require(bounds.outWidth in 1..512 && bounds.outHeight in 1..512 &&
                    bounds.outWidth.toLong() * bounds.outHeight <= 512L * 512)
                value
            }
        } else null
        val profileVersion = if (delta.has("profile_version")) {
            val raw = delta.getJSONObject("profile_version")
            require(raw.keys().asSequence().toSet() == setOf("timestamp", "event_id") &&
                raw.opt("event_id") is String)
            val timestamp = integer(raw.opt("timestamp"))
            val eventId = raw.getString("event_id")
            require(timestamp > 0 && timestamp <= nowMs + 300_000L &&
                eventId.isNotEmpty() && eventId.length <= 256)
            Version(timestamp, eventId)
        } else null
        val deviceRoster = if (delta.has("device_roster")) {
            val encoded = delta.getString("device_roster")
            require(encoded.length in 1..43_692)
            Base64.getDecoder().decode(encoded).also {
                require(it.isNotEmpty() && it.size <= 32 * 1024 &&
                    Base64.getEncoder().encodeToString(it) == encoded)
            }
        } else null
        return Contact(publicKey, x, name, messaging, friendRequest,
            createdAt, avatar, avatarPresent, profileVersion, deviceRoster, false)
    }

    private fun decodeKey(encoded: String): ByteArray {
        require(encoded.length == 44)
        val bytes = Base64.getDecoder().decode(encoded)
        require(bytes.size == 32 && Base64.getEncoder().encodeToString(bytes) == encoded)
        return bytes
    }

    private fun optionalOnion(raw: Any?): String? {
        if (raw == JSONObject.NULL) return null
        require(raw is String && (raw.isEmpty() || onion.matches(raw)))
        return raw.ifEmpty { null }
    }

    private fun integer(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong().also { require(it <= 9_007_199_254_740_991L) }
    }
}
