package com.securelegion.sync

import org.json.JSONObject
import java.util.Base64

/** Validated own-device message history. No delivery ownership is implied. */
internal object DeviceSyncMessageDelta {
    private val optional = setOf("content", "attachment_type", "attachment_data",
        "voice_duration", "voice_data", "reply_to_message_id", "reply_to_text",
        "reply_to_self", "is_edited", "is_read", "self_destruct_at",
        "self_destruct_ttl", "ping_delivered", "message_delivered",
        "control_versions", "reactions")
    private val required = setOf("message_id", "contact_x25519", "message_type",
        "is_sent_by_me", "timestamp", "status")
    private val allowedTypes = setOf("TEXT", "IMAGE", "VOICE", "STICKER")
    private const val MAX_VOICE = 5_242_880
    private const val MAX_IMAGE = 4 * 1_024 * 1_024

    data class Message(
        val id: String, val deleted: Boolean, val contactX25519: ByteArray?,
        val type: String?, val sentByMe: Boolean?, val timestampMs: Long?,
        val status: Int?, val content: String?, val attachmentType: String?,
        val attachmentData: String?, val voiceData: ByteArray?,
        val voiceDuration: Int?, val replyToId: String?, val replyToText: String?,
        val replyToSelf: Boolean, val edited: Boolean, val read: Boolean,
        val selfDestructAtMs: Long?, val selfDestructTtl: Double?,
        val pingDelivered: Boolean, val messageDelivered: Boolean,
        val reactions: List<Reaction> = emptyList()
    )

    data class Reaction(val actor: String, val emoji: String,
                        val removed: Boolean, val timestamp: Long,
                        val eventId: String)

    fun parse(delta: JSONObject, nowMs: Long = System.currentTimeMillis()): Message {
        val keys = delta.keys().asSequence().toSet()
        require("message_id" in keys && delta.opt("message_id") is String)
        val id = delta.getString("message_id")
        require(id.isNotEmpty() && id.length <= 256)
        if (delta.opt("deleted") == true) {
            require(keys == setOf("message_id", "deleted"))
            return Message(id, true, null, null, null, null, null, null, null,
                null, null, null, null, null, false, false, false,
                null, null, false, false)
        }
        require(keys.containsAll(required) && keys.all { it in required || it in optional })
        val contactX = base64(delta.getString("contact_x25519"), 32, 32)
        val type = delta.getString("message_type")
        require(type in allowedTypes)
        val sent = bool(delta, "is_sent_by_me")
        val timestamp = integer(delta.opt("timestamp"))
        require(timestamp in 1..nowMs + 300_000L)
        val status = integer(delta.opt("status"))
        require(status in 0..7)
        val content = nullableString(delta, "content", 65_536)
        if (type == "TEXT") require(content != null)
        val attachmentType = nullableString(delta, "attachment_type", 64)
        val attachmentData = nullableString(delta, "attachment_data", 8 * 1_024 * 1_024)
        if (type == "STICKER") require(attachmentType == "sticker" &&
            attachmentData != null && attachmentData.isNotEmpty() &&
            attachmentData.toByteArray(Charsets.UTF_8).size <= 1024 &&
            !attachmentData.contains("..") && !attachmentData.contains('\\') &&
            !attachmentData.contains(':') && !attachmentData.startsWith('/') &&
            !attachmentData.startsWith('~') &&
            attachmentData.none { it.code < 32 || it.code > 126 })
        if (type == "IMAGE") {
            require(attachmentData != null)
            base64(attachmentData, 1, MAX_IMAGE)
        }
        val voice = if (type == "VOICE") {
            require(delta.opt("voice_data") is String)
            base64(delta.getString("voice_data"), 4, MAX_VOICE)
        } else {
            require(!delta.has("voice_data"))
            null
        }
        val duration = nullableInteger(delta, "voice_duration")?.also { require(it in 0..86_400) }
        val reply = nullableString(delta, "reply_to_message_id", 256)
        if (reply != null) require(reply.isNotEmpty())
        val replyText = nullableString(delta, "reply_to_text", 4_096)
        require(reply == null || replyText == null || delta.opt("reply_to_self") is Boolean)
        val expiry = nullableLong(delta, "self_destruct_at")
        if (expiry != null) require(expiry > 0)
        val ttl = when (val value = delta.opt("self_destruct_ttl")) {
            null, JSONObject.NULL -> null
            is Number -> value.toDouble().also { require(it.isFinite() && it in 1.0..604_800.0) }
            else -> throw IllegalArgumentException("Invalid self-destruct TTL")
        }
        if (delta.has("control_versions"))
            require(delta.getJSONArray("control_versions").length() == 0)
        val reactions = if (!delta.has("reactions")) emptyList() else {
            val array = delta.getJSONArray("reactions")
            require(array.length() <= 2)
            val actors = HashSet<String>()
            (0 until array.length()).map { index ->
                val item = array.getJSONObject(index)
                require(item.keys().asSequence().toSet() == setOf("actor", "emoji",
                    "removed", "timestamp", "event_id"))
                val actor = item.getString("actor")
                base64(actor, 32, 32)
                require(actors.add(actor))
                val emoji = item.getString("emoji")
                require(emoji.codePointCount(0, emoji.length) <= 32 &&
                    emoji.toByteArray(Charsets.UTF_8).size <= 128)
                val removed = bool(item, "removed")
                require(removed || emoji.isNotEmpty())
                val time = integer(item.opt("timestamp"))
                require(time in 1..nowMs + 300_000L)
                val event = item.getString("event_id")
                require(event.isNotEmpty() && event.length <= 256 &&
                    event.all { it.code in 33..126 })
                Reaction(actor, emoji, removed, time, event)
            }
        }
        return Message(id, false, contactX, type, sent, timestamp, status.toInt(),
            content, attachmentType, attachmentData, voice, duration, reply,
            replyText, optionalBool(delta, "reply_to_self"),
            optionalBool(delta, "is_edited"), optionalBool(delta, "is_read"),
            expiry, ttl, optionalBool(delta, "ping_delivered"),
            optionalBool(delta, "message_delivered"), reactions)
    }

    private fun bool(value: JSONObject, key: String): Boolean {
        require(value.opt(key) is Boolean)
        return value.getBoolean(key)
    }

    private fun optionalBool(value: JSONObject, key: String): Boolean =
        if (value.has(key)) bool(value, key) else false

    private fun integer(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong()
    }

    private fun nullableInteger(value: JSONObject, key: String): Int? =
        nullableLong(value, key)?.also { require(it in Int.MIN_VALUE..Int.MAX_VALUE) }?.toInt()

    private fun nullableLong(value: JSONObject, key: String): Long? =
        when (val raw = value.opt(key)) {
            null, JSONObject.NULL -> null
            else -> integer(raw)
        }

    private fun nullableString(value: JSONObject, key: String, maxBytes: Int): String? =
        when (val raw = value.opt(key)) {
            null, JSONObject.NULL -> null
            is String -> raw.also { require(it.toByteArray(Charsets.UTF_8).size <= maxBytes) }
            else -> throw IllegalArgumentException("Invalid $key")
        }

    private fun base64(value: String, minBytes: Int, maxBytes: Int): ByteArray {
        require(value.length <= ((maxBytes + 2) / 3) * 4)
        val bytes = Base64.getDecoder().decode(value)
        require(bytes.size in minBytes..maxBytes &&
            Base64.getEncoder().encodeToString(bytes) == value)
        return bytes
    }
}
