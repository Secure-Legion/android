package com.securelegion.sync

import org.json.JSONObject
import java.security.MessageDigest

/** Inner B0-B5 frame, usable only after B6/B7 Noise authentication. */
internal object DeviceSyncFrameV2 {
    enum class Kind(val wire: Int, val text: String) {
        HELLO(0xB0, "HELLO"), HELLO_ACK(0xB1, "HELLO_ACK"),
        PUSH(0xB2, "PUSH"), PULL_REQUEST(0xB3, "PULL_REQUEST"),
        PULL_RESPONSE(0xB4, "PULL_RESPONSE"), BYE(0xB5, "BYE");
        companion object { fun fromWire(wire: Int) = entries.firstOrNull { it.wire == wire } }
    }

    data class Frame(val kind: Kind, val sender: String, val recipient: String,
                     val timestampMs: Long, val payload: JSONObject, val exactWireHash: ByteArray)

    private val required = setOf("v", "type", "from_device_id", "to_device_id", "ts", "payload")

    fun decode(plaintext: ByteArray, authenticatedSender: String, localDeviceId: String,
               networkWire: ByteArray, nowMs: Long = System.currentTimeMillis()): Frame {
        require(plaintext.size in 2..384 * 1024 && networkWire.size in 5..512 * 1024)
        require(networkWire[0].toInt() and 0xff in 0xB6..0xB7)
        val kind = Kind.fromWire(plaintext[0].toInt() and 0xff)
            ?: throw IllegalArgumentException("Unknown sync kind")
        val json = JSONObject(plaintext.copyOfRange(1, plaintext.size).toString(Charsets.UTF_8))
        require(json.keys().asSequence().toSet() == required)
        require(strictLong(json.opt("v")) == 2L && json.getString("type") == kind.text)
        require(authenticatedSender.matches(Regex("[A-Za-z0-9_-]{43}")) &&
            localDeviceId.matches(Regex("[A-Za-z0-9_-]{43}")))
        require(json.getString("from_device_id") == authenticatedSender &&
            json.getString("to_device_id") == localDeviceId)
        val ts = strictLong(json.opt("ts"))
        require(ts > 0 && ts <= nowMs + 300_000L)
        val payload = json.optJSONObject("payload")
            ?: throw IllegalArgumentException("Invalid sync payload")
        return Frame(kind, authenticatedSender, localDeviceId, ts, payload,
            MessageDigest.getInstance("SHA-256").digest(networkWire))
    }

    fun encode(kind: Kind, localDeviceId: String, peerDeviceId: String,
               payload: JSONObject, nowMs: Long = System.currentTimeMillis()): ByteArray {
        require(localDeviceId.matches(Regex("[A-Za-z0-9_-]{43}")) &&
            peerDeviceId.matches(Regex("[A-Za-z0-9_-]{43}")) && localDeviceId != peerDeviceId)
        require(nowMs in 1..9_007_199_254_740_991L)
        val body = JSONObject().put("v", 2).put("type", kind.text)
            .put("from_device_id", localDeviceId).put("to_device_id", peerDeviceId)
            .put("ts", nowMs).put("payload", payload)
            .toString().toByteArray(Charsets.UTF_8)
        require(body.size + 1 <= 384 * 1024)
        return byteArrayOf(kind.wire.toByte()) + body
    }

    private fun strictLong(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong().also { require(it in 1..9_007_199_254_740_991L) }
    }
}
