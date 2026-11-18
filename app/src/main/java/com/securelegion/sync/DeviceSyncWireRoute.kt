package com.securelegion.sync

import org.json.JSONObject
import java.util.Base64

/** An untrusted routing hint. The roster and Rust Noise engine authenticate it later. */
internal object DeviceSyncWireRoute {
    private val deviceId = Regex("[A-Za-z0-9_-]{43}")
    private const val MAX_WIRE = 512 * 1024
    private const val DATA_PREFIX = 1 + 32 + 43 + 43 + 8 + 1

    fun peerId(wire: ByteArray, localDeviceId: String, accountEd: ByteArray): String {
        require(localDeviceId.matches(deviceId) && accountEd.size == 32)
        require(wire.size in 6..MAX_WIRE)
        val bodyLength = ((wire[1].toInt() and 255) shl 24) or
            ((wire[2].toInt() and 255) shl 16) or
            ((wire[3].toInt() and 255) shl 8) or (wire[4].toInt() and 255)
        require(bodyLength == wire.size - 5)
        val body = wire.copyOfRange(5, wire.size)
        val sender: String
        val recipient: String
        when (wire[0].toInt() and 255) {
            0xB6 -> {
                require(body.size <= 8192)
                val packet = JSONObject(body.toString(Charsets.UTF_8))
                require(packet.keys().asSequence().toSet() == setOf("header", "signature"))
                val header = packet.getJSONObject("header")
                require(header.keys().asSequence().toSet() ==
                    setOf("v", "from", "to", "account", "session", "step", "ts", "noise"))
                require(header.opt("v") is Int && header.getInt("v") == 2)
                require(header.getString("account") ==
                    Base64.getEncoder().encodeToString(accountEd))
                sender = header.getString("from")
                recipient = header.getString("to")
            }
            0xB7 -> {
                require(body.size >= DATA_PREFIX + 2 + 16 && body[0].toInt() == 2)
                sender = body.copyOfRange(33, 76).toString(Charsets.US_ASCII)
                recipient = body.copyOfRange(76, 119).toString(Charsets.US_ASCII)
            }
            else -> throw IllegalArgumentException("Not a forward-secret device frame")
        }
        require(sender.matches(deviceId) && sender != localDeviceId && recipient == localDeviceId)
        return sender
    }
}
