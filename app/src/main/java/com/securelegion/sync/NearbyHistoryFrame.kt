package com.securelegion.sync

import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Build-48 B0–B5 envelope for authenticated Nearby TLS records only. */
internal object NearbyHistoryFrame {
    private const val MAX_WIRE = 512 * 1024
    private const val MAX_PLAIN = 384 * 1024
    private val outerFields = setOf("from", "ct", "sig")
    private val innerFields = setOf("v", "type", "from_device_id",
        "to_device_id", "ts", "payload")
    private val id = Regex("[A-Za-z0-9_-]{43}")

    data class Frame(val kind: DeviceSyncFrameV2.Kind, val sender: String,
                     val recipient: String, val timestampMs: Long,
                     val payload: JSONObject, val wireHash: ByteArray)

    fun encode(kind: DeviceSyncFrameV2.Kind, identity: LocalDeviceIdentity,
               recipientId: String, recipientX: ByteArray, payload: JSONObject,
               nowMs: Long = System.currentTimeMillis()): ByteArray {
        require(id.matches(identity.deviceId) && id.matches(recipientId) &&
            recipientId != identity.deviceId && recipientX.size == 32 &&
            nowMs in 1..9_007_199_254_740_991L)
        val plain = JSONObject().put("v", 1).put("type", kind.text)
            .put("from_device_id", identity.deviceId)
            .put("to_device_id", recipientId).put("ts", nowMs)
            .put("payload", payload).toString().toByteArray(Charsets.UTF_8)
        require(plain.size in 2..MAX_PLAIN)
        val shared = identity.deriveSharedSecret(recipientX)
        val nonce = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val ciphertext = try { RustBridge.xchacha20Encrypt(plain, shared, nonce) }
            finally { plain.fill(0); shared.fill(0) }
        require(ciphertext.size >= 16)
        val encrypted = nonce + ciphertext
        val signature = try { identity.sign(encrypted) }
            finally { ciphertext.fill(0); nonce.fill(0) }
        require(signature.size == 64)
        val outer = JSONObject().put("from", identity.deviceId)
            .put("ct", Base64.getEncoder().encodeToString(encrypted))
            .put("sig", Base64.getEncoder().encodeToString(signature))
            .toString().toByteArray(Charsets.UTF_8)
        encrypted.fill(0)
        signature.fill(0)
        require(outer.size + 5 <= MAX_WIRE)
        val wire = ByteArray(5 + outer.size)
        wire[0] = kind.wire.toByte()
        for (i in 0..3) wire[1 + i] =
            (outer.size ushr ((3 - i) * 8)).toByte()
        outer.copyInto(wire, 5)
        return wire
    }

    fun decode(wire: ByteArray, expectedSender: String,
               identity: LocalDeviceIdentity, senderEd: ByteArray,
               senderX: ByteArray,
               nowMs: Long = System.currentTimeMillis()): Frame {
        require(wire.size in 5..MAX_WIRE && id.matches(expectedSender) &&
            expectedSender != identity.deviceId && senderEd.size == 32 &&
            senderX.size == 32)
        val kind = DeviceSyncFrameV2.Kind.fromWire(wire[0].toInt() and 255)
            ?: throw IllegalArgumentException("Unknown Nearby frame")
        val count = (0..3).fold(0L) { n, i ->
            (n shl 8) or (wire[1 + i].toLong() and 255)
        }
        require(count == wire.size - 5L)
        val outer = JSONObject(wire.copyOfRange(5, wire.size).toString(Charsets.UTF_8))
        require(outer.keys().asSequence().toSet() == outerFields &&
            outer.opt("from") == expectedSender)
        val encrypted = strictBase64(outer.getString("ct"), 40, MAX_WIRE)
        val signature = strictBase64(outer.getString("sig"), 64, 64)
        require(RustBridge.verifySignature(encrypted, signature, senderEd))
        val shared = identity.deriveSharedSecret(senderX)
        val plain = try { RustBridge.xchacha20Decrypt(
            encrypted.copyOfRange(24, encrypted.size), shared,
            encrypted.copyOfRange(0, 24))
                ?: throw IllegalArgumentException("Invalid Nearby ciphertext") }
            finally { shared.fill(0); encrypted.fill(0); signature.fill(0) }
        try {
            require(plain.size in 2..MAX_PLAIN)
            val inner = JSONObject(plain.toString(Charsets.UTF_8))
            require(inner.keys().asSequence().toSet() == innerFields &&
                strictLong(inner.opt("v")) == 1L &&
                inner.opt("type") == kind.text &&
                inner.opt("from_device_id") == expectedSender &&
                inner.opt("to_device_id") == identity.deviceId)
            val timestamp = strictLong(inner.opt("ts"))
            require(timestamp > 0 && timestamp <= nowMs + 300_000L)
            val payload = inner.optJSONObject("payload")
                ?: throw IllegalArgumentException("Invalid Nearby payload")
            return Frame(kind, expectedSender, identity.deviceId, timestamp,
                payload, MessageDigest.getInstance("SHA-256").digest(wire))
        } finally { plain.fill(0) }
    }

    private fun strictBase64(value: String, min: Int, max: Int): ByteArray {
        require(value.length <= ((max + 2) / 3) * 4)
        return Base64.getDecoder().decode(value).also {
            require(it.size in min..max && Base64.getEncoder().encodeToString(it) == value)
        }
    }

    private fun strictLong(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong().also {
            require(it in 1..9_007_199_254_740_991L)
        }
    }
}
