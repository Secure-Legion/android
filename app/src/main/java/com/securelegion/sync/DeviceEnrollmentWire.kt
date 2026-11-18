package com.securelegion.sync

import org.json.JSONObject
import org.json.JSONArray
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Public enrollment wire parsing. No trust state or private key is changed here. */
internal object DeviceEnrollmentWire {
    private const val QR_MAX = 4096
    private const val ENROLL_MAX = 96 * 1024
    private const val RECOVER_MAX = 384 * 1024
    private const val QR_LIFETIME_MS = 5 * 60 * 1000L
    private const val WIRE_TYPE = 0xA3
    private val frameTypes = setOf(
        "offer", "candidate_proof", "owner_approval", "candidate_approval", "grant", "committed"
    )
    private val onionPattern = Regex("[a-z2-7]{56}\\.onion")
    private val digestPattern = Regex("[0-9a-f]{64}")

    data class Endpoint(
        val deviceId: String,
        val name: String,
        val platform: String,
        val onion: String,
        val signingPublicKey: ByteArray,
        val encryptionPublicKey: ByteArray,
        val kemHash: ByteArray,
        val ephemeralPublicKey: ByteArray,
        val nonce: ByteArray,
        val accountIdentity: ByteArray?
    )

    data class CandidateQr(
        val version: Int,
        val expiresAtMs: Long,
        val candidate: Endpoint,
        val pinnedAccount: ByteArray?,
        val raw: JSONObject
    )

    data class Frame(val version: Int, val transcriptId: String, val type: String, val body: JSONObject)

    fun parseCandidateQr(payload: String, nowMs: Long = System.currentTimeMillis()): CandidateQr {
        val bytes = payload.toByteArray(Charsets.UTF_8)
        require(bytes.isNotEmpty() && bytes.size <= QR_MAX) { "Invalid enrollment QR size" }
        val json = JSONObject(payload)
        val version = strictVersion(json.opt("v"))
        exactFields(json, if (version == 1) setOf("v", "t", "expires", "candidate")
            else setOf("v", "t", "expires", "candidate", "account_public"))
        require(json.opt("t") == if (version == 1) "SL_ENROLL" else "SL_RECOVER")
        val expiry = strictLong(json.opt("expires"))
        require(nowMs > 0 && expiry > nowMs && expiry <= nowMs + QR_LIFETIME_MS)
        val candidate = parseEndpoint(json.opt("candidate") as? JSONObject
            ?: throw IllegalArgumentException("Invalid candidate"), "candidate")
        val pinned = if (version == 2) fixedBase64Key(json.opt("account_public")) else null
        return CandidateQr(version, expiry, candidate, pinned, json)
    }

    fun parseOwnerEndpoint(json: JSONObject): Endpoint = parseEndpoint(json, "owner")

    fun decodeFrame(wire: ByteArray): Frame {
        require(wire.size in 6..(RECOVER_MAX + 5) && (wire[0].toInt() and 0xff) == WIRE_TYPE)
        val size = ByteBuffer.wrap(wire, 1, 4).int
        require(size == wire.size - 5 && size > 0)
        val json = JSONObject(decodeUtf8(wire, 5, size))
        val version = strictVersion(json.opt("v"))
        require(size <= if (version == 1) ENROLL_MAX else RECOVER_MAX)
        val id = json.opt("id") as? String ?: throw IllegalArgumentException("Missing transcript")
        val type = json.opt("type") as? String ?: throw IllegalArgumentException("Missing frame type")
        require(digestPattern.matches(id) && type in frameTypes)
        return Frame(version, id, type, json)
    }

    fun encodeFrame(json: JSONObject): ByteArray {
        val version = strictVersion(json.opt("v"))
        val id = json.opt("id") as? String ?: throw IllegalArgumentException("Missing transcript")
        val type = json.opt("type") as? String ?: throw IllegalArgumentException("Missing frame type")
        require(digestPattern.matches(id) && type in frameTypes)
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        require(bytes.size <= if (version == 1) ENROLL_MAX else RECOVER_MAX)
        return byteArrayOf(WIRE_TYPE.toByte()) + ByteBuffer.allocate(4).putInt(bytes.size).array() + bytes
    }

    /** Byte-for-byte build-48 transcript encoding: sorted object keys, UTF-8, no slash escaping. */
    fun canonicalJson(value: Any): ByteArray {
        val out = StringBuilder()
        appendCanonical(out, value)
        return out.toString().toByteArray(Charsets.UTF_8)
    }

    fun transcript(qr: CandidateQr, owner: JSONObject): ByteArray {
        val endpoint = parseOwnerEndpoint(owner)
        require(endpoint.deviceId != qr.candidate.deviceId && endpoint.onion != qr.candidate.onion)
        return canonicalJson(JSONObject().put("protocol", if (qr.version == 1) "Secure-ENROLL-v1"
            else "Secure-RECOVER-v1").put("qr", qr.raw).put("owner", owner))
    }

    fun transcriptId(transcript: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(transcript).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun proofBytes(domain: String, purpose: String, transcript: ByteArray,
                   extra: ByteArray? = null): ByteArray {
        require(domain == "Secure-ENROLL-v1" || domain == "Secure-RECOVER-v1")
        require(purpose in setOf("offer", "candidate_proof", "owner_approval",
            "candidate_approval", "grant", "comparison"))
        return "$domain/$purpose\u0000".toByteArray(Charsets.UTF_8) + transcript +
            (extra?.let { MessageDigest.getInstance("SHA-256").digest(it) } ?: byteArrayOf())
    }

    private fun appendCanonical(out: StringBuilder, value: Any) {
        when (value) {
            is JSONObject -> {
                out.append('{')
                val keys = value.keys().asSequence().toList().sorted()
                keys.forEachIndexed { index, key ->
                    if (index > 0) out.append(',')
                    appendQuoted(out, key)
                    out.append(':')
                    appendCanonical(out, value.get(key))
                }
                out.append('}')
            }
            is JSONArray -> {
                out.append('[')
                for (index in 0 until value.length()) {
                    if (index > 0) out.append(',')
                    appendCanonical(out, value.get(index))
                }
                out.append(']')
            }
            JSONObject.NULL -> out.append("null")
            is String -> appendQuoted(out, value)
            is Boolean -> out.append(if (value) "true" else "false")
            is Byte, is Short, is Int, is Long -> out.append(value.toString())
            is Float -> { require(value.isFinite()); out.append(value.toString()) }
            is Double -> { require(value.isFinite()); out.append(value.toString()) }
            else -> throw IllegalArgumentException("Unsupported canonical JSON value")
        }
    }

    private fun appendQuoted(out: StringBuilder, value: String) {
        out.append('"')
        for (char in value) when (char) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            '\b' -> out.append("\\b")
            '\u000c' -> out.append("\\f")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (char.code < 32) out.append("\\u%04x".format(char.code)) else out.append(char)
        }
        out.append('"')
    }

    private fun parseEndpoint(json: JSONObject, role: String): Endpoint {
        val fields = mutableSetOf(
            "role", "device_id", "device_name", "platform", "onion",
            "device_ed", "device_x", "kem_hash", "e_pub", "nonce"
        )
        if (role == "owner") fields.add("account_identity")
        exactFields(json, fields)
        require(json.opt("role") == role)
        val id = string(json, "device_id")
        val name = string(json, "device_name")
        val platform = string(json, "platform")
        val onion = string(json, "onion")
        require(name.isNotBlank() && name.codePointCount(0, name.length) in 1..64)
        require(name.codePoints().noneMatch { it < 32 || it in 127..159 })
        require(platform.length <= 64 && onionPattern.matches(onion))
        val ed = fixedBase64Key(json.opt("device_ed"))
        val x = fixedBase64Key(json.opt("device_x"))
        val kem = fixedBase64Key(json.opt("kem_hash"))
        val ephemeral = fixedBase64Key(json.opt("e_pub"))
        val nonce = fixedBase64Key(json.opt("nonce"))
        val expectedId = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(
            "secure-legion-device-v1".toByteArray(Charsets.US_ASCII) + ed + x
        ))
        require(id.length == 43 && id == expectedId)
        val accountIdentity = if (role == "owner") {
            val encoded = string(json, "account_identity")
            require(encoded.length == 2272)
            val decoded = Base64.getDecoder().decode(encoded)
            require(decoded.size == 1702 && Base64.getEncoder().encodeToString(decoded) == encoded)
            decoded
        } else null
        return Endpoint(id, name, platform, onion, ed, x, kem, ephemeral, nonce, accountIdentity)
    }

    private fun fixedBase64Key(value: Any?): ByteArray {
        val encoded = value as? String ?: throw IllegalArgumentException("Invalid public key")
        require(encoded.length == 44)
        val bytes = Base64.getDecoder().decode(encoded)
        require(bytes.size == 32 && Base64.getEncoder().encodeToString(bytes) == encoded)
        return bytes
    }

    private fun string(json: JSONObject, key: String): String =
        json.opt(key) as? String ?: throw IllegalArgumentException("Invalid $key")

    private fun strictVersion(value: Any?): Int {
        val version = strictLong(value)
        require(version == 1L || version == 2L)
        return version.toInt()
    }

    private fun strictLong(value: Any?): Long = when (value) {
        is Byte, is Short, is Int, is Long -> (value as Number).toLong()
        else -> throw IllegalArgumentException("Expected integer")
    }

    private fun exactFields(json: JSONObject, fields: Set<String>) {
        val actual = mutableSetOf<String>()
        val keys = json.keys()
        while (keys.hasNext()) actual.add(keys.next())
        require(actual == fields) { "Unexpected enrollment fields" }
    }

    private fun decodeUtf8(bytes: ByteArray, offset: Int, length: Int): String =
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes, offset, length)).toString()
}
