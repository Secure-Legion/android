package com.securelegion.sync

import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Strict C0v2 frame syntax. Roster authorization is a separate required step. */
internal class DeviceTransportFrame private constructor(
    val wire: ByteArray, val version: Int, val kind: Kind,
    val senderAccount: ByteArray, val recipientAccount: ByteArray,
    val senderDeviceId: String, val recipientDeviceId: String,
    val sessionId: ByteArray, val counter: Long, val jobId: ByteArray,
    val payload: ByteArray
) {
    enum class Kind(val code: Int) {
        SESSION_REQUEST(1), PREKEY(2), DATA(3), DEVICE_STORAGE_ACK(4),
        RESPONSIBILITY_REQUEST(5), RESPONSIBILITY_ACK(6), ACCOUNT_STORAGE_ACK(7);
        companion object { fun from(code: Int) = entries.firstOrNull { it.code == code } }
    }

    val signature: ByteArray get() = wire.copyOfRange(wire.size - SIGNATURE_SIZE, wire.size)
    val exactWireHash: ByteArray get() = MessageDigest.getInstance("SHA-256").digest(wire)
    val keyContext: String get() {
        val prekeyHash = exactHash(payload).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
        val generation = if (version == 1) "" else "$counter/"
        return "Secure-DEVICE-TRANSPORT-v$version/session/" +
            "${Base64.getEncoder().encodeToString(senderAccount)}/" +
            "${Base64.getEncoder().encodeToString(recipientAccount)}/" +
            "$senderDeviceId/$recipientDeviceId/${deviceId(sessionId)}/" +
            "$generation$prekeyHash"
    }

    fun verify(signingPublicKey: ByteArray): Boolean = signingPublicKey.size == 32 &&
        RustBridge.verifySignature(domain(version) +
            wire.copyOfRange(0, wire.size - SIGNATURE_SIZE),
            signature, signingPublicKey)

    companion object {
        const val TYPE = 0xC0
        const val HEADER_SIZE = 211
        const val SIGNATURE_SIZE = 64
        const val MAX_PAYLOAD = 5 * 1024 * 1024 + 2048
        const val MAX_COUNTER = 9_007_199_254_740_991L

        fun parse(bytes: ByteArray): DeviceTransportFrame {
            require(bytes.size in HEADER_SIZE + SIGNATURE_SIZE..HEADER_SIZE +
                SIGNATURE_SIZE + MAX_PAYLOAD && (bytes[0].toInt() and 0xff) == TYPE)
            require(u32(bytes, 1) == bytes.size - 5)
            val version = bytes[5].toInt() and 0xff
            val kind = Kind.from(bytes[6].toInt() and 0xff)
                ?: throw IllegalArgumentException("Unknown C0 frame kind")
            require(version == 1 || version == 2)
            require(version == 2 || kind.code <= Kind.DEVICE_STORAGE_ACK.code)
            val counter = u64(bytes, 167)
            val size = u32(bytes, 207)
            require(counter in 0..MAX_COUNTER && size in 0..MAX_PAYLOAD &&
                bytes.size == HEADER_SIZE + size + SIGNATURE_SIZE)
            val sender = deviceId(bytes.copyOfRange(71, 103))
            val recipient = deviceId(bytes.copyOfRange(103, 135))
            val session = bytes.copyOfRange(135, 167)
            val job = bytes.copyOfRange(175, 207)
            val payload = bytes.copyOfRange(HEADER_SIZE, HEADER_SIZE + size)
            val handshake = kind == Kind.SESSION_REQUEST || kind == Kind.PREKEY
            if (version == 2 && kind != Kind.RESPONSIBILITY_REQUEST &&
                kind != Kind.RESPONSIBILITY_ACK) {
                val generation = u64(session, 0)
                require(generation in 2..MAX_COUNTER && (!handshake || generation == counter))
            }
            if (handshake) require(job.all { it == 0.toByte() } &&
                if (version == 1) counter == 0L else counter > 0)
            when (kind) {
                Kind.SESSION_REQUEST -> if (version == 1) require(payload.isEmpty())
                    else require(payload.size == 8 && u64(payload, 0) < counter)
                Kind.PREKEY -> require(payload.size == 1600)
                Kind.DATA -> require(payload.size >= 50 && payload[0].toInt() in 0..1 &&
                    payload.size >= 50 + payload[0].toInt() * 1600)
                Kind.DEVICE_STORAGE_ACK, Kind.ACCOUNT_STORAGE_ACK -> require(payload.size == 32)
                Kind.RESPONSIBILITY_REQUEST -> require(counter == 0L && payload.isEmpty())
                Kind.RESPONSIBILITY_ACK -> require(counter == 0L && payload.size == 32)
            }
            return DeviceTransportFrame(bytes.copyOf(), version, kind,
                bytes.copyOfRange(7, 39), bytes.copyOfRange(39, 71),
                sender, recipient, session, counter, job, payload)
        }

        fun sign(kind: Kind, senderAccount: ByteArray, recipientAccount: ByteArray,
                 senderDeviceId: String, recipientDeviceId: String,
                 sessionId: ByteArray, counter: Long, jobId: ByteArray,
                 payload: ByteArray, identity: LocalDeviceIdentity,
                 version: Int = 2): DeviceTransportFrame {
            require(version in 1..2 && senderAccount.size == 32 && recipientAccount.size == 32 &&
                sessionId.size == 32 && jobId.size == 32 &&
                counter in 0..MAX_COUNTER && payload.size <= MAX_PAYLOAD &&
                identity.deviceId == senderDeviceId)
            val sender = decodeDeviceId(senderDeviceId)
            val recipient = decodeDeviceId(recipientDeviceId)
            val wire = ByteArray(HEADER_SIZE + payload.size + SIGNATURE_SIZE)
            wire[0] = TYPE.toByte()
            writeU32(wire, 1, wire.size - 5)
            wire[5] = version.toByte()
            wire[6] = kind.code.toByte()
            senderAccount.copyInto(wire, 7)
            recipientAccount.copyInto(wire, 39)
            sender.copyInto(wire, 71)
            recipient.copyInto(wire, 103)
            sessionId.copyInto(wire, 135)
            writeU64(wire, 167, counter)
            jobId.copyInto(wire, 175)
            writeU32(wire, 207, payload.size)
            payload.copyInto(wire, HEADER_SIZE)
            val signature = identity.sign(domain(version) +
                wire.copyOfRange(0, wire.size - SIGNATURE_SIZE))
            require(signature.size == SIGNATURE_SIZE)
            signature.copyInto(wire, wire.size - SIGNATURE_SIZE)
            return parse(wire)
        }

        fun logicalId(account: ByteArray, deviceId: String, jobId: ByteArray): String {
            require(account.size == 32 && jobId.size == 32)
            val hash = MessageDigest.getInstance("SHA-256").digest(
                "Secure-DEVICE-TRANSPORT-v1/job\u0000".toByteArray() +
                    account + decodeDeviceId(deviceId) + jobId)
            return "dev_" + deviceId(hash)
        }

        fun randomId(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun sessionIdForGeneration(generation: Long): ByteArray {
            require(generation in 2..MAX_COUNTER)
            return randomId().also { writeU64(it, 0, generation) }
        }

        private fun exactHash(bytes: ByteArray) =
            MessageDigest.getInstance("SHA-256").digest(bytes)

        private fun domain(version: Int) =
            "Secure-DEVICE-TRANSPORT-v$version\u0000".toByteArray(Charsets.UTF_8)
        private fun deviceId(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        private fun decodeDeviceId(id: String): ByteArray {
            require(id.matches(Regex("[A-Za-z0-9_-]{43}")))
            val bytes = Base64.getUrlDecoder().decode(id)
            require(bytes.size == 32 && deviceId(bytes) == id)
            return bytes
        }
        private fun u32(bytes: ByteArray, at: Int): Int {
            require(at >= 0 && at + 4 <= bytes.size)
            return (0..3).fold(0) { n, i -> (n shl 8) or (bytes[at + i].toInt() and 0xff) }
        }
        private fun u64(bytes: ByteArray, at: Int): Long {
            require(at >= 0 && at + 8 <= bytes.size)
            return (0..7).fold(0L) { n, i -> (n shl 8) or (bytes[at + i].toLong() and 0xff) }
        }
        private fun writeU32(bytes: ByteArray, at: Int, value: Int) {
            for (i in 0..3) bytes[at + i] = (value ushr ((3 - i) * 8)).toByte()
        }
        private fun writeU64(bytes: ByteArray, at: Int, value: Long) {
            for (i in 0..7) bytes[at + i] = (value ushr ((7 - i) * 8)).toByte()
        }
    }
}
