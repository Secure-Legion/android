package com.securelegion.sync

import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Strict C2 framing. Parsing never grants membership or device authority. */
internal class DeviceGroupFrame private constructor(
    val wire: ByteArray,
    val kind: Kind,
    val senderAccount: ByteArray,
    val recipientAccount: ByteArray,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val groupId: ByteArray,
    val bundleId: ByteArray,
    val bundleHash: ByteArray,
    val createdAtMs: Long,
    val chunkIndex: Int,
    val chunkCount: Int,
    val bundleLength: Int,
    val senderRoster: ByteArray,
    val payload: ByteArray
) {
    enum class Kind(val code: Int) {
        DATA(1), DEVICE_STORAGE_ACK(2), REINVITATION(3),
        ACCOUNT_STORAGE_ACK(4), PROOF_REQUEST(5), PROOF_RESPONSE(6);
        companion object { fun from(code: Int) = entries.firstOrNull { it.code == code } }
    }

    val carriesData: Boolean get() = kind != Kind.DEVICE_STORAGE_ACK &&
        kind != Kind.ACCOUNT_STORAGE_ACK
    val isAcknowledgment: Boolean get() = !carriesData
    val expectedPlaintextLength: Int get() = minOf(CHUNK_BYTES,
        bundleLength - chunkIndex * CHUNK_BYTES)

    fun verify(signingKey: ByteArray, capabilities: Int,
               nowMs: Long = System.currentTimeMillis()): Boolean {
        if (signingKey.size != 32 || capabilities and 0x04 == 0 ||
            kind == Kind.ACCOUNT_STORAGE_ACK && capabilities and 0x02 == 0 ||
            createdAtMs > nowMs + 5 * 60_000L) return false
        return RustBridge.verifySignature(SIGNATURE_DOMAIN +
            wire.copyOfRange(0, wire.size - SIGNATURE_BYTES),
            wire.copyOfRange(wire.size - SIGNATURE_BYTES, wire.size), signingKey)
    }

    fun acknowledges(original: DeviceGroupFrame): Boolean = isAcknowledgment &&
        original.carriesData && senderAccount.contentEquals(original.recipientAccount) &&
        recipientAccount.contentEquals(original.senderAccount) &&
        senderDeviceId == original.recipientDeviceId &&
        recipientDeviceId == original.senderDeviceId &&
        groupId.contentEquals(original.groupId) && bundleId.contentEquals(original.bundleId) &&
        bundleHash.contentEquals(original.bundleHash) &&
        bundleLength == original.bundleLength && chunkCount == original.chunkCount

    /** Caller must verify the current sender certificate before calling this. */
    fun openChunk(identity: LocalDeviceIdentity): ByteArray {
        require(carriesData && recipientDeviceId == identity.deviceId)
        val hybrid = payload.copyOfRange(0, HYBRID_BYTES)
        val shared = identity.withSyncKeys { _, xSecret ->
            identity.withMLKemPrivateKey { kemSecret ->
                RustBridge.hybridDecapsulate(xSecret, kemSecret, hybrid)
            }
        } ?: throw IllegalArgumentException("Invalid C2 hybrid ciphertext")
        if (shared.size != 64) {
            shared.fill(0)
            throw IllegalArgumentException("Invalid C2 shared secret")
        }
        val key = try { wrapKey(shared, wire.copyOfRange(0, HEADER_BYTES),
            senderRoster, hybrid) } finally { shared.fill(0) }
        try {
            val nonceStart = HYBRID_BYTES
            val nonce = payload.copyOfRange(nonceStart, nonceStart + 24)
            val ciphertext = payload.copyOfRange(nonceStart + 24, payload.size)
            return RustBridge.xchacha20Decrypt(ciphertext, key, nonce)?.also {
                require(it.size == expectedPlaintextLength) {
                    it.fill(0)
                    "Invalid C2 plaintext length"
                }
            } ?: throw IllegalArgumentException("Invalid C2 chunk authentication")
        } finally { key.fill(0) }
    }

    companion object {
        const val TYPE = 0xC2
        const val HEADER_BYTES = 253
        const val SIGNATURE_BYTES = 64
        const val CHUNK_BYTES = 64 * 1024
        const val MAX_BUNDLE_BYTES = 32 * 1024 * 1024
        const val MAX_ROSTER_BYTES = 32 * 1024
        const val HYBRID_BYTES = 1600
        const val AEAD_OVERHEAD = 40
        const val MAX_WIRE_BYTES = HEADER_BYTES + MAX_ROSTER_BYTES + HYBRID_BYTES +
            CHUNK_BYTES + AEAD_OVERHEAD + SIGNATURE_BYTES
        private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
        private val SIGNATURE_DOMAIN =
            "Secure-GROUP-TRANSPORT-v1/signature\u0000".toByteArray(Charsets.UTF_8)
        private val WRAP_DOMAIN =
            "Secure-GROUP-TRANSPORT-v1/wrap\u0000".toByteArray(Charsets.UTF_8)

        private fun wrapKey(shared: ByteArray, header: ByteArray, roster: ByteArray,
                            hybrid: ByteArray): ByteArray {
            require(shared.size == 64 && header.size == HEADER_BYTES &&
                roster.size in 1..MAX_ROSTER_BYTES && hybrid.size == HYBRID_BYTES)
            val context = header + hash(roster) + hash(hybrid)
            val salt = hash(WRAP_DOMAIN + context)
            val prk = hmac(salt, shared)
            return try { hmac(prk, WRAP_DOMAIN + context + byteArrayOf(1)) }
                finally { prk.fill(0); salt.fill(0) }
        }

        private fun hmac(key: ByteArray, body: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(key, "HmacSHA256"))
                doFinal(body)
            }

        fun parse(bytes: ByteArray): DeviceGroupFrame {
            require(bytes.size in HEADER_BYTES + SIGNATURE_BYTES..MAX_WIRE_BYTES &&
                (bytes[0].toInt() and 0xff) == TYPE && u32(bytes, 1) == bytes.size - 5L &&
                (bytes[5].toInt() and 0xff) == 1) { "Malformed C2 frame" }
            val kind = Kind.from(bytes[6].toInt() and 0xff)
                ?: throw IllegalArgumentException("Unknown C2 kind")
            val created = u64(bytes, 231)
            val index = u16(bytes, 239)
            val count = u16(bytes, 241)
            val total = u32(bytes, 243).toInt()
            val rosterLength = u16(bytes, 247)
            val payloadLength = u32(bytes, 249)
            require(created in 1..MAX_SAFE_INTEGER && rosterLength in 1..MAX_ROSTER_BYTES &&
                total in 1..MAX_BUNDLE_BYTES &&
                count == (total + CHUNK_BYTES - 1) / CHUNK_BYTES &&
                index in 0 until count &&
                (!isAck(kind) || index == 0) &&
                (kind != Kind.PROOF_REQUEST || count == 1 && total <= 519) &&
                (kind != Kind.PROOF_RESPONSE || count == 1 && total <= 2164) &&
                payloadLength == (if (isAck(kind)) 0L else
                    (HYBRID_BYTES + minOf(CHUNK_BYTES, total - index * CHUNK_BYTES) +
                        AEAD_OVERHEAD).toLong()) &&
                bytes.size.toLong() == HEADER_BYTES + rosterLength + payloadLength +
                    SIGNATURE_BYTES) { "Invalid C2 bounds" }
            require(bytes.sliceArray(167 until 199).any { it != 0.toByte() }) {
                "Zero C2 bundle ID"
            }
            fun slice(start: Int, end: Int) = bytes.copyOfRange(start, end)
            return DeviceGroupFrame(bytes.copyOf(), kind,
                slice(7, 39), slice(39, 71), deviceId(slice(71, 103)),
                deviceId(slice(103, 135)), slice(135, 167), slice(167, 199),
                slice(199, 231), created, index, count, total,
                slice(HEADER_BYTES, HEADER_BYTES + rosterLength),
                slice(HEADER_BYTES + rosterLength,
                    HEADER_BYTES + rosterLength + payloadLength.toInt()))
        }

        /** Call only after the entire bundle and its application are committed. */
        fun committedAck(original: DeviceGroupFrame, localAccount: ByteArray,
                         identity: LocalDeviceIdentity, signedRoster: ByteArray,
                         accountStored: Boolean = false,
                         nowMs: Long = System.currentTimeMillis()): DeviceGroupFrame {
            require(original.carriesData && localAccount.size == 32 &&
                original.recipientAccount.contentEquals(localAccount) &&
                original.recipientDeviceId == identity.deviceId &&
                signedRoster.size in 1..MAX_ROSTER_BYTES && nowMs in 1..MAX_SAFE_INTEGER)
            val bytes = ByteArray(HEADER_BYTES + signedRoster.size + SIGNATURE_BYTES)
            bytes[0] = TYPE.toByte()
            putU32(bytes, 1, bytes.size - 5)
            bytes[5] = 1
            bytes[6] = (if (accountStored) Kind.ACCOUNT_STORAGE_ACK else
                Kind.DEVICE_STORAGE_ACK).code.toByte()
            localAccount.copyInto(bytes, 7)
            original.senderAccount.copyInto(bytes, 39)
            decodeId(identity.deviceId).copyInto(bytes, 71)
            decodeId(original.senderDeviceId).copyInto(bytes, 103)
            original.groupId.copyInto(bytes, 135)
            original.bundleId.copyInto(bytes, 167)
            original.bundleHash.copyInto(bytes, 199)
            putU64(bytes, 231, nowMs)
            putU16(bytes, 239, 0)
            putU16(bytes, 241, original.chunkCount)
            putU32(bytes, 243, original.bundleLength)
            putU16(bytes, 247, signedRoster.size)
            putU32(bytes, 249, 0)
            signedRoster.copyInto(bytes, HEADER_BYTES)
            val signature = identity.sign(SIGNATURE_DOMAIN +
                bytes.copyOfRange(0, bytes.size - SIGNATURE_BYTES))
            require(signature.size == SIGNATURE_BYTES)
            signature.copyInto(bytes, bytes.size - SIGNATURE_BYTES)
            return parse(bytes)
        }

        /** Creates one encrypted C2 chunk for a currently authorized recipient. */
        fun sealChunk(kind: Kind, localAccount: ByteArray,
                      recipientAccount: ByteArray, recipientDeviceId: String,
                      recipientX: ByteArray, recipientKem: ByteArray,
                      identity: LocalDeviceIdentity, signedRoster: ByteArray,
                      groupId: ByteArray, bundleId: ByteArray, bundleHash: ByteArray,
                      bundleLength: Int, chunkIndex: Int, plaintext: ByteArray,
                      nowMs: Long = System.currentTimeMillis()): DeviceGroupFrame {
            require(kind != Kind.DEVICE_STORAGE_ACK && kind != Kind.ACCOUNT_STORAGE_ACK &&
                localAccount.size == 32 && recipientAccount.size == 32 &&
                recipientX.size == 32 && recipientKem.size == 1568 &&
                signedRoster.size in 1..MAX_ROSTER_BYTES &&
                groupId.size == 32 && bundleId.size == 32 &&
                bundleId.any { it != 0.toByte() } && bundleHash.size == 32 &&
                bundleLength in 1..MAX_BUNDLE_BYTES && nowMs in 1..MAX_SAFE_INTEGER)
            val count = (bundleLength + CHUNK_BYTES - 1) / CHUNK_BYTES
            require(chunkIndex in 0 until count &&
                plaintext.size == minOf(CHUNK_BYTES,
                    bundleLength - chunkIndex * CHUNK_BYTES) &&
                (kind != Kind.PROOF_REQUEST || count == 1 && bundleLength <= 519) &&
                (kind != Kind.PROOF_RESPONSE || count == 1 && bundleLength <= 2164))
            val hybridResult = RustBridge.hybridEncapsulate(recipientX, recipientKem)
            if (hybridResult.size != 64 + HYBRID_BYTES) {
                hybridResult.fill(0)
                throw IllegalArgumentException("Invalid C2 encapsulation result")
            }
            val shared = hybridResult.copyOfRange(0, 64)
            val hybrid = hybridResult.copyOfRange(64, hybridResult.size)
            hybridResult.fill(0)
            val bytes = ByteArray(HEADER_BYTES + signedRoster.size + HYBRID_BYTES +
                plaintext.size + AEAD_OVERHEAD + SIGNATURE_BYTES)
            bytes[0] = TYPE.toByte()
            putU32(bytes, 1, bytes.size - 5)
            bytes[5] = 1
            bytes[6] = kind.code.toByte()
            localAccount.copyInto(bytes, 7)
            recipientAccount.copyInto(bytes, 39)
            decodeId(identity.deviceId).copyInto(bytes, 71)
            decodeId(recipientDeviceId).copyInto(bytes, 103)
            groupId.copyInto(bytes, 135)
            bundleId.copyInto(bytes, 167)
            bundleHash.copyInto(bytes, 199)
            putU64(bytes, 231, nowMs)
            putU16(bytes, 239, chunkIndex)
            putU16(bytes, 241, count)
            putU32(bytes, 243, bundleLength)
            putU16(bytes, 247, signedRoster.size)
            putU32(bytes, 249, HYBRID_BYTES + plaintext.size + AEAD_OVERHEAD)
            signedRoster.copyInto(bytes, HEADER_BYTES)
            hybrid.copyInto(bytes, HEADER_BYTES + signedRoster.size)
            val key = try { wrapKey(shared, bytes.copyOfRange(0, HEADER_BYTES),
                signedRoster, hybrid) } finally { shared.fill(0) }
            try {
                val nonce = ByteArray(24).also(SecureRandom()::nextBytes)
                val ciphertext = RustBridge.xchacha20Encrypt(plaintext, key, nonce)
                require(ciphertext.size == plaintext.size + 16)
                val start = HEADER_BYTES + signedRoster.size + HYBRID_BYTES
                nonce.copyInto(bytes, start)
                ciphertext.copyInto(bytes, start + nonce.size)
            } finally { key.fill(0) }
            val signature = identity.sign(SIGNATURE_DOMAIN +
                bytes.copyOfRange(0, bytes.size - SIGNATURE_BYTES))
            require(signature.size == SIGNATURE_BYTES)
            signature.copyInto(bytes, bytes.size - SIGNATURE_BYTES)
            return parse(bytes)
        }

        fun hash(bytes: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(bytes)

        private fun isAck(kind: Kind) = kind == Kind.DEVICE_STORAGE_ACK ||
            kind == Kind.ACCOUNT_STORAGE_ACK
        private fun deviceId(bytes: ByteArray) =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        private fun decodeId(id: String): ByteArray {
            require(id.matches(Regex("[A-Za-z0-9_-]{43}")))
            return Base64.getUrlDecoder().decode(id).also { require(it.size == 32) }
        }
        private fun u16(bytes: ByteArray, offset: Int) =
            ((bytes[offset].toInt() and 0xff) shl 8) or
                (bytes[offset + 1].toInt() and 0xff)
        private fun u32(bytes: ByteArray, offset: Int): Long =
            (0 until 4).fold(0L) { value, i ->
                (value shl 8) or (bytes[offset + i].toLong() and 0xff)
            }
        private fun u64(bytes: ByteArray, offset: Int): Long =
            (0 until 8).fold(0L) { value, i ->
                (value shl 8) or (bytes[offset + i].toLong() and 0xff)
            }
        private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
            bytes[offset] = (value ushr 8).toByte()
            bytes[offset + 1] = value.toByte()
        }
        private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
            for (i in 0 until 4) bytes[offset + i] = (value ushr (24 - 8 * i)).toByte()
        }
        private fun putU64(bytes: ByteArray, offset: Int, value: Long) {
            for (i in 0 until 8) bytes[offset + i] = (value ushr (56 - 8 * i)).toByte()
        }
    }
}
