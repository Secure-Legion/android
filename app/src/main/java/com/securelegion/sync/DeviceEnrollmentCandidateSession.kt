package com.securelegion.sync

import android.util.Base64
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import org.json.JSONObject
import java.io.Closeable
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Candidate A3 exchange. A verified grant is inert until a profile commits it. */
internal class DeviceEnrollmentCandidateSession private constructor(
    private val device: LocalDeviceIdentity,
    val request: DeviceEnrollmentWire.CandidateQr,
    val qrPayload: String,
    private val ephemeralPrivate: ByteArray,
    private val kemPublic: ByteArray
) : Closeable {
    data class VerifiedGrant(val accountIdentity: ByteArray, val accountEd: ByteArray,
                             val certificate: ByteArray, val signedRoster: ByteArray,
                             val accountName: String, val ownerDeviceId: String,
                             val ownerOnion: String, val transcriptId: String,
                             val grantHash: String)

    private var owner: DeviceEnrollmentWire.Endpoint? = null
    private var accountIdentity: ByteArray? = null
    private var accountEd: ByteArray? = null
    private var transcript: ByteArray? = null
    private var id: String? = null
    private var confirmation = ByteArray(0)
    private var wrapping = ByteArray(0)
    private var acceptedOffer: ByteArray? = null
    private var candidateProof: ByteArray? = null
    private var localApproved = false
    private var ownerApproved = false
    private var closed = false

    val transcriptId: String? get() = id
    val ownerOnion: String? get() = owner?.onion
    /** Protect this seed in app Keystore storage until grant commit or QR expiry. */
    fun checkpointEphemeral(): ByteArray {
        requireOpen()
        require(owner == null)
        return ephemeralPrivate.copyOf()
    }
    val comparisonCode: String get() {
        requireReady()
        val mac = hmac(confirmation, proof("comparison"))
        val value = (((mac[0].toLong() and 255) shl 24) or
            ((mac[1].toLong() and 255) shl 16) or
            ((mac[2].toLong() and 255) shl 8) or (mac[3].toLong() and 255)) % 1_000_000
        return "%03d-%03d".format(value / 1000, value % 1000)
    }

    fun acceptOffer(wire: ByteArray): ByteArray {
        requireOpen()
        val frame = DeviceEnrollmentWire.decodeFrame(wire)
        require(frame.type == "offer" && frame.version == request.version &&
            frame.body.keys().asSequence().toSet() == setOf("v", "id", "type", "qr", "owner", "proof"))
        require(MessageDigest.isEqual(DeviceEnrollmentWire.canonicalJson(frame.body.getJSONObject("qr")),
            DeviceEnrollmentWire.canonicalJson(request.raw)))
        acceptedOffer?.let {
            require(it.contentEquals(wire))
            return candidateProof!!.copyOf()
        }
        val ownerObject = frame.body.getJSONObject("owner")
        val endpoint = DeviceEnrollmentWire.parseOwnerEndpoint(ownerObject)
        require(endpoint.deviceId != device.deviceId && endpoint.onion != device.onionAddress)
        val identity = endpoint.accountIdentity ?: throw IllegalArgumentException("Missing account identity")
        val pinned = identity.copyOfRange(6, 38)
        request.pinnedAccount?.let { require(MessageDigest.isEqual(it, pinned)) }
        val verifiedIdentity = auth(JSONObject().put("operation", "verify_account_identity")
            .put("identity", b64(identity)).put("pinned_account", b64(pinned)))
        require(verifiedIdentity.getString("account_ed") == b64(pinned))
        val bytes = DeviceEnrollmentWire.transcript(request, ownerObject)
        val transcriptId = DeviceEnrollmentWire.transcriptId(bytes)
        require(frame.transcriptId == transcriptId)
        var shared = RustBridge.deriveSharedSecret(ephemeralPrivate, endpoint.ephemeralPublicKey)
        var confirmationKey = ByteArray(0)
        var wrappingKey = ByteArray(0)
        try {
            require(shared.size == 32 && shared.any { it != 0.toByte() })
            confirmationKey = RustBridge.deriveRootKey(shared, "$DOMAIN/confirmation/$transcriptId")
            wrappingKey = RustBridge.deriveRootKey(shared, "$DOMAIN/grant/$transcriptId")
            require(confirmationKey.size == 32 && wrappingKey.size == 32)
            require(verifyProof(frame.body.getJSONObject("proof"), "offer", pinned,
                bytes, confirmationKey))
            val candidateMessage = DeviceEnrollmentWire.proofBytes(DOMAIN, "candidate_proof", bytes)
            val candidateSignature = device.sign(candidateMessage)
            val proof = JSONObject().put("sig", b64(candidateSignature))
                .put("mac", b64(hmac(confirmationKey, candidateMessage)))
            val reply = DeviceEnrollmentWire.encodeFrame(JSONObject().put("v", 1)
                .put("id", transcriptId).put("type", "candidate_proof")
                .put("kem_public", b64(kemPublic)).put("proof", proof))
            owner = endpoint
            accountIdentity = identity
            accountEd = pinned
            transcript = bytes
            id = transcriptId
            confirmation = confirmationKey
            wrapping = wrappingKey
            acceptedOffer = wire.copyOf()
            candidateProof = reply.copyOf()
            ephemeralPrivate.fill(0)
            return reply
        } finally {
            shared.fill(0)
            if (owner == null) { confirmationKey.fill(0); wrappingKey.fill(0) }
        }
    }

    fun approveComparison(): ByteArray {
        requireReady()
        localApproved = true
        return DeviceEnrollmentWire.encodeFrame(baseFrame("candidate_approval")
            .put("proof", makeProof("candidate_approval")))
    }

    fun acceptOwnerApproval(wire: ByteArray) {
        requireReady()
        val frame = requireFrame(wire, "owner_approval", setOf("v", "id", "type", "proof"))
        require(verifyProof(frame.getJSONObject("proof"), "owner_approval", accountEd!!,
            transcript!!, confirmation))
        ownerApproved = true
    }

    fun acceptGrant(wire: ByteArray): VerifiedGrant {
        requireReady()
        require(localApproved && ownerApproved)
        val frame = requireFrame(wire, "grant", setOf("v", "id", "type", "ct", "proof"))
        val ciphertext = canonicalB64(frame.getString("ct"), 40, 96 * 1024)
        require(verifyProof(frame.getJSONObject("proof"), "grant", accountEd!!,
            transcript!!, confirmation, ciphertext))
        val plaintext = RustBridge.xchacha20Decrypt(ciphertext.copyOfRange(24, ciphertext.size),
            wrapping, ciphertext.copyOfRange(0, 24)) ?: throw IllegalArgumentException("Invalid grant")
        try {
            val grant = JSONObject(plaintext.toString(Charsets.UTF_8))
            require(grant.keys().asSequence().toSet() == setOf("v", "id", "identity", "certificate",
                "roster", "account_name") && grant.getInt("v") == 1 && grant.getString("id") == id)
            val accountName = grant.getString("account_name")
            require(accountName.isNotBlank() && accountName.codePointCount(0, accountName.length) <= 64 &&
                accountName.codePoints().noneMatch { it < 32 || it in 127..159 })
            val grantedIdentity = canonicalB64(grant.getString("identity"), 1702, 1702)
            require(MessageDigest.isEqual(grantedIdentity, accountIdentity!!))
            val certificate = canonicalB64(grant.getString("certificate"), 274, 274)
            val cert = auth(JSONObject().put("operation", "verify_certificate")
                .put("certificate", b64(certificate)).put("pinned_account", b64(accountEd!!)))
            require(cert.getString("device_id") == device.deviceId &&
                cert.getString("device_ed") == b64(device.signingPublicKey) &&
                cert.getString("device_x") == b64(device.encryptionPublicKey) &&
                cert.getString("onion") + ".onion" == device.onionAddress &&
                cert.getString("ml_kem_public_hash") == b64(sha256(kemPublic)))
            val roster = canonicalB64(grant.getString("roster"), 1, 32 * 1024)
            val verifiedRoster = auth(JSONObject().put("operation", "verify_roster")
                .put("roster", b64(roster)).put("pinned_account", b64(accountEd!!))
                .put("previous_roster", JSONObject.NULL).put("now_ms", System.currentTimeMillis())
                .put("authorize", JSONObject().put("device_id", device.deviceId)
                    .put("capabilities", 0x07)))
            require(verifiedRoster.getString("primary_device_id") == owner!!.deviceId)
            val entries = verifiedRoster.getJSONArray("entries")
            var selfMatch = false
            var ownerMatch = false
            for (index in 0 until entries.length()) {
                val entry = entries.getJSONObject(index)
                val member = entry.getJSONObject("certificate")
                when (member.getString("device_id")) {
                    device.deviceId -> selfMatch = member.getString("certificate") == b64(certificate) &&
                        entry.getString("ml_kem_public") == b64(kemPublic)
                    owner!!.deviceId -> ownerMatch = member.getString("device_ed") == b64(owner!!.signingPublicKey) &&
                        member.getString("device_x") == b64(owner!!.encryptionPublicKey) &&
                        member.getString("onion") + ".onion" == owner!!.onion &&
                        member.getString("ml_kem_public_hash") == b64(owner!!.kemHash)
                }
            }
            require(selfMatch && ownerMatch)
            return VerifiedGrant(grantedIdentity, accountEd!!.copyOf(), certificate, roster,
                accountName, owner!!.deviceId, owner!!.onion, id!!,
                sha256(ciphertext).joinToString("") { "%02x".format(it.toInt() and 255) })
        } finally { plaintext.fill(0) }
    }

    fun committedReceipt(grant: VerifiedGrant): ByteArray {
        requireReady()
        require(localApproved && ownerApproved && grant.transcriptId == id &&
            MessageDigest.isEqual(grant.accountEd, accountEd!!))
        val message = "$DOMAIN/committed\u0000${grant.transcriptId}\u0000${grant.grantHash}"
            .toByteArray(Charsets.UTF_8)
        return DeviceEnrollmentWire.encodeFrame(baseFrame("committed")
            .put("grant_hash", grant.grantHash).put("sig", b64(device.sign(message))))
    }

    private fun baseFrame(type: String) = JSONObject().put("v", 1).put("id", id).put("type", type)
    private fun requireFrame(wire: ByteArray, type: String, fields: Set<String>): JSONObject {
        val frame = DeviceEnrollmentWire.decodeFrame(wire)
        require(frame.version == 1 && frame.transcriptId == id && frame.type == type &&
            frame.body.keys().asSequence().toSet() == fields)
        return frame.body
    }
    private fun proof(purpose: String, extra: ByteArray? = null) =
        DeviceEnrollmentWire.proofBytes(DOMAIN, purpose, transcript!!, extra)
    private fun makeProof(purpose: String): JSONObject {
        val message = proof(purpose)
        return JSONObject().put("sig", b64(device.sign(message)))
            .put("mac", b64(hmac(confirmation, message)))
    }
    private fun requireOpen() {
        check(!closed)
        if (System.currentTimeMillis() >= request.expiresAtMs) { close(); error("Enrollment expired") }
    }
    private fun requireReady() { requireOpen(); check(owner != null && id != null) }
    override fun close() {
        if (closed) return
        ephemeralPrivate.fill(0); confirmation.fill(0); wrapping.fill(0)
        closed = true
    }

    companion object {
        private const val DOMAIN = "Secure-ENROLL-v1"
        fun restore(device: LocalDeviceIdentity, qrPayload: String,
                    ephemeralPrivate: ByteArray,
                    nowMs: Long = System.currentTimeMillis()): DeviceEnrollmentCandidateSession {
            require(ephemeralPrivate.size == 32)
            val parsed = DeviceEnrollmentWire.parseCandidateQr(qrPayload, nowMs)
            require(parsed.version == 1 && parsed.candidate.deviceId == device.deviceId &&
                parsed.candidate.onion == device.onionAddress &&
                parsed.candidate.signingPublicKey.contentEquals(device.signingPublicKey) &&
                parsed.candidate.encryptionPublicKey.contentEquals(device.encryptionPublicKey))
            val public = ByteArray(32)
            check(LazySodiumAndroid(SodiumAndroid()).cryptoScalarMultBase(public, ephemeralPrivate))
            require(public.contentEquals(parsed.candidate.ephemeralPublicKey))
            val kem = device.mlKemPublicKey()
            require(sha256(kem).contentEquals(parsed.candidate.kemHash))
            return DeviceEnrollmentCandidateSession(device, parsed, qrPayload,
                ephemeralPrivate.copyOf(), kem)
        }

        fun create(device: LocalDeviceIdentity, deviceName: String,
                   nowMs: Long = System.currentTimeMillis()): DeviceEnrollmentCandidateSession {
            require(deviceName.isNotBlank() && deviceName.codePointCount(0, deviceName.length) <= 64 &&
                deviceName.codePoints().noneMatch { it < 32 || it in 127..159 })
            val ephemeral = ByteArray(32).also { SecureRandom().nextBytes(it) }
            try {
                val public = ByteArray(32)
                check(LazySodiumAndroid(SodiumAndroid()).cryptoScalarMultBase(public, ephemeral))
                val kem = device.mlKemPublicKey()
                val endpoint = JSONObject().put("role", "candidate")
                    .put("device_id", device.deviceId).put("device_name", deviceName)
                    .put("platform", "Android").put("onion", device.onionAddress)
                    .put("device_ed", b64(device.signingPublicKey))
                    .put("device_x", b64(device.encryptionPublicKey))
                    .put("kem_hash", b64(sha256(kem))).put("e_pub", b64(public))
                    .put("nonce", b64(ByteArray(32).also { SecureRandom().nextBytes(it) }))
                val qr = JSONObject().put("v", 1).put("t", "SL_ENROLL")
                    .put("expires", nowMs + 300_000).put("candidate", endpoint)
                val payload = DeviceEnrollmentWire.canonicalJson(qr).toString(Charsets.UTF_8)
                val parsed = DeviceEnrollmentWire.parseCandidateQr(payload, nowMs)
                return DeviceEnrollmentCandidateSession(device, parsed, payload, ephemeral, kem)
            } catch (e: Exception) { ephemeral.fill(0); throw e }
        }
        private fun auth(request: JSONObject): JSONObject = JSONObject(RustBridge.deviceAuthorization(
            request.toString().toByteArray(Charsets.UTF_8), null).toString(Charsets.UTF_8))
        private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
        private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun canonicalB64(value: String, minimum: Int, maximum: Int): ByteArray {
            val bytes = Base64.decode(value, Base64.DEFAULT)
            require(bytes.size in minimum..maximum && b64(bytes) == value)
            return bytes
        }
        private fun hmac(key: ByteArray, message: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(message)
        private fun verifyProof(value: JSONObject, purpose: String, publicKey: ByteArray,
                                transcript: ByteArray, key: ByteArray,
                                extra: ByteArray? = null): Boolean {
            if (value.keys().asSequence().toSet() != setOf("sig", "mac")) return false
            val signature = try { canonicalB64(value.getString("sig"), 64, 64) }
                catch (_: Exception) { return false }
            val mac = try { canonicalB64(value.getString("mac"), 32, 32) }
                catch (_: Exception) { return false }
            val message = DeviceEnrollmentWire.proofBytes(DOMAIN, purpose, transcript, extra)
            return MessageDigest.isEqual(mac, hmac(key, message)) &&
                RustBridge.verifySignature(message, signature, publicKey)
        }
    }
}
