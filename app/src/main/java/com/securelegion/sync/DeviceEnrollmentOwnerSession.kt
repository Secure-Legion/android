package com.securelegion.sync

import android.util.Base64
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import org.json.JSONObject
import java.io.Closeable
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** In-memory primary-device A3 authentication. No roster changes occur here. */
internal class DeviceEnrollmentOwnerSession private constructor(
    val request: DeviceEnrollmentWire.CandidateQr,
    val ownerEndpoint: DeviceEnrollmentWire.Endpoint,
    val transcriptId: String,
    val accountIdentity: ByteArray,
    val accountSigningPublicKey: ByteArray,
    private val transcript: ByteArray,
    private val signingSeed: ByteArray,
    private val confirmationKey: ByteArray,
    private val grantWrappingKey: ByteArray,
    private val offer: ByteArray
) : Closeable {
    private var candidateKemPublic: ByteArray? = null
    private var localApproved = false
    private var candidateApproved = false
    private var closed = false

    val candidateDeviceId: String get() = request.candidate.deviceId
    val candidateName: String get() = request.candidate.name
    val candidateOnion: String get() = request.candidate.onion
    val canIssueGrant: Boolean get() = !closed && localApproved && candidateApproved && candidateKemPublic != null

    val comparisonCode: String get() {
        requireOpen()
        val mac = hmac(confirmationKey, proof("comparison"))
        val value = (((mac[0].toLong() and 255) shl 24) or
            ((mac[1].toLong() and 255) shl 16) or
            ((mac[2].toLong() and 255) shl 8) or (mac[3].toLong() and 255)) % 1_000_000
        return "%03d-%03d".format(value / 1000, value % 1000)
    }

    fun encodedOffer(): ByteArray { requireOpen(); return offer.copyOf() }

    fun acceptCandidateProof(wire: ByteArray) {
        requireOpen()
        val frame = requireFrame(wire, "candidate_proof", setOf("v", "id", "type", "kem_public", "proof"))
        val encoded = frame.getString("kem_public")
        require(encoded.length == 2092)
        val kem = Base64.decode(encoded, Base64.DEFAULT)
        require(kem.size == 1568 && b64(kem) == encoded)
        require(MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(kem),
            request.candidate.kemHash))
        require(verifyProof(frame.getJSONObject("proof"), "candidate_proof",
            request.candidate.signingPublicKey))
        candidateKemPublic?.fill(0)
        candidateKemPublic = kem
    }

    fun approveComparison(): ByteArray {
        requireOpen()
        localApproved = true
        return DeviceEnrollmentWire.encodeFrame(baseFrame("owner_approval")
            .put("proof", makeProof("owner_approval")))
    }

    fun acceptCandidateApproval(wire: ByteArray) {
        requireOpen()
        val frame = requireFrame(wire, "candidate_approval", setOf("v", "id", "type", "proof"))
        require(verifyProof(frame.getJSONObject("proof"), "candidate_approval",
            request.candidate.signingPublicKey))
        candidateApproved = true
    }

    fun <T> withProvenCandidateKemKey(block: (ByteArray) -> T): T {
        requireOpen()
        val key = candidateKemPublic ?: throw IllegalStateException("Candidate key not proven")
        val copy = key.copyOf()
        return try { block(copy) } finally { copy.fill(0) }
    }

    private fun requireFrame(wire: ByteArray, type: String, fields: Set<String>): JSONObject {
        val frame = DeviceEnrollmentWire.decodeFrame(wire)
        require(frame.version == request.version && frame.transcriptId == transcriptId && frame.type == type)
        val keys = frame.body.keys().asSequence().toSet()
        require(keys == fields)
        return frame.body
    }

    private fun baseFrame(type: String) = JSONObject().put("v", request.version)
        .put("id", transcriptId).put("type", type)

    private fun proof(purpose: String, extra: ByteArray? = null): ByteArray =
        DeviceEnrollmentWire.proofBytes(if (request.version == 1) "Secure-ENROLL-v1"
            else "Secure-RECOVER-v1", purpose, transcript, extra)

    private fun makeProof(purpose: String): JSONObject {
        val bytes = proof(purpose)
        val signature = RustBridge.signData(bytes, signingSeed)
        require(signature.size == 64)
        return JSONObject().put("sig", b64(signature))
            .put("mac", b64(hmac(confirmationKey, bytes)))
    }

    private fun verifyProof(value: JSONObject, purpose: String, publicKey: ByteArray): Boolean {
        if (value.keys().asSequence().toSet() != setOf("sig", "mac")) return false
        val signature = decodeExact(value.optString("sig"), 64) ?: return false
        val mac = decodeExact(value.optString("mac"), 32) ?: return false
        val bytes = proof(purpose)
        return MessageDigest.isEqual(mac, hmac(confirmationKey, bytes)) &&
            RustBridge.verifySignature(bytes, signature, publicKey)
    }

    private fun requireOpen() {
        check(!closed)
        if (System.currentTimeMillis() >= request.expiresAtMs) {
            close()
            throw IllegalStateException("Enrollment expired")
        }
    }

    override fun close() {
        if (closed) return
        signingSeed.fill(0)
        confirmationKey.fill(0)
        grantWrappingKey.fill(0)
        candidateKemPublic?.fill(0)
        closed = true
    }

    companion object {
        fun create(qrPayload: String, keys: KeyManager, owner: LocalDeviceIdentity,
                   ownerName: String, nowMs: Long = System.currentTimeMillis()): DeviceEnrollmentOwnerSession {
            val request = DeviceEnrollmentWire.parseCandidateQr(qrPayload, nowMs)
            val accountEd = keys.getSigningPublicKey()
            val accountX = keys.getEncryptionPublicKey()
            val accountKem = keys.getKyberPublicKey()
            require(accountEd.size == 32 && accountX.size == 32 && accountKem.size == 1568)
            request.pinnedAccount?.let { require(MessageDigest.isEqual(it, accountEd)) }
            val seed = keys.getSigningKeyBytes()
            var ephemeral = ByteArray(32)
            var shared = ByteArray(0)
            var confirmation = ByteArray(0)
            var wrapping = ByteArray(0)
            var success = false
            try {
                require(seed.size == 32)
                val identityResponse = JSONObject(RustBridge.deviceAuthorization(
                    JSONObject().put("operation", "issue_account_identity")
                        .put("account_x", b64(accountX)).put("account_kem", b64(accountKem))
                        .toString().toByteArray(Charsets.UTF_8), seed
                ).toString(Charsets.UTF_8))
                val identityEncoded = identityResponse.getString("identity")
                val identity = decodeExact(identityEncoded, 1702)
                    ?: throw IllegalArgumentException("Invalid account identity")
                require(identityResponse.getString("account_ed") == b64(accountEd))
                SecureRandom().nextBytes(ephemeral)
                val public = ByteArray(32)
                check(LazySodiumAndroid(SodiumAndroid()).cryptoScalarMultBase(public, ephemeral))
                val kem = owner.mlKemPublicKey()
                val ownerObject = JSONObject().put("role", "owner")
                    .put("device_id", owner.deviceId).put("device_name", ownerName)
                    .put("platform", "Android").put("onion", owner.onionAddress)
                    .put("device_ed", b64(owner.signingPublicKey))
                    .put("device_x", b64(owner.encryptionPublicKey))
                    .put("kem_hash", b64(MessageDigest.getInstance("SHA-256").digest(kem)))
                    .put("e_pub", b64(public)).put("nonce", b64(ByteArray(32).also { SecureRandom().nextBytes(it) }))
                    .put("account_identity", identityEncoded)
                kem.fill(0)
                val endpoint = DeviceEnrollmentWire.parseOwnerEndpoint(ownerObject)
                val transcript = DeviceEnrollmentWire.transcript(request, ownerObject)
                val id = DeviceEnrollmentWire.transcriptId(transcript)
                shared = RustBridge.deriveSharedSecret(ephemeral, request.candidate.ephemeralPublicKey)
                require(shared.size == 32 && shared.any { it != 0.toByte() })
                val domain = if (request.version == 1) "Secure-ENROLL-v1" else "Secure-RECOVER-v1"
                confirmation = RustBridge.deriveRootKey(shared, "$domain/confirmation/$id")
                wrapping = RustBridge.deriveRootKey(shared, "$domain/grant/$id")
                require(confirmation.size == 32 && wrapping.size == 32)
                val offerProof = DeviceEnrollmentWire.proofBytes(domain, "offer", transcript)
                val signature = RustBridge.signData(offerProof, seed)
                require(signature.size == 64 && RustBridge.verifySignature(offerProof, signature, accountEd))
                val offer = DeviceEnrollmentWire.encodeFrame(JSONObject().put("v", request.version)
                    .put("id", id).put("type", "offer").put("qr", request.raw)
                    .put("owner", ownerObject).put("proof", JSONObject()
                        .put("sig", b64(signature)).put("mac", b64(hmac(confirmation, offerProof)))))
                success = true
                return DeviceEnrollmentOwnerSession(request, endpoint, id, identity, accountEd,
                    transcript, seed, confirmation, wrapping, offer)
            } finally {
                ephemeral.fill(0); shared.fill(0)
                if (!success) { seed.fill(0); confirmation.fill(0); wrapping.fill(0) }
            }
        }

        private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
        private fun decodeExact(value: String, size: Int): ByteArray? = try {
            val decoded = Base64.decode(value, Base64.DEFAULT)
            if (decoded.size == size && b64(decoded) == value) decoded else null
        } catch (_: Exception) { null }

        private fun hmac(key: ByteArray, message: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(message)
    }
}
