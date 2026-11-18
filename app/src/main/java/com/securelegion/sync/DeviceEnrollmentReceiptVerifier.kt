package com.securelegion.sync

import android.util.Base64
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import java.security.MessageDigest

/** Completes only the exact durable grant named by an authorized candidate receipt. */
internal class DeviceEnrollmentReceiptVerifier(private val roster: DeviceRosterStore) {
    fun verifyAndComplete(wire: ByteArray): Boolean {
        val ack = DeviceEnrollmentWire.decodeFrame(wire)
        if (ack.type != "committed" ||
            ack.body.keys().asSequence().toSet() != setOf("v", "id", "type", "grant_hash", "sig")) return false
        val pending = roster.pendingEnrollmentGrant(ack.transcriptId) ?: return false
        val peer = roster.authorizedPeer(pending.account, pending.candidateDeviceId, 0x02)
            ?: return false
        val grant = DeviceEnrollmentWire.decodeFrame(pending.wireFrame)
        if (grant.version != ack.version || grant.transcriptId != ack.transcriptId ||
            grant.type != "grant") return false
        val encodedCiphertext = grant.body.optString("ct")
        val ciphertext = decodeCanonical(encodedCiphertext) ?: return false
        val hash = MessageDigest.getInstance("SHA-256").digest(ciphertext)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        if (ack.body.optString("grant_hash") != hash) return false
        val signature = decodeCanonical(ack.body.optString("sig")) ?: return false
        if (signature.size != 64) return false
        val domain = if (ack.version == 1) "Secure-ENROLL-v1" else "Secure-RECOVER-v1"
        val message = "$domain/committed\u0000${ack.transcriptId}\u0000$hash".toByteArray(Charsets.UTF_8)
        if (!RustBridge.verifySignature(message, signature, peer.signingKey)) return false
        return roster.completeEnrollmentGrant(pending)
    }

    private fun decodeCanonical(encoded: String): ByteArray? = try {
        val bytes = Base64.decode(encoded, Base64.DEFAULT)
        if (Base64.encodeToString(bytes, Base64.NO_WRAP) == encoded) bytes else null
    } catch (_: Exception) { null }
}
