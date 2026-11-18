package com.securelegion.sync

import android.util.Base64
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** Primary-only issuer. All signatures and roster validation use the portable Rust API. */
internal class DeviceRosterAuthority(private val store: DeviceRosterStore) {
    data class EnrollmentAuthorization(val certificate: ByteArray, val signedRoster: ByteArray,
                                       val epoch: Long, val exactGrant: ByteArray)
    private val encoder = Base64.NO_WRAP
    private val certificateLifetimeMs = 365L * 24 * 60 * 60 * 1000
    private val maxTime = 9_007_199_254_740_991L

    fun ensurePrimaryRoster(
        keyManager: KeyManager,
        identity: LocalDeviceIdentity,
        displayName: String,
        nowMs: Long = System.currentTimeMillis()
    ): DeviceRosterStore.AcceptedRoster {
        val account = keyManager.getSigningPublicKey()
        require(account.size == 32 && displayName.isNotBlank())
        val existing = store.fetchSignedRoster(account)
        if (existing != null) {
            val verified = verifyRoster(existing, account, nowMs, identity.deviceId, 0x07)
            require(verified.getString("primary_device_id") == identity.deviceId)
            val entries = verified.getJSONArray("entries")
            return DeviceRosterStore.AcceptedRoster(
                verified.getLong("epoch"), identity.deviceId,
                (0 until entries.length()).map {
                    entries.getJSONObject(it).getJSONObject("certificate").getString("device_id")
                }
            )
        }
        require(nowMs in 1..(maxTime - certificateLifetimeMs))
        val kem = identity.mlKemPublicKey()
        val seed = keyManager.getSigningKeyBytes()
        try {
            require(seed.size == 32)
            val certificate = issueCertificate(
                account, identity.signingPublicKey, identity.encryptionPublicKey,
                kem, identity.onionAddress, nowMs, nowMs + certificateLifetimeMs, seed
            )
            val entry = JSONObject().put("certificate", b64(certificate))
                .put("ml_kem_public", b64(kem)).put("name", displayName)
            val request = JSONObject().put("operation", "issue_roster")
                .put("epoch", 1).put("issued_at_ms", nowMs)
                .put("primary_device_id", identity.deviceId)
                .put("entries", JSONArray().put(entry))
            val roster = Base64.decode(call(request, seed).getString("roster"), Base64.DEFAULT)
            return store.acceptSignedRoster(roster, account, identity.deviceId, nowMs)
        } finally { seed.fill(0); kem.fill(0) }
    }

    /** Sign and durably commit enrollment before the encrypted grant may be sent. */
    fun authorizeEnrollment(keyManager: KeyManager, owner: LocalDeviceIdentity,
                            session: DeviceEnrollmentOwnerSession, ownerName: String,
                            accountName: String, nowMs: Long = System.currentTimeMillis()): EnrollmentAuthorization {
        require(session.request.version == 1 && session.canIssueGrant)
        val account = keyManager.getSigningPublicKey()
        require(account.contentEquals(session.accountSigningPublicKey))
        val previous = store.fetchSignedRoster(account) ?: run {
            ensurePrimaryRoster(keyManager, owner, ownerName, nowMs)
            store.fetchSignedRoster(account) ?: throw IllegalStateException("Primary roster unavailable")
        }
        val current = verifyRoster(previous, account, nowMs, owner.deviceId, 0x07)
        require(current.getString("primary_device_id") == owner.deviceId)
        val oldEpoch = current.getLong("epoch")
        require(oldEpoch in 1 until maxTime && nowMs in 1..(maxTime - certificateLifetimeMs))
        val issuedAt = maxOf(nowMs, current.getLong("issued_at_ms") + 1)
        require(issuedAt < maxTime && issuedAt <= maxTime - certificateLifetimeMs)
        val entries = JSONArray()
        val currentEntries = current.getJSONArray("entries")
        var ownerMatches = false
        for (index in 0 until currentEntries.length()) {
            val entry = currentEntries.getJSONObject(index)
            val cert = entry.getJSONObject("certificate")
            require(cert.getString("device_id") != session.candidateDeviceId)
            if (cert.getString("device_id") == owner.deviceId) {
                require(cert.getString("device_ed") == b64(owner.signingPublicKey) &&
                    cert.getString("device_x") == b64(owner.encryptionPublicKey) &&
                    cert.getString("onion") + ".onion" == owner.onionAddress)
                ownerMatches = true
            }
            entries.put(JSONObject().put("certificate", cert.getString("certificate"))
                .put("ml_kem_public", entry.getString("ml_kem_public"))
                .put("name", entry.getString("name")))
        }
        require(ownerMatches && entries.length() in 1..7)
        val seed = keyManager.getSigningKeyBytes()
        try {
            require(seed.size == 32)
            return session.withProvenCandidateKemKey { candidateKem ->
                val certificate = issueCertificate(account, session.request.candidate.signingPublicKey,
                    session.request.candidate.encryptionPublicKey, candidateKem,
                    session.candidateOnion, issuedAt, issuedAt + certificateLifetimeMs, seed)
                entries.put(JSONObject().put("certificate", b64(certificate))
                    .put("ml_kem_public", b64(candidateKem)).put("name", session.candidateName))
                val response = call(JSONObject().put("operation", "issue_roster")
                    .put("epoch", oldEpoch + 1).put("issued_at_ms", issuedAt)
                    .put("primary_device_id", owner.deviceId).put("entries", entries), seed)
                val signedRoster = Base64.decode(response.getString("roster"), Base64.DEFAULT)
                val exactGrant = session.createGrant(certificate, signedRoster, accountName)
                val accepted = try {
                    store.acceptSignedRoster(signedRoster, account, owner.deviceId, nowMs,
                        DeviceRosterStore.PendingGrant(session.transcriptId, session.candidateDeviceId,
                            exactGrant, session.request.expiresAtMs))
                } catch (e: Exception) { session.discardUncommittedGrant(); throw e }
                require(accepted.epoch == oldEpoch + 1 && accepted.primaryDeviceId == owner.deviceId &&
                    session.candidateDeviceId in accepted.deviceIds)
                EnrollmentAuthorization(certificate, signedRoster, accepted.epoch, exactGrant)
            }
        } finally { seed.fill(0) }
    }

    /** Revoke through a newly signed complete roster; never delete only a local row. */
    fun revoke(
        keyManager: KeyManager,
        identity: LocalDeviceIdentity,
        revokedIds: Set<String>,
        nowMs: Long = System.currentTimeMillis()
    ): DeviceRosterStore.AcceptedRoster {
        require(revokedIds.isNotEmpty() && revokedIds.size <= 7)
        require(identity.deviceId !in revokedIds && revokedIds.all { it.length == 43 })
        val account = keyManager.getSigningPublicKey()
        val previous = store.fetchSignedRoster(account)
            ?: throw IllegalStateException("No signed roster")
        val current = verifyRoster(previous, account, nowMs, identity.deviceId, 0x07)
        require(current.getString("primary_device_id") == identity.deviceId)
        val oldEpoch = current.getLong("epoch")
        require(oldEpoch in 1 until maxTime && nowMs in 1..maxTime)
        val oldEntries = current.getJSONArray("entries")
        val retained = JSONArray()
        val found = HashSet<String>()
        for (index in 0 until oldEntries.length()) {
            val old = oldEntries.getJSONObject(index)
            val id = old.getJSONObject("certificate").getString("device_id")
            if (id in revokedIds) found.add(id) else retained.put(JSONObject()
                .put("certificate", old.getJSONObject("certificate").getString("certificate"))
                .put("ml_kem_public", old.getString("ml_kem_public"))
                .put("name", old.getString("name")))
        }
        require(found == revokedIds && retained.length() in 1..8)
        val issuedAt = maxOf(nowMs, current.getLong("issued_at_ms") + 1)
        require(issuedAt <= maxTime)
        val seed = keyManager.getSigningKeyBytes()
        try {
            val request = JSONObject().put("operation", "issue_roster")
                .put("epoch", oldEpoch + 1).put("issued_at_ms", issuedAt)
                .put("primary_device_id", identity.deviceId).put("entries", retained)
            val roster = Base64.decode(call(request, seed).getString("roster"), Base64.DEFAULT)
            return store.acceptSignedRoster(roster, account, identity.deviceId, nowMs)
        } finally { seed.fill(0) }
    }

    private fun issueCertificate(
        account: ByteArray, ed: ByteArray, x: ByteArray, kem: ByteArray,
        onion: String, issuedAt: Long, expiresAt: Long, seed: ByteArray
    ): ByteArray {
        require(onion.length == 62 && onion.endsWith(".onion"))
        val claims = JSONObject()
            .put("account_ed", b64(account)).put("device_ed", b64(ed))
            .put("device_x", b64(x))
            .put("ml_kem_public_hash", b64(MessageDigest.getInstance("SHA-256").digest(kem)))
            .put("onion", onion.removeSuffix(".onion"))
            .put("issued_at_ms", issuedAt).put("expires_at_ms", expiresAt)
            .put("capabilities", 0x07)
        val response = call(JSONObject().put("operation", "issue_certificate")
            .put("claims", claims), seed)
        return Base64.decode(response.getString("certificate"), Base64.DEFAULT)
    }

    private fun verifyRoster(roster: ByteArray, account: ByteArray, nowMs: Long,
                             localId: String, capability: Int): JSONObject {
        val request = JSONObject().put("operation", "verify_roster")
            .put("roster", b64(roster)).put("pinned_account", b64(account))
            .put("previous_roster", JSONObject.NULL).put("now_ms", nowMs)
            .put("authorize", JSONObject().put("device_id", localId)
                .put("capabilities", capability))
        return call(request, null)
    }

    private fun call(request: JSONObject, seed: ByteArray?): JSONObject = JSONObject(
        RustBridge.deviceAuthorization(request.toString().toByteArray(Charsets.UTF_8), seed)
            .toString(Charsets.UTF_8)
    )

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, encoder)
}
