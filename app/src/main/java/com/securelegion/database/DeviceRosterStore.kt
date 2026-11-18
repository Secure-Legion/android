package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.RustBridge
import org.json.JSONObject
import java.security.MessageDigest

/**
 * The durable authorization boundary for independent device endpoints.
 * Call off the main thread and only while the SQLCipher profile is unlocked.
 * No network worker may use a certificate without checking this store again.
 */
class DeviceRosterStore(private val database: SecureLegionDatabase) {
    data class AcceptedRoster(val epoch: Long, val primaryDeviceId: String, val deviceIds: List<String>)
    data class PendingGrant(val transcriptId: String, val candidateDeviceId: String,
                            val wireFrame: ByteArray, val expiresAtMs: Long)
    data class PendingGrantRecord(val transcriptId: String, val account: ByteArray,
                                  val candidateDeviceId: String, val wireFrame: ByteArray,
                                  val expiresAtMs: Long)
    private data class Endpoint(val onion: String, val signingKey: ByteArray)

    data class DeviceView(
        val deviceId: String,
        val displayName: String,
        val onion: String,
        val capabilities: Int,
        val expiresAtMs: Long,
        val isSelf: Boolean
    )

    data class PeerKeys(val deviceId: String, val signingKey: ByteArray,
                        val encryptionKey: ByteArray, val onion: String)

    fun authorizedPeer(pinnedAccount: ByteArray, deviceId: String, capability: Int,
                       nowMs: Long = System.currentTimeMillis()): PeerKeys? {
        if (!isAuthorized(pinnedAccount, deviceId, capability, nowMs)) return null
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT deviceEd,deviceX,syncOnion FROM authorized_devices " +
                "WHERE accountEd=? AND deviceId=? AND (capabilities & ?) = ? AND expiresAtMs>?",
            arrayOf(account, deviceId, capability, capability, nowMs)
        )).use { if (it.moveToFirst()) PeerKeys(deviceId, it.getBlob(0),
            it.getBlob(1), it.getString(2)) else null }
    }

    fun fetchSignedRoster(pinnedAccount: ByteArray): ByteArray? {
        require(pinnedAccount.size == 32)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT signedRoster FROM device_rosters WHERE accountEd = ?", arrayOf(account)
        )).use { if (it.moveToFirst()) it.getBlob(0) else null }
    }

    fun pendingEnrollmentGrants(pinnedAccount: ByteArray,
                                nowMs: Long = System.currentTimeMillis()): List<PendingGrantRecord> {
        require(pinnedAccount.size == 32)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT transcript_id,candidate_device_id,wire_frame,expires_at_ms " +
                "FROM enrollment_grant_outbox WHERE account_ed=? AND expires_at_ms>? " +
                "ORDER BY created_at_ms LIMIT 8", arrayOf<Any>(account, nowMs)
        )).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(PendingGrantRecord(cursor.getString(0),
                    pinnedAccount.copyOf(), cursor.getString(1), cursor.getBlob(2), cursor.getLong(3)))
            }
        }
    }

    fun pendingEnrollmentGrant(transcriptId: String, nowMs: Long = System.currentTimeMillis()): PendingGrantRecord? {
        require(transcriptId.matches(Regex("[0-9a-f]{64}")))
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT account_ed,candidate_device_id,wire_frame,expires_at_ms " +
                "FROM enrollment_grant_outbox WHERE transcript_id=? AND expires_at_ms>?",
            arrayOf<Any>(transcriptId, nowMs)
        )).use { cursor ->
            if (!cursor.moveToFirst()) null else PendingGrantRecord(transcriptId,
                Base64.decode(cursor.getString(0), Base64.DEFAULT), cursor.getString(1),
                cursor.getBlob(2), cursor.getLong(3))
        }
    }

    /** Delete only the grant bytes authenticated by a candidate's signed receipt. */
    fun completeEnrollmentGrant(pending: PendingGrantRecord): Boolean {
        val account = Base64.encodeToString(pending.account, Base64.NO_WRAP)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val exact = db.query(SimpleSQLiteQuery(
                "SELECT wire_frame FROM enrollment_grant_outbox WHERE transcript_id=? " +
                    "AND account_ed=? AND candidate_device_id=?",
                arrayOf(pending.transcriptId, account, pending.candidateDeviceId)
            )).use { it.moveToFirst() && it.getBlob(0).contentEquals(pending.wireFrame) }
            val authorized = db.query(SimpleSQLiteQuery(
                "SELECT 1 FROM authorized_devices WHERE accountEd=? AND deviceId=? " +
                    "AND (capabilities & 2)=2 AND expiresAtMs>?",
                arrayOf(account, pending.candidateDeviceId, System.currentTimeMillis())
            )).use { it.moveToFirst() }
            if (!exact || !authorized) return false
            db.execSQL("DELETE FROM enrollment_grant_outbox WHERE transcript_id=? AND account_ed=? " +
                "AND candidate_device_id=? AND wire_frame=?",
                arrayOf(pending.transcriptId, account, pending.candidateDeviceId, pending.wireFrame))
            db.setTransactionSuccessful()
            return true
        } finally { db.endTransaction() }
    }

    fun listAuthorizedDevices(pinnedAccount: ByteArray): List<DeviceView> {
        require(pinnedAccount.size == 32)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT deviceId,displayName,syncOnion,capabilities,expiresAtMs,isSelf " +
                "FROM authorized_devices WHERE accountEd = ? ORDER BY isSelf DESC,displayName",
            arrayOf(account)
        )).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(DeviceView(
                    cursor.getString(0), cursor.getString(1), cursor.getString(2),
                    cursor.getInt(3), cursor.getLong(4), cursor.getInt(5) != 0
                ))
            }
        }
    }

    fun acceptSignedRoster(
        signedRoster: ByteArray,
        pinnedAccount: ByteArray,
        localDeviceId: String?,
        nowMs: Long = System.currentTimeMillis(),
        pendingGrant: PendingGrant? = null
    ): AcceptedRoster {
        require(pinnedAccount.size == 32 && signedRoster.isNotEmpty() && signedRoster.size <= 32 * 1024)
        require(localDeviceId == null || localDeviceId.length == 43)
        require(nowMs in 1..9_007_199_254_740_991L)
        require(pendingGrant == null || (pendingGrant.transcriptId.matches(Regex("[0-9a-f]{64}")) &&
            pendingGrant.candidateDeviceId.length == 43 && pendingGrant.wireFrame.isNotEmpty() &&
            pendingGrant.wireFrame.size <= 393_221 && pendingGrant.expiresAtMs > nowMs))
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val previous = db.query(SimpleSQLiteQuery(
                "SELECT signedRoster FROM device_rosters WHERE accountEd = ?", arrayOf(account)
            )).use { if (it.moveToFirst()) it.getBlob(0) else null }
            val oldEndpoints = HashMap<String, Endpoint>()
            db.query(SimpleSQLiteQuery(
                "SELECT deviceId,syncOnion,deviceEd FROM authorized_devices WHERE accountEd = ?",
                arrayOf(account)
            )).use { cursor ->
                while (cursor.moveToNext()) oldEndpoints[cursor.getString(0)] =
                    Endpoint(cursor.getString(1), cursor.getBlob(2))
            }
            val request = JSONObject().apply {
                put("operation", "verify_roster")
                put("roster", Base64.encodeToString(signedRoster, Base64.NO_WRAP))
                put("pinned_account", account)
                put("previous_roster", previous?.let { Base64.encodeToString(it, Base64.NO_WRAP) } ?: JSONObject.NULL)
                put("now_ms", nowMs)
                put("authorize", JSONObject.NULL)
            }
            val verified = JSONObject(RustBridge.deviceAuthorization(
                request.toString().toByteArray(Charsets.UTF_8), null
            ).toString(Charsets.UTF_8))
            require(verified.getString("account_ed") == account)
            require(Base64.decode(verified.getString("roster"), Base64.DEFAULT).contentEquals(signedRoster))
            val epoch = verified.getLong("epoch")
            val issuedAt = verified.getLong("issued_at_ms")
            val primary = verified.getString("primary_device_id")
            val entries = verified.getJSONArray("entries")
            require(epoch > 0 && entries.length() in 1..8)

            db.execSQL("INSERT OR REPLACE INTO device_rosters (accountEd,epoch,issuedAtMs,primaryDeviceId,signedRoster,acceptedAtMs) VALUES (?,?,?,?,?,?)",
                arrayOf(account, epoch, issuedAt, primary, signedRoster, nowMs))
            // Each accepted roster completely replaces the active endpoint set.
            // A revoked certificate cannot remain authoritative after this commit.
            db.execSQL("DELETE FROM authorized_devices WHERE accountEd = ?", arrayOf(account))
            val ids = ArrayList<String>(entries.length())
            val newEndpoints = HashMap<String, Endpoint>()
            for (index in 0 until entries.length()) {
                val entry = entries.getJSONObject(index)
                val cert = entry.getJSONObject("certificate")
                val id = cert.getString("device_id")
                ids.add(id)
                newEndpoints[id] = Endpoint(cert.getString("onion") + ".onion",
                    Base64.decode(cert.getString("device_ed"), Base64.DEFAULT))
                db.execSQL("INSERT INTO authorized_devices (deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX,mlKemPublic,certificate,capabilities,issuedAtMs,expiresAtMs,rosterEpoch,isSelf) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    arrayOf(
                        id, account, entry.getString("name"), cert.getString("onion") + ".onion",
                        Base64.decode(cert.getString("device_ed"), Base64.DEFAULT),
                        Base64.decode(cert.getString("device_x"), Base64.DEFAULT),
                        Base64.decode(entry.getString("ml_kem_public"), Base64.DEFAULT),
                        Base64.decode(cert.getString("certificate"), Base64.DEFAULT),
                        cert.getInt("capabilities"), cert.getLong("issued_at_ms"),
                        cert.getLong("expires_at_ms"), epoch, if (id == localDeviceId) 1 else 0
                    ))
            }
            for (removed in oldEndpoints.keys - ids.toSet()) {
                for (table in arrayOf("device_transport_epochs", "device_transport_sessions",
                    "device_transport_jobs", "device_transport_receipts",
                    "device_transport_skipped_keys")) {
                    db.execSQL("DELETE FROM $table WHERE account_ed = ? AND peer_device_id = ?",
                        arrayOf(account, removed))
                }
                for (table in arrayOf("device_sync_cursors", "device_sync_versions",
                    "device_sync_pending", "device_sync_chunks", "device_sync_outbox",
                    "device_sync_acks", "device_transport_skips",
                    "device_sync_live_peers", "device_sync_live_seed",
                    "device_sync_live_work")) {
                    db.execSQL("DELETE FROM $table WHERE peer_device_id = ?", arrayOf(removed))
                }
                db.execSQL("DELETE FROM enrollment_grant_outbox WHERE candidate_device_id = ?",
                    arrayOf(removed))
            }
            // Public revocation notice goes to old and new endpoints, including
            // the removed peer. An A5 may clear only this notification.
            if (localDeviceId == primary && (previous == null || !previous.contentEquals(signedRoster))) {
                val hash = MessageDigest.getInstance("SHA-256").digest(signedRoster)
                for ((id, endpoint) in oldEndpoints + newEndpoints) {
                    if (id == localDeviceId) continue
                    db.execSQL("INSERT OR REPLACE INTO device_roster_notifications " +
                        "(account_ed,peer_device_id,onion,signing_key,roster_hash,next_try_at_ms,attempts) " +
                        "VALUES (?,?,?,?,?,0,0)",
                        arrayOf(account, id, endpoint.onion, endpoint.signingKey, hash))
                }
            }
            if (pendingGrant != null) {
                require(pendingGrant.candidateDeviceId in ids)
                db.execSQL("INSERT INTO enrollment_grant_outbox " +
                    "(transcript_id,account_ed,candidate_device_id,wire_frame,expires_at_ms,created_at_ms) " +
                    "VALUES (?,?,?,?,?,?)", arrayOf(pendingGrant.transcriptId, account,
                        pendingGrant.candidateDeviceId, pendingGrant.wireFrame,
                        pendingGrant.expiresAtMs, nowMs))
            }
            db.setTransactionSuccessful()
            return AcceptedRoster(epoch, primary, ids)
        } finally {
            db.endTransaction()
        }
    }

    /** Check immediately before a send, receive, retry, ACK, or sync apply. */
    fun isAuthorized(pinnedAccount: ByteArray, deviceId: String, capability: Int,
                     nowMs: Long = System.currentTimeMillis()): Boolean {
        if (pinnedAccount.size != 32 || deviceId.length != 43 ||
            capability == 0 || capability and 0x07 != capability) return false
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        val db = database.openHelper.readableDatabase
        db.query(SimpleSQLiteQuery(
            "SELECT capabilities,expiresAtMs FROM authorized_devices WHERE accountEd = ? AND deviceId = ?",
            arrayOf(account, deviceId)
        )).use {
            return it.moveToFirst() && it.getInt(0) and capability == capability &&
                nowMs in 1 until it.getLong(1)
        }
    }

    fun isLocalAuthorized(pinnedAccount: ByteArray, deviceId: String, capability: Int,
                          nowMs: Long = System.currentTimeMillis()): Boolean {
        if (!isAuthorized(pinnedAccount, deviceId, capability, nowMs)) return false
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT isSelf FROM authorized_devices WHERE accountEd = ? AND deviceId = ?",
            arrayOf(account, deviceId)
        )).use { it.moveToFirst() && it.getInt(0) == 1 }
    }
}
