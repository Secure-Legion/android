package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.RustBridge
import org.json.JSONObject

/**
 * The durable authorization boundary for independent device endpoints.
 * Call off the main thread and only while the SQLCipher profile is unlocked.
 * No network worker may use a certificate without checking this store again.
 */
class DeviceRosterStore(private val database: SecureLegionDatabase) {
    data class AcceptedRoster(val epoch: Long, val primaryDeviceId: String, val deviceIds: List<String>)

    data class DeviceView(
        val deviceId: String,
        val displayName: String,
        val onion: String,
        val capabilities: Int,
        val expiresAtMs: Long,
        val isSelf: Boolean
    )

    fun fetchSignedRoster(pinnedAccount: ByteArray): ByteArray? {
        require(pinnedAccount.size == 32)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT signedRoster FROM device_rosters WHERE accountEd = ?", arrayOf(account)
        )).use { if (it.moveToFirst()) it.getBlob(0) else null }
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
        nowMs: Long = System.currentTimeMillis()
    ): AcceptedRoster {
        require(pinnedAccount.size == 32 && signedRoster.isNotEmpty() && signedRoster.size <= 32 * 1024)
        require(localDeviceId == null || localDeviceId.length == 43)
        require(nowMs in 1..9_007_199_254_740_991L)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val previous = db.query(SimpleSQLiteQuery(
                "SELECT signedRoster FROM device_rosters WHERE accountEd = ?", arrayOf(account)
            )).use { if (it.moveToFirst()) it.getBlob(0) else null }
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
            for (index in 0 until entries.length()) {
                val entry = entries.getJSONObject(index)
                val cert = entry.getJSONObject("certificate")
                val id = cert.getString("device_id")
                ids.add(id)
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
