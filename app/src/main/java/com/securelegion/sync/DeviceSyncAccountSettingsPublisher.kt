package com.securelegion.sync

import android.content.Context
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/** Captures account profile revisions and queues exact, restart-stable Tor work. */
internal class DeviceSyncAccountSettingsPublisher(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore
) {
    private val outbox = DeviceSyncOutboxStore(database, roster)

    fun capturePrimary(context: Context, keyManager: KeyManager,
                       nowMs: Long = System.currentTimeMillis()) {
        require(keyManager.isInitialized() && nowMs > 0)
        keyManager.getUsername()?.let { name ->
            capture(JSONObject().put("settings_id", "account:name")
                .put("version", 1).put("value", name),
                keyManager.getUsernameChangedAtMs(), nowMs)
        }
        val prefs = context.getSharedPreferences("secure_legion_settings", Context.MODE_PRIVATE)
        val photo = prefs.getString("profile_photo_base64", null)
        capture(JSONObject().put("settings_id", "account:photo").put("version", 1)
            .put("value", photo ?: JSONObject.NULL),
            prefs.getLong("profile_photo_changed_at_ms", 0L), nowMs)
    }

    fun enqueueForPeer(accountEd: ByteArray, localDeviceId: String, peerDeviceId: String,
                       nowMs: Long = System.currentTimeMillis()) {
        require(accountEd.size == 32 && localDeviceId.length == 43 && peerDeviceId.length == 43 &&
            roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs) &&
            roster.isAuthorized(accountEd, peerDeviceId, 0x02, nowMs))
        val db = database.openHelper.readableDatabase
        val rows = db.query(SimpleSQLiteQuery(
            "SELECT l.object_id,l.event_time_ms,l.sequence,l.delta_json,l.digest " +
                "FROM device_sync_local_events l JOIN device_sync_settings s " +
                "ON s.object_id=l.object_id WHERE l.topic='settings' ORDER BY l.object_id"
        )).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(LocalRevision(cursor.getString(0),
                    cursor.getLong(1), cursor.getLong(2), cursor.getBlob(3), cursor.getBlob(4)))
            }
        }
        for (row in rows) {
            if (!roster.isLocalAuthorized(accountEd, localDeviceId, 0x02) ||
                !roster.isAuthorized(accountEd, peerDeviceId, 0x02)) break
            val identity = RustBridge.deviceHistoryIdentity(row.delta, "settings",
                row.id, row.eventTimeMs)
            try {
                require(identity.size >= 66 && identity.copyOfRange(0, 32)
                    .contentEquals(row.digest))
                val eventId = identity.copyOfRange(32, 64).toHex()
                val existing = db.query(SimpleSQLiteQuery(
                    "SELECT event_id FROM device_sync_outbox WHERE peer_device_id=? " +
                        "AND topic='settings' AND object_id=?",
                    arrayOf(peerDeviceId, row.id)
                )).use { if (it.moveToFirst()) it.getString(0) else null }
                if (existing == eventId) continue
                val settled = db.query(SimpleSQLiteQuery(
                    "SELECT event_id FROM device_sync_acks WHERE peer_device_id=? " +
                        "AND topic='settings' AND object_id=?",
                    arrayOf(peerDeviceId, row.id)
                )).use { if (it.moveToFirst()) it.getString(0) else null }
                if (settled == eventId) continue
                val observed = db.query(SimpleSQLiteQuery(
                    "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                        "peer_device_id=? AND topic='settings' AND object_id=?",
                    arrayOf(peerDeviceId, row.id)
                )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
                if (observed != null && observed.first == row.eventTimeMs &&
                    observed.second.contentEquals(row.digest)) continue
                outbox.enqueue(accountEd, localDeviceId, peerDeviceId, "settings", row.id,
                    row.eventTimeMs, row.sequence, row.delta,
                    DeviceSyncOutboxStore.Transport.TOR, nowMs = nowMs)
            } finally { identity.fill(0) }
        }
    }

    private fun capture(delta: JSONObject, localChangedAtMs: Long, nowMs: Long) {
        val setting = DeviceSyncAccountSettingDelta.parse(delta)
        val raw = delta.toString().toByteArray(Charsets.UTF_8)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val old = db.query(SimpleSQLiteQuery(
                "SELECT event_time_ms,sequence,delta_json FROM device_sync_local_events " +
                    "WHERE topic='settings' AND object_id=?", arrayOf(setting.id)
            )).use { if (it.moveToFirst()) Triple(it.getLong(0), it.getLong(1),
                it.getBlob(2)) else null }
            val eventTime = maxOf(nowMs, (old?.first ?: 0L) + 1)
            val identity = RustBridge.deviceHistoryIdentity(raw, "settings", setting.id,
                eventTime)
            try {
                require(identity.size >= 66)
                val canonical = identity.copyOfRange(64, identity.size)
                if (old != null && old.third.contentEquals(canonical)) {
                    db.setTransactionSuccessful()
                    return
                }
                val storedAt = db.query(SimpleSQLiteQuery(
                    "SELECT updated_at_ms FROM device_sync_settings WHERE object_id=?",
                    arrayOf(setting.id)
                )).use { if (it.moveToFirst()) it.getLong(0) else old?.first }
                if (storedAt != null && localChangedAtMs < storedAt) {
                    db.setTransactionSuccessful()
                    return
                }
                val sequence = (old?.second ?: 0L) + 1
                db.execSQL("INSERT OR REPLACE INTO device_sync_settings " +
                    "(object_id,delta_json,updated_at_ms) VALUES (?,?,?)",
                    arrayOf(setting.id, canonical, eventTime))
                db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                    "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
                    "VALUES ('settings',?,?,?,?,?)",
                    arrayOf(setting.id, eventTime, identity.copyOfRange(0, 32),
                        sequence, canonical))
                db.setTransactionSuccessful()
            } finally { identity.fill(0) }
        } finally { db.endTransaction() }
    }

    private data class LocalRevision(val id: String, val eventTimeMs: Long,
                                     val sequence: Long, val delta: ByteArray,
                                     val digest: ByteArray)

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }

    companion object {
        private val localChange = AtomicBoolean(false)
        fun wake() { localChange.set(true) }
        fun consumeWake(): Boolean = localChange.getAndSet(false)
    }
}
