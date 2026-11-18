package com.securelegion.sync

import android.content.Context
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.KeyManager
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject

/** Transactional account settings import, with restart-safe preference materialization. */
internal class DeviceSyncAccountSettingsReceiver(
    private val database: SecureLegionDatabase,
    roster: DeviceRosterStore
) {
    private val chunks = DeviceSyncChunkStore(database, roster)

    fun receive(accountEd: ByteArray, localDeviceId: String,
                part: DeviceSyncChunkStore.Part,
                nowMs: Long = System.currentTimeMillis()): DeviceSyncChunkStore.Result {
        require(part.topic == "settings")
        return chunks.receive(accountEd, localDeviceId, part, nowMs) { db, canonical ->
            require(canonical.size in 2..400_000)
            val setting = DeviceSyncAccountSettingDelta.parse(
                JSONObject(canonical.toString(Charsets.UTF_8)))
            require(setting.id == part.objectId)
            applyVersioned(db, part, canonical, nowMs)
            true
        }
    }

    /** Call after import and on every authorized profile start. */
    fun materializePrimary(context: Context, keyManager: KeyManager) {
        require(keyManager.isInitialized())
        val db = database.openHelper.readableDatabase
        val rows = db.query(SimpleSQLiteQuery(
            "SELECT object_id,delta_json FROM device_sync_settings " +
                "WHERE object_id IN ('account:name','account:photo')"
        )).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(cursor.getString(0) to cursor.getBlob(1))
            }
        }
        for ((id, raw) in rows) {
            val setting = DeviceSyncAccountSettingDelta.parse(
                JSONObject(raw.toString(Charsets.UTF_8)))
            require(setting.id == id)
            if (id == "account:name") keyManager.storeUsernameFromDeviceSync(setting.value!!)
            else {
                val editor = context.getSharedPreferences("secure_legion_settings",
                    Context.MODE_PRIVATE).edit()
                if (setting.value == null) editor.remove("profile_photo_base64")
                else editor.putString("profile_photo_base64", setting.value)
                check(editor.commit())
            }
        }
    }

    private fun applyVersioned(db: SupportSQLiteDatabase,
                               part: DeviceSyncChunkStore.Part,
                               canonical: ByteArray, nowMs: Long) {
        val digest = ByteArray(32) { i ->
            part.digestHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        val previous = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                "peer_device_id=? AND topic='settings' AND object_id=?",
            arrayOf(part.peerDeviceId, part.objectId)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
        if (previous == null || part.eventTimeMs > previous.first ||
            part.eventTimeMs == previous.first && digest.toHex() > previous.second.toHex()) {
            val local = db.query(SimpleSQLiteQuery(
                "SELECT event_time_ms,digest FROM device_sync_local_events " +
                    "WHERE topic='settings' AND object_id=?", arrayOf(part.objectId)
            )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
            val incomingWins = local == null || part.eventTimeMs > local.first ||
                part.eventTimeMs == local.first && digest.toHex() > local.second.toHex()
            if (incomingWins) {
                db.execSQL("INSERT OR REPLACE INTO device_sync_settings " +
                    "(object_id,delta_json,updated_at_ms) VALUES (?,?,?)",
                    arrayOf(part.objectId, canonical, nowMs))
                db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                    "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
                    "VALUES ('settings',?,?,?,?,?)",
                    arrayOf(part.objectId, part.eventTimeMs, digest, part.sequence, canonical))
            }
            db.execSQL("INSERT OR REPLACE INTO device_sync_versions " +
                "(peer_device_id,topic,object_id,event_time_ms,digest) " +
                "VALUES (?,'settings',?,?,?)",
                arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs, digest))
        }
        db.execSQL("INSERT INTO device_sync_cursors " +
            "(peer_device_id,topic,pushed_seq,received_seq,updated_at_ms) " +
            "VALUES (?,'settings',0,?,?) ON CONFLICT(peer_device_id,topic) DO UPDATE SET " +
            "received_seq=MAX(received_seq,excluded.received_seq)," +
            "updated_at_ms=excluded.updated_at_ms",
            arrayOf(part.peerDeviceId, part.sequence, nowMs))
    }

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
