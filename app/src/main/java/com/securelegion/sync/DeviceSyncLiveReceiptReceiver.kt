package com.securelegion.sync

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject

/** Complete live receipt chunks only; caller supplies authenticated B6/B7 identity. */
internal class DeviceSyncLiveReceiptReceiver(
    private val database: SecureLegionDatabase,
    roster: DeviceRosterStore
) {
    private val chunks = DeviceSyncChunkStore(database, roster)

    fun receive(accountEd: ByteArray, localDeviceId: String,
                part: DeviceSyncChunkStore.Part, liveNegotiated: Boolean,
                nowMs: Long = System.currentTimeMillis()): DeviceSyncChunkStore.Result {
        require(liveNegotiated && part.topic == "receipts")
        return chunks.receive(accountEd, localDeviceId, part, nowMs) { db, canonical ->
            require(canonical.size in 2..1024)
            val receipt = DeviceSyncReceiptDelta.parse(
                JSONObject(canonical.toString(Charsets.UTF_8)))
            require(receipt.messageId == part.objectId)
            applyVersioned(db, part, receipt, canonical, nowMs)
        }
    }

    private fun applyVersioned(db: SupportSQLiteDatabase, part: DeviceSyncChunkStore.Part,
                               receipt: DeviceSyncReceiptDelta.Receipt,
                               canonical: ByteArray, nowMs: Long): Boolean {
        val digest = ByteArray(32) { i ->
            part.digestHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        val previous = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,digest FROM device_sync_versions " +
                "WHERE peer_device_id=? AND topic='receipts' AND object_id=?",
            arrayOf(part.peerDeviceId, part.objectId)
        )).use { cursor ->
            if (!cursor.moveToFirst()) null else cursor.getLong(0) to cursor.getBlob(1)
        }
        if (previous != null) {
            require(previous.first != part.eventTimeMs || previous.second.contentEquals(digest)) {
                "Conflicting receipt revision"
            }
            if (previous.first >= part.eventTimeMs) return true
        }
        if (!DeviceSyncReceiptDelta.applyInTransaction(db, receipt)) {
            val pending = db.query(SimpleSQLiteQuery(
                "SELECT event_id,digest,delta_json FROM device_sync_pending " +
                    "WHERE peer_device_id=? AND topic='receipts' AND object_id=? AND event_time_ms=?",
                arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs)
            )).use { cursor ->
                if (!cursor.moveToFirst()) null else Triple(cursor.getString(0),
                    cursor.getBlob(1), cursor.getBlob(2))
            }
            if (pending != null) {
                require(pending.first == part.eventId && pending.second.contentEquals(digest) &&
                    pending.third.contentEquals(canonical)) { "Conflicting deferred receipt" }
                return false
            }
            val queued = db.query(SimpleSQLiteQuery(
                "SELECT COUNT(*),COALESCE(SUM(length(delta_json)),0) FROM device_sync_pending " +
                    "WHERE peer_device_id=? AND is_live=1", arrayOf(part.peerDeviceId)
            )).use { cursor -> check(cursor.moveToFirst()); cursor.getLong(0) to cursor.getLong(1) }
            require(queued.first < 256 && queued.second + canonical.size <= 16L * 1024 * 1024)
            db.execSQL("INSERT INTO device_sync_pending " +
                "(peer_device_id,topic,object_id,sequence,event_time_ms,delta_json,reason," +
                "created_at_ms,event_id,digest,is_live) VALUES (?,?,?,?,?,?,?,?,?,?,1)",
                arrayOf(part.peerDeviceId, "receipts", part.objectId, part.sequence,
                    part.eventTimeMs, canonical, "missing_message", nowMs, part.eventId, digest))
            return false
        }
        db.execSQL("INSERT OR REPLACE INTO device_sync_versions " +
            "(peer_device_id,topic,object_id,event_time_ms,digest) VALUES (?,'receipts',?,?,?)",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs, digest))
        db.execSQL("INSERT INTO device_sync_cursors " +
            "(peer_device_id,topic,pushed_seq,received_seq,updated_at_ms) " +
            "VALUES (?,'receipts',0,?,?) ON CONFLICT(peer_device_id,topic) DO UPDATE SET " +
            "received_seq=MAX(received_seq,excluded.received_seq),updated_at_ms=excluded.updated_at_ms",
            arrayOf(part.peerDeviceId, part.sequence, nowMs))
        db.execSQL("DELETE FROM device_sync_pending WHERE peer_device_id=? AND topic='receipts' " +
            "AND object_id=? AND event_time_ms<=?",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs))
        return true
    }
}
