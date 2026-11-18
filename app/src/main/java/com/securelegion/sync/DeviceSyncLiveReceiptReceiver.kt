package com.securelegion.sync

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.LinkedChatStore
import org.json.JSONObject

/** Complete live receipt chunks only; caller supplies authenticated B6/B7 identity. */
internal class DeviceSyncLiveReceiptReceiver(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val linked: LinkedChatStore? = null
) {
    private val chunks = DeviceSyncChunkStore(database, roster)
    data class Applied(val peerDeviceId: String, val objectId: String,
                       val eventId: String, val digestHex: String, val eventTimeMs: Long)

    fun receive(accountEd: ByteArray, localDeviceId: String,
                part: DeviceSyncChunkStore.Part, liveNegotiated: Boolean,
                nowMs: Long = System.currentTimeMillis(),
                archiveAuthenticated: Boolean = false): DeviceSyncChunkStore.Result {
        require((liveNegotiated || archiveAuthenticated) && part.topic == "receipts")
        return chunks.receive(accountEd, localDeviceId, part, nowMs) { db, canonical ->
            require(canonical.size in 2..1024)
            val receipt = DeviceSyncReceiptDelta.parse(
                JSONObject(canonical.toString(Charsets.UTF_8)))
            require(receipt.messageId == part.objectId)
            applyVersioned(db, part, receipt, canonical, nowMs,
                isLive = !archiveAuthenticated)
        }
    }

    /** Missing-message rows are retried after imports; each row is independent. */
    fun drainPending(accountEd: ByteArray, localDeviceId: String,
                     liveNegotiated: (String) -> Boolean,
                     nowMs: Long = System.currentTimeMillis()): List<Applied> {
        val db = database.openHelper.writableDatabase
        val committed = ArrayList<Applied>()
        var lastId = 0L
        while (true) {
            val rows = db.query(SimpleSQLiteQuery(
                "SELECT id,peer_device_id,object_id,sequence,event_time_ms,delta_json,event_id,digest " +
                    "FROM device_sync_pending WHERE id>? AND topic='receipts' AND is_live=1 " +
                    "ORDER BY id LIMIT 25", arrayOf(lastId)
            )).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(Pending(cursor.getLong(0), cursor.getString(1),
                        cursor.getString(2), cursor.getLong(3), cursor.getLong(4),
                        cursor.getBlob(5), cursor.getString(6), cursor.getBlob(7)))
                }
            }
            if (rows.isEmpty()) break
            for (row in rows) {
                lastId = row.id
                if (!liveNegotiated(row.peer) ||
                    !roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs) ||
                    !roster.isAuthorized(accountEd, row.peer, 0x02, nowMs)) continue
                try {
                    require(row.eventId.matches(Regex("[0-9a-f]{64}")) &&
                        row.digest.size == 32 && row.delta.size in 2..1024)
                    val identity = RustBridge.deviceHistoryIdentity(row.delta, "receipts",
                        row.objectId, row.eventTimeMs)
                    require(identity.size >= 66 && identity.copyOfRange(0, 32)
                        .contentEquals(row.digest) && identity.copyOfRange(32, 64)
                        .toHex() == row.eventId)
                    val receipt = DeviceSyncReceiptDelta.parse(
                        JSONObject(row.delta.toString(Charsets.UTF_8)))
                    require(receipt.messageId == row.objectId)
                    val part = DeviceSyncChunkStore.Part(row.peer, "receipts", row.objectId,
                        row.eventId, row.digest.toHex(), row.eventTimeMs, row.sequence,
                        0, 1, row.delta)
                    db.beginTransaction()
                    try {
                        require(liveNegotiated(row.peer) &&
                            roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs) &&
                            roster.isAuthorized(accountEd, row.peer, 0x02, nowMs))
                        val applied = applyVersioned(db, part, receipt, row.delta, nowMs)
                        if (applied) db.execSQL("DELETE FROM device_sync_pending WHERE id=?",
                            arrayOf(row.id))
                        db.setTransactionSuccessful()
                        if (applied) committed.add(Applied(row.peer, row.objectId,
                            row.eventId, row.digest.toHex(), row.eventTimeMs))
                    } finally { db.endTransaction() }
                } catch (_: Exception) {
                    // Keep this row for repair while later dependencies proceed.
                }
            }
        }
        return committed
    }

    private fun applyVersioned(db: SupportSQLiteDatabase, part: DeviceSyncChunkStore.Part,
                               receipt: DeviceSyncReceiptDelta.Receipt,
                               canonical: ByteArray, nowMs: Long,
                               isLive: Boolean = true): Boolean {
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
            if (previous.first >= part.eventTimeMs) {
                db.execSQL("DELETE FROM device_sync_pending WHERE peer_device_id=? " +
                    "AND topic='receipts' AND object_id=? AND event_time_ms<=?",
                    arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs))
                return true
            }
        }
        if (!(linked?.applyReceipt(db, receipt) ?:
                DeviceSyncReceiptDelta.applyInTransaction(db, receipt))) {
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
                "WHERE peer_device_id=? AND is_live=?",
                arrayOf(part.peerDeviceId, if (isLive) 1 else 0)
            )).use { cursor -> check(cursor.moveToFirst()); cursor.getLong(0) to cursor.getLong(1) }
            require(queued.first < 256 && queued.second + canonical.size <= 16L * 1024 * 1024)
            db.execSQL("INSERT INTO device_sync_pending " +
                "(peer_device_id,topic,object_id,sequence,event_time_ms,delta_json,reason," +
                "created_at_ms,event_id,digest,is_live) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                arrayOf(part.peerDeviceId, "receipts", part.objectId, part.sequence,
                    part.eventTimeMs, canonical, "missing_message", nowMs, part.eventId,
                    digest, if (isLive) 1 else 0))
            return false
        }
        val local = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,sequence,digest FROM device_sync_local_events " +
                "WHERE topic='receipts' AND object_id=?", arrayOf(part.objectId)
        )).use { if (it.moveToFirst()) Triple(it.getLong(0), it.getLong(1),
            it.getBlob(2)) else null }
        if (local == null || part.eventTimeMs > local.first ||
            part.eventTimeMs == local.first && part.digestHex > local.third.toHex()) {
            db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
                "VALUES ('receipts',?,?,?,?,?)",
                arrayOf(part.objectId, part.eventTimeMs, digest,
                    maxOf(part.sequence, (local?.second ?: 0L) + 1), canonical))
            db.execSQL("INSERT INTO device_sync_source_changes " +
                "(topic,object_id,kind,changed_at_ms) " +
                "VALUES ('receipts',?,'import',?)", arrayOf(part.objectId, nowMs))
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

    private data class Pending(val id: Long, val peer: String, val objectId: String,
                               val sequence: Long, val eventTimeMs: Long, val delta: ByteArray,
                               val eventId: String, val digest: ByteArray)

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
