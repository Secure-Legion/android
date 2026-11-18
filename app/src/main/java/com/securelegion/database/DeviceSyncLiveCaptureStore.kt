package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase

/** Per-peer one-time seed and bounded source ID discovery. No message bodies are read here. */
internal class DeviceSyncLiveCaptureStore(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val linked: Boolean = false
) {
    data class SourceWork(val sequence: Long, val topic: String, val objectId: String,
                          val kind: String, val attempts: Int)

    fun initialize(accountEd: ByteArray, localDeviceId: String, peerDeviceId: String,
                   liveNegotiated: Boolean, nowMs: Long = System.currentTimeMillis()): Boolean {
        require(liveNegotiated && authorized(accountEd, localDeviceId, peerDeviceId, nowMs))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            require(authorized(accountEd, localDeviceId, peerDeviceId, nowMs))
            val exists = db.query(SimpleSQLiteQuery(
                "SELECT 1 FROM device_sync_live_peers WHERE peer_device_id=?",
                arrayOf(peerDeviceId))).use { it.moveToFirst() }
            if (exists) { db.setTransactionSuccessful(); return false }
            val snapshot = db.query(SimpleSQLiteQuery(
                "SELECT COALESCE(MAX(seq),0) FROM device_sync_source_changes"))
                .use { check(it.moveToFirst()); it.getLong(0) }
            db.execSQL("INSERT INTO device_sync_live_peers " +
                "(peer_device_id,seed_snapshot_seq,discovered_seq,created_at_ms) VALUES (?,?,?,?)",
                arrayOf(peerDeviceId, snapshot, snapshot, nowMs))
            // This one indexed selection never repeats at reconnect or after ACK.
            db.query(SimpleSQLiteQuery(if (linked)
                "SELECT message_id FROM linked_chat_messages " +
                    "ORDER BY timestamp_ms DESC,message_id DESC LIMIT 50"
                else "SELECT messageId FROM messages " +
                    "ORDER BY timestamp DESC,id DESC LIMIT 50")).use { cursor ->
                var ordinal = 0
                while (cursor.moveToNext()) {
                    db.execSQL("INSERT INTO device_sync_live_seed " +
                        "(peer_device_id,message_id,ordinal) VALUES (?,?,?)",
                        arrayOf(peerDeviceId, cursor.getString(0), ordinal++))
                }
            }
            db.setTransactionSuccessful()
            return true
        } finally { db.endTransaction() }
    }

    fun seedIds(peerDeviceId: String, limit: Int = 25): List<String> {
        require(peerDeviceId.length == 43 && limit in 1..25)
        val ids = ArrayList<String>(limit)
        database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT message_id FROM device_sync_live_seed WHERE peer_device_id=? " +
                "ORDER BY ordinal LIMIT ?", arrayOf(peerDeviceId, limit))).use { cursor ->
            while (cursor.moveToNext()) ids.add(cursor.getString(0))
        }
        return ids
    }

    /** Call only after the exact snapshot is in the durable outbox or ACK table. */
    fun completeSeed(peerDeviceId: String, messageId: String) {
        require(peerDeviceId.length == 43 && messageId.isNotEmpty())
        database.openHelper.writableDatabase.execSQL(
            "DELETE FROM device_sync_live_seed WHERE peer_device_id=? AND message_id=?",
            arrayOf(peerDeviceId, messageId))
    }

    /** A missing attachment does not block every older seed behind it. */
    fun rotateSeed(peerDeviceId: String, messageId: String) {
        require(peerDeviceId.length == 43 && messageId.isNotEmpty())
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val last = db.query(SimpleSQLiteQuery(
                "SELECT COALESCE(MAX(ordinal),0) FROM device_sync_live_seed " +
                    "WHERE peer_device_id=?", arrayOf(peerDeviceId)
            )).use { check(it.moveToFirst()); it.getLong(0) }
            require(last < Long.MAX_VALUE)
            db.execSQL("UPDATE device_sync_live_seed SET ordinal=? " +
                "WHERE peer_device_id=? AND message_id=?",
                arrayOf(last + 1, peerDeviceId, messageId))
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    /** A write failure retains the source ID for retry and does not move discovery. */
    fun completeWork(peerDeviceId: String, sourceSequence: Long) {
        require(peerDeviceId.length == 43 && sourceSequence > 0)
        database.openHelper.writableDatabase.execSQL(
            "DELETE FROM device_sync_live_work WHERE peer_device_id=? AND source_seq=?",
            arrayOf(peerDeviceId, sourceSequence))
    }

    /** A full work queue leaves undiscovered source changes in the global log. */
    fun discover(accountEd: ByteArray, localDeviceId: String, peerDeviceId: String,
                 liveNegotiated: Boolean, nowMs: Long = System.currentTimeMillis()): Int {
        require(liveNegotiated && authorized(accountEd, localDeviceId, peerDeviceId, nowMs))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            require(authorized(accountEd, localDeviceId, peerDeviceId, nowMs))
            val last = db.query(SimpleSQLiteQuery(
                "SELECT discovered_seq FROM device_sync_live_peers WHERE peer_device_id=?",
                arrayOf(peerDeviceId))).use { check(it.moveToFirst()); it.getLong(0) }
            val queued = db.query(SimpleSQLiteQuery(
                "SELECT COUNT(*) FROM device_sync_live_work WHERE peer_device_id=?",
                arrayOf(peerDeviceId))).use { check(it.moveToFirst()); it.getInt(0) }
            val limit = (MAX_WORK_IDS - queued).coerceIn(0, 25)
            if (limit == 0) { db.setTransactionSuccessful(); return 0 }
            val changes = DeviceSyncSourceCapture.next(db, last, limit)
            for (change in changes) {
                if (change.topic !in setOf("messages", "receipts")) continue
                db.execSQL("INSERT INTO device_sync_live_work " +
                    "(peer_device_id,source_seq,topic,object_id,kind) VALUES (?,?,?,?,?)",
                    arrayOf(peerDeviceId, change.sequence, change.topic,
                        change.objectId, change.kind))
            }
            if (changes.isNotEmpty()) db.execSQL("UPDATE device_sync_live_peers " +
                "SET discovered_seq=? WHERE peer_device_id=?",
                arrayOf(changes.last().sequence, peerDeviceId))
            db.setTransactionSuccessful()
            return changes.size
        } finally { db.endTransaction() }
    }

    fun due(peerDeviceId: String, nowMs: Long = System.currentTimeMillis(),
            limit: Int = 25): List<SourceWork> {
        require(peerDeviceId.length == 43 && limit in 1..25)
        val rows = ArrayList<SourceWork>(limit)
        val db = database.openHelper.readableDatabase
        fun append(sql: String, count: Int) {
            db.query(SimpleSQLiteQuery(
                "SELECT source_seq,topic,object_id,kind,attempts FROM device_sync_live_work " +
                    "WHERE peer_device_id=? AND next_try_at_ms<=? $sql LIMIT ?",
                arrayOf(peerDeviceId, nowMs, count))).use { cursor ->
                while (cursor.moveToNext()) {
                    val row = SourceWork(cursor.getLong(0), cursor.getString(1),
                        cursor.getString(2), cursor.getString(3), cursor.getInt(4))
                    if (rows.none { it.sequence == row.sequence }) rows.add(row)
                }
            }
        }
        // Reserve one turn for the oldest due revision so a stream of new
        // messages cannot starve older work. Body changes take the remaining
        // slots before status-only receipt updates. Contacts use their own queue.
        append("ORDER BY source_seq", 1)
        if (limit > 1) append("ORDER BY CASE WHEN topic='messages' AND kind='body' THEN 0 " +
            "WHEN topic='messages' THEN 1 ELSE 2 END, source_seq DESC", limit)
        if (rows.size > limit) rows.subList(limit, rows.size).clear()
        return rows
    }

    fun defer(peerDeviceId: String, sequence: Long,
              nowMs: Long = System.currentTimeMillis()) {
        require(peerDeviceId.length == 43 && sequence > 0)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val attempts = db.query(SimpleSQLiteQuery(
                "SELECT attempts FROM device_sync_live_work WHERE peer_device_id=? AND source_seq=?",
                arrayOf(peerDeviceId, sequence))).use { if (it.moveToFirst()) it.getInt(0) else null }
            if (attempts != null) {
                val delay = (5_000L shl attempts.coerceIn(0, 10)).coerceAtMost(3_600_000L)
                db.execSQL("UPDATE device_sync_live_work SET attempts=?,next_try_at_ms=? " +
                    "WHERE peer_device_id=? AND source_seq=?",
                    arrayOf(attempts + 1, nowMs + delay, peerDeviceId, sequence))
            }
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    private fun authorized(accountEd: ByteArray, local: String, peer: String,
                           nowMs: Long): Boolean =
        accountEd.size == 32 && local.length == 43 && peer.length == 43 && local != peer &&
            roster.isLocalAuthorized(accountEd, local, 0x02, nowMs) &&
            roster.isAuthorized(accountEd, peer, 0x02, nowMs)

    companion object { const val MAX_WORK_IDS = 256 }
}
