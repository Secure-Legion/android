package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery

/** Fresh contact captures precede a bounded initial seed; both are durable. */
internal class DeviceSyncContactWorkStore(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val linked: Boolean = false
) {
    data class Change(val sequence: Long, val objectId: String,
                      val kind: String, val attempts: Int)
    data class Seed(val contactId: Long, val objectId: String)

    fun initialize(accountEd: ByteArray, localId: String, peerId: String,
                   nowMs: Long = System.currentTimeMillis()) {
        requireAuthorized(accountEd, localId, peerId, nowMs)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            requireAuthorized(accountEd, localId, peerId, nowMs)
            val exists = db.query(SimpleSQLiteQuery(
                "SELECT 1 FROM device_sync_contact_peers WHERE peer_device_id=?",
                arrayOf(peerId))).use { it.moveToFirst() }
            if (!exists) {
                val snapshot = db.query(SimpleSQLiteQuery(
                    "SELECT COALESCE(MAX(seq),0) FROM device_sync_source_changes"
                )).use { check(it.moveToFirst()); it.getLong(0) }
                db.execSQL("INSERT INTO device_sync_contact_peers " +
                    "(peer_device_id,seed_snapshot_seq,seed_after_id,discovered_seq,created_at_ms) " +
                    "VALUES (?,?,0,?,?)", arrayOf(peerId, snapshot, snapshot, nowMs))
            }
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    /** A full work queue leaves its source checkpoint unchanged. */
    fun discover(accountEd: ByteArray, localId: String, peerId: String,
                 nowMs: Long = System.currentTimeMillis()): Int {
        requireAuthorized(accountEd, localId, peerId, nowMs)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            requireAuthorized(accountEd, localId, peerId, nowMs)
            val last = db.query(SimpleSQLiteQuery(
                "SELECT discovered_seq FROM device_sync_contact_peers WHERE peer_device_id=?",
                arrayOf(peerId))).use { check(it.moveToFirst()); it.getLong(0) }
            val queued = db.query(SimpleSQLiteQuery(
                "SELECT COUNT(*) FROM device_sync_contact_work WHERE peer_device_id=?",
                arrayOf(peerId))).use { check(it.moveToFirst()); it.getInt(0) }
            val limit = (256 - queued).coerceIn(0, 25)
            if (limit == 0) { db.setTransactionSuccessful(); return 0 }
            val changes = db.query(SimpleSQLiteQuery(
                "SELECT seq,object_id,kind FROM device_sync_source_changes " +
                    "WHERE seq>? AND topic='contacts' ORDER BY seq LIMIT ?",
                arrayOf(last, limit)
            )).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(Triple(cursor.getLong(0),
                        cursor.getString(1), cursor.getString(2)))
                }
            }
            for ((seq, objectId, kind) in changes) {
                require(kind == "upsert" || kind == "delete")
                db.execSQL("INSERT INTO device_sync_contact_work " +
                    "(peer_device_id,source_seq,object_id,kind) VALUES (?,?,?,?)",
                    arrayOf(peerId, seq, objectId, kind))
            }
            if (changes.isNotEmpty()) db.execSQL("UPDATE device_sync_contact_peers " +
                "SET discovered_seq=? WHERE peer_device_id=?",
                arrayOf(changes.last().first, peerId))
            db.setTransactionSuccessful()
            return changes.size
        } finally { db.endTransaction() }
    }

    /** Two fresh turns plus one old seed per network batch. */
    fun due(peerId: String, nowMs: Long = System.currentTimeMillis()): List<Change> {
        require(peerId.length == 43)
        val db = database.openHelper.readableDatabase
        val rows = ArrayList<Change>(2)
        fun append(order: String) {
            db.query(SimpleSQLiteQuery(
                "SELECT source_seq,object_id,kind,attempts FROM device_sync_contact_work " +
                    "WHERE peer_device_id=? AND next_try_at_ms<=? ORDER BY $order LIMIT 1",
                arrayOf(peerId, nowMs)
            )).use { if (it.moveToFirst()) {
                val row = Change(it.getLong(0), it.getString(1), it.getString(2), it.getInt(3))
                if (rows.none { prior -> prior.sequence == row.sequence }) rows.add(row)
            } }
        }
        append("source_seq DESC")
        append("source_seq ASC")
        return rows
    }

    fun nextSeed(peerId: String): Seed? {
        require(peerId.length == 43)
        val db = database.openHelper.readableDatabase
        val afterId = db.query(SimpleSQLiteQuery(
            "SELECT seed_after_id FROM device_sync_contact_peers WHERE peer_device_id=?",
            arrayOf(peerId))).use { if (it.moveToFirst()) it.getLong(0) else return null }
        if (afterId == Long.MAX_VALUE) return null
        return db.query(SimpleSQLiteQuery(if (linked)
            "SELECT rowid,account_ed FROM linked_chat_contacts " +
                "WHERE rowid>? ORDER BY rowid LIMIT 1"
            else "SELECT id,publicKeyBase64 FROM contacts WHERE id>? ORDER BY id LIMIT 1",
            arrayOf(afterId)
        )).use { if (it.moveToFirst()) Seed(it.getLong(0), it.getString(1)) else null }
    }

    fun nextDeletionSeed(peerId: String): String? {
        require(peerId.length == 43)
        val db = database.openHelper.readableDatabase
        val after = db.query(SimpleSQLiteQuery(
            "SELECT seed_after_deletion FROM device_sync_contact_peers WHERE peer_device_id=?",
            arrayOf(peerId))).use { if (it.moveToFirst()) it.getString(0) else return null }
        return db.query(SimpleSQLiteQuery(
            "SELECT d.object_id FROM device_sync_deletions d WHERE d.topic='contacts' " +
                "AND d.object_id>? AND NOT EXISTS (SELECT 1 FROM contacts c WHERE " +
                "c.publicKeyBase64=d.object_id) ORDER BY d.object_id LIMIT 1",
            arrayOf(after)
        )).use { if (it.moveToFirst()) it.getString(0) else null }
    }

    fun completeSeed(peerId: String, contactId: Long) {
        require(peerId.length == 43 && contactId > 0)
        database.openHelper.writableDatabase.execSQL(
            "UPDATE device_sync_contact_peers SET seed_after_id=MAX(seed_after_id,?) " +
                "WHERE peer_device_id=?", arrayOf(contactId, peerId))
    }

    fun completeDeletionSeed(peerId: String, objectId: String) {
        require(peerId.length == 43 && objectId.isNotEmpty() && objectId.length <= 256)
        database.openHelper.writableDatabase.execSQL(
            "UPDATE device_sync_contact_peers SET seed_after_deletion=? " +
                "WHERE peer_device_id=? AND seed_after_deletion<?",
            arrayOf(objectId, peerId, objectId))
    }

    fun completeChange(peerId: String, sequence: Long) {
        require(peerId.length == 43 && sequence > 0)
        database.openHelper.writableDatabase.execSQL(
            "DELETE FROM device_sync_contact_work WHERE peer_device_id=? AND source_seq=?",
            arrayOf(peerId, sequence))
    }

    fun defer(peerId: String, sequence: Long, attempts: Int,
              nowMs: Long = System.currentTimeMillis()) {
        require(peerId.length == 43 && sequence > 0 && attempts >= 0)
        val delay = (5_000L shl attempts.coerceIn(0, 10)).coerceAtMost(3_600_000L)
        database.openHelper.writableDatabase.execSQL(
            "UPDATE device_sync_contact_work SET attempts=attempts+1,next_try_at_ms=? " +
                "WHERE peer_device_id=? AND source_seq=?",
            arrayOf(nowMs + delay, peerId, sequence))
    }

    private fun requireAuthorized(accountEd: ByteArray, localId: String,
                                  peerId: String, nowMs: Long) {
        require(accountEd.size == 32 && localId.length == 43 && peerId.length == 43 &&
            localId != peerId && roster.isLocalAuthorized(accountEd, localId, 0x02, nowMs) &&
            roster.isAuthorized(accountEd, peerId, 0x02, nowMs))
    }
}
