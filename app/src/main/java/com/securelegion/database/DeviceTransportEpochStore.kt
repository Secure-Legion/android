package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.sync.DeviceTransportFrame
import java.util.Base64

/** Monotonic C0v2 session generations; caller has authorized both endpoints. */
internal object DeviceTransportEpochStore {
    data class Allocated(val generation: Long, val retiredThrough: Long)

    fun allocate(db: SupportSQLiteDatabase, account: ByteArray,
                 peerId: String, localId: String): Allocated {
        require(db.inTransaction())
        validate(account, peerId, localId)
        reap(db, account, peerId, localId)
        val prior = read(db, account, peerId, localId, "tx")
        val generation = prior?.first ?: 2L
        val retired = prior?.second ?: 0L
        require(generation in 2..DeviceTransportFrame.MAX_COUNTER)
        if (prior == null) db.execSQL("INSERT INTO device_transport_epochs " +
            "(account_ed,peer_device_id,local_device_id,direction," +
            "next_generation,retired_through) VALUES (?,?,?,'tx',?,?)",
            arrayOf(encoded(account), peerId, localId, generation + 1, retired))
        else db.execSQL("UPDATE device_transport_epochs SET next_generation=? " +
            "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
            "AND direction='tx'", arrayOf(generation + 1, encoded(account), peerId, localId))
        return Allocated(generation, retired)
    }

    fun markRetiring(db: SupportSQLiteDatabase, account: ByteArray,
                     peerId: String, localId: String, sessionId: ByteArray) {
        require(db.inTransaction() && sessionId.size == 32)
        validate(account, peerId, localId)
        db.execSQL("UPDATE device_transport_sessions SET state='retiring' " +
            "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
            "AND session_id=? AND direction='tx'",
            arrayOf(encoded(account), peerId, localId, sessionId))
    }

    /** Preserve assigned wires; only counterless drafts may move to a new session. */
    fun reap(db: SupportSQLiteDatabase, account: ByteArray,
             peerId: String, localId: String) {
        require(db.inTransaction())
        validate(account, peerId, localId)
        val key = encoded(account)
        val retiring = db.query(SimpleSQLiteQuery("SELECT session_id FROM " +
            "device_transport_sessions WHERE account_ed=? AND peer_device_id=? " +
            "AND local_device_id=? AND direction='tx' AND state='retiring'",
            arrayOf(key, peerId, localId))).use { c -> buildList {
            while (c.moveToNext()) add(c.getBlob(0))
        } }
        for (session in retiring) {
            val scope = arrayOf<Any>(key, peerId, localId, session)
            val malformed = db.query(SimpleSQLiteQuery("SELECT 1 FROM " +
                "device_transport_jobs WHERE account_ed=? AND peer_device_id=? " +
                "AND local_device_id=? AND session_id=? AND wire IS NULL AND " +
                "(counter IS NOT NULL OR wire_hash IS NOT NULL OR plaintext IS NULL) LIMIT 1",
                scope)).use { it.moveToFirst() }
            check(!malformed) { "Invalid unassigned transport job" }
            db.execSQL("UPDATE device_transport_jobs SET session_id=? " +
                "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                "AND session_id=? AND wire IS NULL",
                arrayOf<Any>(ByteArray(0), key, peerId, localId, session))
            val assigned = db.query(SimpleSQLiteQuery("SELECT 1 FROM " +
                "device_transport_jobs WHERE account_ed=? AND peer_device_id=? " +
                "AND local_device_id=? AND session_id=? AND wire IS NOT NULL LIMIT 1",
                scope)).use { it.moveToFirst() }
            if (!assigned) db.execSQL("DELETE FROM device_transport_sessions " +
                "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                "AND session_id=? AND direction='tx' AND state='retiring'", scope)
        }
        val epoch = read(db, account, peerId, localId, "tx") ?: return
        val remaining = db.query(SimpleSQLiteQuery("SELECT MIN(generation) FROM " +
            "device_transport_sessions WHERE account_ed=? AND peer_device_id=? " +
            "AND local_device_id=? AND direction='tx'",
            arrayOf(key, peerId, localId))).use { c ->
            check(c.moveToFirst()); if (c.isNull(0)) null else c.getLong(0)
        }
        val floor = if (remaining == null) epoch.first - 1 else remaining - 1
        check(remaining == null || remaining > epoch.second)
        if (floor > epoch.second) db.execSQL("UPDATE device_transport_epochs " +
            "SET retired_through=? WHERE account_ed=? AND peer_device_id=? " +
            "AND local_device_id=? AND direction='tx'",
            arrayOf(floor, key, peerId, localId))
    }

    fun admit(db: SupportSQLiteDatabase, account: ByteArray,
              peerId: String, localId: String, generation: Long,
              retireThrough: Long) {
        require(db.inTransaction())
        validate(account, peerId, localId)
        val prior = read(db, account, peerId, localId, "rx")
        val next = prior?.first ?: 2L
        val floor = prior?.second ?: 0L
        require(generation in next..DeviceTransportFrame.MAX_COUNTER &&
            retireThrough >= floor && retireThrough < generation)
        if (prior == null) db.execSQL("INSERT INTO device_transport_epochs " +
            "(account_ed,peer_device_id,local_device_id,direction," +
            "next_generation,retired_through) VALUES (?,?,?,'rx',?,?)",
            arrayOf(encoded(account), peerId, localId, generation + 1, retireThrough))
        else db.execSQL("UPDATE device_transport_epochs SET " +
            "next_generation=?,retired_through=? WHERE account_ed=? " +
            "AND peer_device_id=? AND local_device_id=? AND direction='rx'",
            arrayOf(generation + 1, retireThrough, encoded(account), peerId, localId))
        db.execSQL("DELETE FROM device_transport_skipped_keys WHERE account_ed=? " +
            "AND peer_device_id=? AND local_device_id=? AND session_id IN " +
            "(SELECT session_id FROM device_transport_sessions WHERE account_ed=? " +
            "AND peer_device_id=? AND local_device_id=? AND direction='rx' " +
            "AND generation<=?)",
            arrayOf(encoded(account), peerId, localId, encoded(account),
                peerId, localId, retireThrough))
        db.execSQL("DELETE FROM device_transport_sessions WHERE account_ed=? " +
            "AND peer_device_id=? AND local_device_id=? AND direction='rx' " +
            "AND generation<=?",
            arrayOf(encoded(account), peerId, localId, retireThrough))
    }

    private fun read(db: SupportSQLiteDatabase, account: ByteArray,
                     peerId: String, localId: String,
                     direction: String): Pair<Long, Long>? =
        db.query(SimpleSQLiteQuery("SELECT next_generation,retired_through " +
            "FROM device_transport_epochs WHERE account_ed=? AND peer_device_id=? " +
            "AND local_device_id=? AND direction=?",
            arrayOf(encoded(account), peerId, localId, direction)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getLong(1) else null }

    private fun validate(account: ByteArray, peerId: String, localId: String) {
        require(account.size == 32 && peerId.length == 43 && localId.length == 43 &&
            peerId != localId)
    }

    private fun encoded(account: ByteArray): String =
        Base64.getEncoder().encodeToString(account)
}
