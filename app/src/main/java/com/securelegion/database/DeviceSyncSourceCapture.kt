package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase

/** Durable local change IDs; payload loading and per-peer progress are separate. */
internal object DeviceSyncSourceCapture {
    data class Change(val sequence: Long, val topic: String, val objectId: String,
                      val kind: String, val changedAtMs: Long)

    /** Call inside the same transaction as a verified own-device import. */
    fun <T> suppressDuringImport(db: SupportSQLiteDatabase, apply: () -> T): T {
        require(db.inTransaction())
        db.execSQL("UPDATE device_sync_import_guard SET depth=depth+1 WHERE id=1")
        try {
            return apply()
        } finally {
            // Both the imported rows and this guard update roll back together on failure.
            db.execSQL("UPDATE device_sync_import_guard SET depth=depth-1 WHERE id=1 AND depth>0")
        }
    }

    /** Uses the sequence index; never reads a message body or attachment. */
    fun next(db: SupportSQLiteDatabase, afterSequence: Long, limit: Int = 25): List<Change> {
        require(afterSequence >= 0 && limit in 1..25)
        val rows = ArrayList<Change>(limit)
        db.query(SimpleSQLiteQuery("SELECT seq,topic,object_id,kind,changed_at_ms " +
            "FROM device_sync_source_changes WHERE seq>? ORDER BY seq LIMIT ?",
            arrayOf(afterSequence, limit))).use { cursor ->
            while (cursor.moveToNext()) rows.add(Change(cursor.getLong(0), cursor.getString(1),
                cursor.getString(2), cursor.getString(3), cursor.getLong(4)))
        }
        return rows
    }
}
