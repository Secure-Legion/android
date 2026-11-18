package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.RustBridge

/** Bounded, encrypted chunk assembly with application commit in one transaction. */
class DeviceSyncChunkStore(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore
) {
    data class Part(val peerDeviceId: String, val topic: String, val objectId: String,
                    val eventId: String, val digestHex: String, val eventTimeMs: Long,
                    val sequence: Long, val index: Int, val total: Int, val bytes: ByteArray)

    enum class Result { PENDING, DEFERRED, COMMITTED }

    private val topics = setOf("messages", "receipts", "contacts", "settings", "groups", "group_links")
    private val hex64 = Regex("[0-9a-f]{64}")

    /**
     * [apply] must mutate only this SQLCipher database and return true only after
     * the event and applied cursor have been durably written in this transaction.
     * A deferred event keeps every part and receives no settlement.
     */
    fun receive(accountEd: ByteArray, localDeviceId: String, part: Part,
                nowMs: Long = System.currentTimeMillis(),
                apply: (SupportSQLiteDatabase, ByteArray) -> Boolean): Result {
        require(part.topic in topics && part.objectId.isNotEmpty() && part.objectId.length <= 512)
        require(part.peerDeviceId.length == 43 && localDeviceId.length == 43)
        require(hex64.matches(part.eventId) && hex64.matches(part.digestHex))
        require(part.eventTimeMs in 1..9_007_199_254_740_991L &&
            part.eventTimeMs <= nowMs + 300_000L && part.sequence > 0)
        val isGroup = part.topic == "groups"
        val maxParts = if (isGroup) 256 else 64
        val maxSize = if (isGroup) 32 * 1024 * 1024 else 8 * 1024 * 1024
        val lifetime = if (isGroup) 3_600_000L else 300_000L
        require(part.total in 1..maxParts && part.index in 0 until part.total)
        require(part.bytes.isNotEmpty() && part.bytes.size <= 128 * 1024)
        require(accountEd.size == 32 && localDeviceId != part.peerDeviceId)
        val capability = if (isGroup || part.topic == "group_links") 0x06 else 0x02
        require(roster.isLocalAuthorized(accountEd, localDeviceId, capability, nowMs) &&
            roster.isAuthorized(accountEd, part.peerDeviceId, capability, nowMs))
        val chunkId = "hist:${part.eventId}"
        val digest = hexToBytes(part.digestHex)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            // Roster changes are serialized by SQLCipher's write transaction.
            require(roster.isLocalAuthorized(accountEd, localDeviceId, capability, nowMs) &&
                roster.isAuthorized(accountEd, part.peerDeviceId, capability, nowMs))
            val existing = db.query(SimpleSQLiteQuery(
                "SELECT part_index,part_total,sequence,event_time_ms,event_digest,chunk_bytes," +
                    "created_at_ms,object_id,event_id FROM device_sync_chunks " +
                    "WHERE peer_device_id=? AND topic=? AND chunk_id=? ORDER BY part_index",
                arrayOf(part.peerDeviceId, part.topic, chunkId)
            )).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(StoredPart(cursor.getInt(0), cursor.getInt(1),
                        cursor.getLong(2), cursor.getLong(3), cursor.getBlob(4), cursor.getBlob(5),
                        cursor.getLong(6), cursor.getString(7), cursor.getString(8)))
                }
            }
            if (existing.isNotEmpty()) {
                val first = existing.first()
                if (first.createdAtMs > nowMs || nowMs - first.createdAtMs >= lifetime) {
                    db.execSQL("DELETE FROM device_sync_chunks WHERE peer_device_id=? AND topic=? AND chunk_id=?",
                        arrayOf(part.peerDeviceId, part.topic, chunkId))
                    db.setTransactionSuccessful()
                    return Result.DEFERRED
                }
                require(existing.all {
                    it.total == part.total && it.sequence == part.sequence &&
                        it.eventTimeMs == part.eventTimeMs && it.digest.contentEquals(digest) &&
                        it.objectId == part.objectId && it.eventId == part.eventId
                }) { "Conflicting chunk assembly" }
                val sameIndex = existing.firstOrNull { it.index == part.index }
                if (sameIndex != null && !sameIndex.bytes.contentEquals(part.bytes)) {
                    throw IllegalArgumentException("Conflicting duplicate chunk")
                }
            }
            val aggregate = existing.sumOf { it.bytes.size.toLong() } +
                if (existing.any { it.index == part.index }) 0 else part.bytes.size
            require(aggregate <= maxSize)
            if (existing.none { it.index == part.index }) {
                db.query(SimpleSQLiteQuery(
                    "SELECT COUNT(DISTINCT chunk_id),COALESCE(SUM(length(chunk_bytes)),0) " +
                        "FROM device_sync_chunks WHERE peer_device_id=?",
                    arrayOf(part.peerDeviceId)
                )).use { cursor ->
                    require(cursor.moveToFirst())
                    require(cursor.getLong(0) < 256 &&
                        cursor.getLong(1) + part.bytes.size <= 64L * 1024 * 1024)
                }
                val oldest = existing.firstOrNull()?.createdAtMs ?: nowMs
                db.execSQL("INSERT INTO device_sync_chunks " +
                    "(peer_device_id,topic,chunk_id,part_index,part_total,sequence,event_time_ms," +
                    "event_digest,chunk_bytes,created_at_ms,object_id,event_id) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", arrayOf(part.peerDeviceId, part.topic,
                        chunkId, part.index, part.total, part.sequence, part.eventTimeMs,
                        digest, part.bytes, oldest, part.objectId, part.eventId))
            }
            val allParts = if (existing.any { it.index == part.index }) existing else
                existing + StoredPart(part.index, part.total, part.sequence, part.eventTimeMs,
                    digest, part.bytes, existing.firstOrNull()?.createdAtMs ?: nowMs,
                    part.objectId, part.eventId)
            if (allParts.size < part.total) {
                db.setTransactionSuccessful()
                return Result.PENDING
            }
            require(allParts.size == part.total && allParts.map { it.index }.toSet().size == part.total)
            val delta = ByteArray(allParts.sumOf { it.bytes.size })
            var offset = 0
            for (item in allParts.sortedBy { it.index }) {
                item.bytes.copyInto(delta, offset)
                offset += item.bytes.size
            }
            try {
                val identity = RustBridge.deviceHistoryIdentity(delta, part.topic,
                    part.objectId, part.eventTimeMs)
                require(identity.size >= 66 && identity.copyOfRange(0, 32).contentEquals(digest) &&
                    identity.copyOfRange(32, 64).toHex() == part.eventId &&
                    identity.size - 64 <= maxSize)
                val canonical = identity.copyOfRange(64, identity.size)
                try {
                    val committed = apply(db, canonical)
                    if (committed) db.execSQL(
                        "DELETE FROM device_sync_chunks WHERE peer_device_id=? AND topic=? AND chunk_id=?",
                        arrayOf(part.peerDeviceId, part.topic, chunkId))
                    db.setTransactionSuccessful()
                    return if (committed) Result.COMMITTED else Result.DEFERRED
                } finally { canonical.fill(0); identity.fill(0) }
            } finally { delta.fill(0) }
        } finally { db.endTransaction() }
    }

    private data class StoredPart(val index: Int, val total: Int, val sequence: Long,
                                  val eventTimeMs: Long, val digest: ByteArray,
                                  val bytes: ByteArray, val createdAtMs: Long,
                                  val objectId: String, val eventId: String)

    private fun hexToBytes(hex: String) = ByteArray(32) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
