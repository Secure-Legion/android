package com.securelegion.sync

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.LinkedChatStore
import com.securelegion.database.DeviceSyncSourceCapture
import org.json.JSONObject

/** Authenticated live message import; missing pinned contacts remain durable. */
internal class DeviceSyncLiveMessageReceiver(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val encryptForLocalProfile: (String) -> String,
    private val storeMedia: (DeviceSyncMessageDelta.Message) -> String = {
        throw IllegalArgumentException("Media storage unavailable")
    },
    private val linked: LinkedChatStore? = null
) {
    private val chunks = DeviceSyncChunkStore(database, roster)
    data class Applied(val peerDeviceId: String, val objectId: String,
                       val eventId: String, val digestHex: String, val eventTimeMs: Long)

    fun receive(accountEd: ByteArray, localDeviceId: String,
                part: DeviceSyncChunkStore.Part, liveNegotiated: Boolean,
                nowMs: Long = System.currentTimeMillis(),
                archiveAuthenticated: Boolean = false): DeviceSyncChunkStore.Result {
        require((liveNegotiated || archiveAuthenticated) && part.topic == "messages")
        return chunks.receive(accountEd, localDeviceId, part, nowMs) { db, canonical ->
            require(canonical.size in 2..8 * 1024 * 1024)
            val message = DeviceSyncMessageDelta.parse(
                JSONObject(canonical.toString(Charsets.UTF_8)), nowMs)
            require(message.id == part.objectId)
            applyVersioned(db, accountEd, part, message, canonical, nowMs,
                isLive = !archiveAuthenticated)
        }
    }

    /** Retry retained events after their pinned contact arrives. */
    fun drainPending(accountEd: ByteArray, localDeviceId: String,
                     liveNegotiated: (String) -> Boolean,
                     nowMs: Long = System.currentTimeMillis()): List<Applied> {
        val db = database.openHelper.writableDatabase
        val applied = ArrayList<Applied>()
        var afterId = 0L
        while (true) {
            val rows = db.query(SimpleSQLiteQuery(
                "SELECT id,peer_device_id,object_id,sequence,event_time_ms,delta_json," +
                    "event_id,digest FROM device_sync_pending WHERE id>? " +
                    "AND topic='messages' AND is_live=1 ORDER BY id LIMIT 25",
                arrayOf(afterId)
            )).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(Pending(cursor.getLong(0),
                        cursor.getString(1), cursor.getString(2), cursor.getLong(3),
                        cursor.getLong(4), cursor.getBlob(5), cursor.getString(6),
                        cursor.getBlob(7)))
                }
            }
            if (rows.isEmpty()) break
            for (row in rows) {
                afterId = row.id
                if (!liveNegotiated(row.peer) ||
                    !roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs) ||
                    !roster.isAuthorized(accountEd, row.peer, 0x02, nowMs)) continue
                try {
                    require(row.eventId.matches(Regex("[0-9a-f]{64}")) &&
                        row.digest.size == 32 && row.delta.size in 2..8 * 1024 * 1024)
                    val identity = RustBridge.deviceHistoryIdentity(row.delta, "messages",
                        row.objectId, row.eventTimeMs)
                    try {
                        require(identity.size >= 66 && identity.copyOfRange(0, 32)
                            .contentEquals(row.digest) && identity.copyOfRange(32, 64)
                            .toHex() == row.eventId)
                    } finally { identity.fill(0) }
                    val message = DeviceSyncMessageDelta.parse(
                        JSONObject(row.delta.toString(Charsets.UTF_8)), nowMs)
                    require(message.id == row.objectId)
                    val part = DeviceSyncChunkStore.Part(row.peer, "messages", row.objectId,
                        row.eventId, row.digest.toHex(), row.eventTimeMs, row.sequence,
                        0, 1, row.delta)
                    db.beginTransaction()
                    var committed = false
                    try {
                        require(liveNegotiated(row.peer) &&
                            roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs) &&
                            roster.isAuthorized(accountEd, row.peer, 0x02, nowMs))
                        committed = applyVersioned(db, accountEd, part, message, row.delta, nowMs)
                        if (committed) {
                            db.execSQL("DELETE FROM device_sync_pending WHERE id=?",
                                arrayOf(row.id))
                            db.execSQL("DELETE FROM device_sync_chunks WHERE peer_device_id=? " +
                                "AND topic='messages' AND chunk_id=?",
                                arrayOf(row.peer, "hist:${row.eventId}"))
                        }
                        db.setTransactionSuccessful()
                    } finally { db.endTransaction() }
                    if (committed) applied.add(Applied(row.peer, row.objectId,
                        row.eventId, row.digest.toHex(), row.eventTimeMs))
                } catch (_: Exception) {
                    // A bad row cannot prevent later contacts/messages from progressing.
                }
            }
        }
        return applied
    }

    private fun applyVersioned(db: SupportSQLiteDatabase, accountEd: ByteArray,
                               part: DeviceSyncChunkStore.Part,
                               message: DeviceSyncMessageDelta.Message,
                               canonical: ByteArray, nowMs: Long,
                               isLive: Boolean = true): Boolean {
        val digest = ByteArray(32) { index ->
            part.digestHex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
        val prior = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                "peer_device_id=? AND topic='messages' AND object_id=?",
            arrayOf(part.peerDeviceId, part.objectId)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
        if (prior != null && (prior.first > part.eventTimeMs ||
                prior.first == part.eventTimeMs && prior.second.toHex() >= part.digestHex)) {
            advanceCursor(db, part, nowMs)
            return true
        }
        val local = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,sequence,digest FROM device_sync_local_events " +
                "WHERE topic='messages' AND object_id=?", arrayOf(part.objectId)
        )).use { if (it.moveToFirst()) Triple(it.getLong(0), it.getLong(1),
            it.getBlob(2)) else null }
        val incomingWins = local == null || part.eventTimeMs > local.first ||
            part.eventTimeMs == local.first && part.digestHex > local.third.toHex()
        if (incomingWins && !(linked?.applyMessage(db, message) ?:
                DeviceSyncDirectMessageStore.applyInTransaction(db, message,
                    encryptForLocalProfile, storeMedia))) {
            defer(db, part, canonical, digest, nowMs, isLive)
            return false
        }
        if (incomingWins) {
            if (!message.deleted && message.reactions.isNotEmpty())
                mergeReactions(db, accountEd, message)
            db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
                "VALUES ('messages',?,?,?,?,?)",
                arrayOf(part.objectId, part.eventTimeMs, digest,
                    maxOf(part.sequence, (local?.second ?: 0L) + 1), canonical))
            db.execSQL("INSERT INTO device_sync_source_changes " +
                "(topic,object_id,kind,changed_at_ms) " +
                "VALUES ('messages',?,'import',?)", arrayOf(part.objectId, nowMs))
            if (!message.deleted && message.contactX25519 != null) {
                val account = if (linked != null) db.query(SimpleSQLiteQuery(
                    "SELECT account_ed FROM linked_chat_contacts WHERE x25519=? AND blocked=0",
                    arrayOf(message.contactX25519)
                )).use { if (it.moveToFirst()) it.getString(0) else null }
                else db.query(SimpleSQLiteQuery(
                    "SELECT publicKeyBase64 FROM contacts WHERE " +
                        "x25519PublicKeyBase64=? AND friendshipStatus='CONFIRMED' AND isBlocked=0",
                    arrayOf(android.util.Base64.encodeToString(message.contactX25519,
                        android.util.Base64.NO_WRAP))
                )).use { if (it.moveToFirst()) it.getString(0) else null }
                if (account != null) DeviceChatControlStore(encryptForLocalProfile,
                    linked != null).drainForMessage(db,
                    android.util.Base64.decode(account, android.util.Base64.NO_WRAP), nowMs)
            }
        }
        db.execSQL("INSERT OR REPLACE INTO device_sync_versions " +
            "(peer_device_id,topic,object_id,event_time_ms,digest) " +
            "VALUES (?,'messages',?,?,?)",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs, digest))
        advanceCursor(db, part, nowMs)
        db.execSQL("DELETE FROM device_sync_pending WHERE peer_device_id=? " +
            "AND topic='messages' AND object_id=? AND event_time_ms<=?",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs))
        return true
    }

    private fun mergeReactions(db: SupportSQLiteDatabase, accountEd: ByteArray,
                               message: DeviceSyncMessageDelta.Message) {
        val x = requireNotNull(message.contactX25519)
        val own = android.util.Base64.encodeToString(accountEd,
            android.util.Base64.NO_WRAP)
        val contact = if (linked != null) db.query(SimpleSQLiteQuery(
            "SELECT account_ed FROM linked_chat_contacts WHERE x25519=? AND blocked=0",
            arrayOf(x)
        )).use { if (it.moveToFirst()) it.getString(0) else null }
        else db.query(SimpleSQLiteQuery("SELECT publicKeyBase64 FROM contacts WHERE " +
            "x25519PublicKeyBase64=? AND friendshipStatus='CONFIRMED' AND isBlocked=0",
            arrayOf(android.util.Base64.encodeToString(x, android.util.Base64.NO_WRAP))
        )).use { if (it.moveToFirst()) it.getString(0) else null }
        require(contact != null)
        val contactId = if (linked == null) db.query(SimpleSQLiteQuery(
            "SELECT id FROM contacts WHERE publicKeyBase64=?", arrayOf(contact)
        )).use { if (it.moveToFirst()) it.getLong(0) else null } else null
        if (linked != null) db.execSQL("CREATE TABLE IF NOT EXISTS linked_chat_reactions (" +
            "account_ed TEXT NOT NULL,target_id TEXT NOT NULL,emoji TEXT NOT NULL," +
            "removed INTEGER NOT NULL,updated_at_ms INTEGER NOT NULL," +
            "PRIMARY KEY(account_ed,target_id))")
        DeviceSyncSourceCapture.suppressDuringImport(db) {
        for (reaction in message.reactions) {
            require(reaction.actor == own || reaction.actor == contact)
            if (linked != null) db.execSQL("INSERT INTO linked_chat_reactions " +
                "(account_ed,target_id,emoji,removed,updated_at_ms) VALUES (?,?,?,?,?) " +
                "ON CONFLICT(account_ed,target_id) DO UPDATE SET emoji=excluded.emoji," +
                "removed=excluded.removed,updated_at_ms=excluded.updated_at_ms " +
                "WHERE excluded.updated_at_ms>=updated_at_ms",
                arrayOf(reaction.actor, message.id, reaction.emoji,
                    if (reaction.removed) 1 else 0, reaction.timestamp))
            else db.execSQL("INSERT INTO message_reactions " +
                "(contactId,targetMessageId,reactorPubKey,emoji,isRemoved,createdAt,updatedAt) " +
                "VALUES (?,?,?,?,?,?,?) ON CONFLICT(contactId,targetMessageId,reactorPubKey) " +
                "DO UPDATE SET emoji=excluded.emoji,isRemoved=excluded.isRemoved," +
                "updatedAt=excluded.updatedAt WHERE excluded.updatedAt>=updatedAt",
                arrayOf(requireNotNull(contactId), message.id, reaction.actor,
                    reaction.emoji, if (reaction.removed) 1 else 0,
                    reaction.timestamp, reaction.timestamp))
        }
        }
    }

    private fun defer(db: SupportSQLiteDatabase, part: DeviceSyncChunkStore.Part,
                      canonical: ByteArray, digest: ByteArray, nowMs: Long,
                      isLive: Boolean) {
        val existing = db.query(SimpleSQLiteQuery(
            "SELECT event_id,digest,delta_json FROM device_sync_pending " +
                "WHERE peer_device_id=? AND topic='messages' AND object_id=? " +
                "AND event_time_ms=?",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs)
        )).use { if (it.moveToFirst()) Triple(it.getString(0), it.getBlob(1),
            it.getBlob(2)) else null }
        if (existing != null) {
            require(existing.first == part.eventId && existing.second.contentEquals(digest) &&
                existing.third.contentEquals(canonical))
            return
        }
        val queued = db.query(SimpleSQLiteQuery(
            "SELECT COUNT(*),COALESCE(SUM(length(delta_json)),0) " +
            "FROM device_sync_pending WHERE peer_device_id=? AND is_live=?",
            arrayOf(part.peerDeviceId, if (isLive) 1 else 0)
        )).use { check(it.moveToFirst()); it.getLong(0) to it.getLong(1) }
        require(queued.first < 256 && queued.second + canonical.size <= 16L * 1024 * 1024)
        db.execSQL("INSERT INTO device_sync_pending " +
            "(peer_device_id,topic,object_id,sequence,event_time_ms,delta_json,reason," +
            "created_at_ms,event_id,digest,is_live) " +
            "VALUES (?,'messages',?,?,?,?,?,?,?,?,?)",
            arrayOf(part.peerDeviceId, part.objectId, part.sequence,
                part.eventTimeMs, canonical, "missing_contact", nowMs,
                part.eventId, digest, if (isLive) 1 else 0))
    }

    private fun advanceCursor(db: SupportSQLiteDatabase,
                              part: DeviceSyncChunkStore.Part, nowMs: Long) {
        db.execSQL("INSERT INTO device_sync_cursors " +
            "(peer_device_id,topic,pushed_seq,received_seq,updated_at_ms) " +
            "VALUES (?,'messages',0,?,?) ON CONFLICT(peer_device_id,topic) DO UPDATE SET " +
            "received_seq=MAX(received_seq,excluded.received_seq)," +
            "updated_at_ms=excluded.updated_at_ms",
            arrayOf(part.peerDeviceId, part.sequence, nowMs))
    }

    private data class Pending(val id: Long, val peer: String, val objectId: String,
                               val sequence: Long, val eventTimeMs: Long,
                               val delta: ByteArray, val eventId: String,
                               val digest: ByteArray)

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
