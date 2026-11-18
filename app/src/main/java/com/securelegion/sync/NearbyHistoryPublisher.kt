package com.securelegion.sync

import android.content.Context
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject

/** Captures the owner's archive in bounded ID pages before a Nearby transfer. */
internal class NearbyHistoryPublisher(context: Context,
                                      private val database: SecureLegionDatabase,
                                      private val roster: DeviceRosterStore,
                                      keys: KeyManager) {
    private val messageExporter = DeviceSyncLivePublisher(context, database, roster, keys)
    private val outbox = DeviceSyncOutboxStore(database, roster)

    fun prepare(account: ByteArray, local: String, peer: String,
                progress: (String) -> Unit, checkActive: () -> Unit) {
        var lastId = ""
        var scanned = 0
        val db = database.openHelper.readableDatabase
        while (true) {
            val ids = db.query(SimpleSQLiteQuery(
                "SELECT messageId FROM messages WHERE messageId>? " +
                    "ORDER BY messageId LIMIT 25", arrayOf(lastId)
            )).use { c -> buildList {
                while (c.moveToNext()) add(c.getString(0))
            } }
            if (ids.isEmpty()) break
            for (id in ids) {
                checkActive()
                check(roster.isLocalAuthorized(account, local, 0x02) &&
                    roster.isAuthorized(account, peer, 0x02))
                val now = System.currentTimeMillis()
                // A live revision in flight owns this object key until settled.
                if (!hasPending(peer, "messages", id)) {
                    val delta = messageExporter.archiveMessageDelta(id, now)
                    queue(account, local, peer, "messages", id, delta, now)
                }
                if (!hasPending(peer, "receipts", id)) {
                    DeviceSyncReceiptDelta.export(db, id)?.let { receipt ->
                        queue(account, local, peer, "receipts", id, receipt, now)
                    }
                }
                scanned++
                if (scanned % 100 == 0) progress("Prepared $scanned messages")
            }
            lastId = ids.last()
        }
    }

    private fun hasPending(peer: String, topic: String, id: String): Boolean =
        database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT 1 FROM device_sync_outbox WHERE peer_device_id=? " +
                "AND topic=? AND object_id=?", arrayOf(peer, topic, id)
        )).use { it.moveToFirst() }

    private fun queue(account: ByteArray, local: String, peer: String,
                      topic: String, id: String, delta: JSONObject, nowMs: Long) {
        val db = database.openHelper.readableDatabase
        val old = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,sequence,digest FROM device_sync_local_events " +
                "WHERE topic=? AND object_id=?", arrayOf(topic, id)
        )).use { c -> if (c.moveToFirst()) Triple(c.getLong(0), c.getLong(1), c.getBlob(2))
            else null }
        val bytes = delta.toString().toByteArray(Charsets.UTF_8)
        val proposedTime = maxOf(nowMs, (old?.first ?: 0L) + 1L)
        val proposed = RustBridge.deviceHistoryIdentity(bytes, topic, id, proposedTime)
        try {
            require(proposed.size >= 66)
            val unchanged = old != null && old.third.contentEquals(proposed.copyOfRange(0, 32))
            val time = if (unchanged) old!!.first else proposedTime
            val seq = if (unchanged) old!!.second else (old?.second ?: 0L) + 1L
            val identity = if (unchanged) RustBridge.deviceHistoryIdentity(bytes,
                topic, id, time) else proposed
            try {
                require(identity.size >= 66)
                val eventId = identity.copyOfRange(32, 64).toHex()
                val ack = db.query(SimpleSQLiteQuery(
                    "SELECT event_id FROM device_sync_acks WHERE peer_device_id=? " +
                        "AND topic=? AND object_id=?", arrayOf(peer, topic, id)
                )).use { if (it.moveToFirst()) it.getString(0) else null }
                if (ack == eventId) return
                val observed = db.query(SimpleSQLiteQuery(
                    "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                        "peer_device_id=? AND topic=? AND object_id=?",
                    arrayOf(peer, topic, id)
                )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
                if (observed != null && observed.first == time &&
                    observed.second.contentEquals(identity.copyOfRange(0, 32))) return
                outbox.enqueue(account, local, peer, topic, id, time, seq,
                    identity.copyOfRange(64, identity.size),
                    DeviceSyncOutboxStore.Transport.NEARBY, nowMs = nowMs)
            } finally { if (identity !== proposed) identity.fill(0) }
        } finally { proposed.fill(0); bytes.fill(0) }
    }

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
