package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceSyncFrameV2
import com.securelegion.sync.DeviceSyncSettlementWire
import com.securelegion.sync.DeviceSyncTorPolicy
import java.util.Locale

/** Durable own-device history work. All callers must hold an unlocked profile. */
class DeviceSyncOutboxStore(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore
) {
    data class Event(
        val peerDeviceId: String,
        val topic: String,
        val objectId: String,
        val eventId: String,
        val eventTimeMs: Long,
        val digest: ByteArray,
        val sequence: Long,
        val canonicalDelta: ByteArray,
        val transport: Transport,
        val attempts: Int,
        val isLive: Boolean
    )

    enum class Transport { TOR, NEARBY }

    /** Caller supplies a frame already authenticated by Noise or pinned Nearby TLS. */
    internal fun consumeAuthenticatedResponse(accountEd: ByteArray, localDeviceId: String,
                                     frame: DeviceSyncFrameV2.Frame,
                                     transport: Transport,
                                     liveNegotiated: Boolean = false,
                                     nowMs: Long = System.currentTimeMillis()): Boolean {
        require(frame.kind == DeviceSyncFrameV2.Kind.PULL_RESPONSE &&
            frame.recipient == localDeviceId)
        val response = DeviceSyncSettlementWire.parse(frame.payload)
        return when (response.kind) {
            DeviceSyncSettlementWire.Kind.TRANSPORT_SKIPPED ->
                transport == Transport.TOR && recordTorSkip(accountEd, localDeviceId,
                    frame.sender, response.eventId, response.digestHex, response.topic,
                    response.objectId, response.eventTimeMs, nowMs)
            DeviceSyncSettlementWire.Kind.SETTLED -> settle(accountEd, localDeviceId,
                frame.sender, transport, response.eventId, response.digestHex,
                response.topic, response.objectId, response.eventTimeMs, liveNegotiated, nowMs)
        }
    }

    private val torTopics = setOf("contacts", "settings")
    private val nearbyTopics = setOf("messages", "receipts", "contacts", "settings", "groups")

    /** Group links require a separate signed-operation validator before enqueue. */
    fun enqueue(
        accountEd: ByteArray,
        localDeviceId: String,
        peerDeviceId: String,
        topic: String,
        objectId: String,
        eventTimeMs: Long,
        sequence: Long,
        deltaJson: ByteArray,
        transport: Transport,
        isLive: Boolean = false,
        liveNegotiated: Boolean = false,
        nowMs: Long = System.currentTimeMillis()
    ): Event {
        require(accountEd.size == 32 && localDeviceId.length == 43 && peerDeviceId.length == 43)
        require(localDeviceId != peerDeviceId && objectId.isNotEmpty() && objectId.length <= 512)
        require(eventTimeMs in 1..9_007_199_254_740_991L && eventTimeMs <= nowMs + 300_000L)
        require(sequence > 0 && deltaJson.isNotEmpty())
        require(transport == Transport.TOR && (topic in torTopics && !isLive ||
            topic in DeviceSyncTorPolicy.liveTopics && isLive && liveNegotiated) ||
            transport == Transport.NEARBY && topic in nearbyTopics)
        require(!isLive || transport == Transport.TOR && topic in DeviceSyncTorPolicy.liveTopics)
        val capability = if (topic == "groups") 0x06 else 0x02
        require(roster.isLocalAuthorized(accountEd, localDeviceId, capability, nowMs))
        require(roster.isAuthorized(accountEd, peerDeviceId, capability, nowMs))

        val identity = RustBridge.deviceHistoryIdentity(deltaJson, topic, objectId, eventTimeMs)
        require(identity.size >= 66)
        val digest = identity.copyOfRange(0, 32)
        val eventId = identity.copyOfRange(32, 64).toHex()
        val canonical = identity.copyOfRange(64, identity.size)
        val event = Event(peerDeviceId, topic, objectId, eventId, eventTimeMs,
            digest, sequence, canonical, transport, 0, isLive)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            // Revocation can race with canonicalization; check again under the write transaction.
            require(roster.isLocalAuthorized(accountEd, localDeviceId, capability, nowMs))
            require(roster.isAuthorized(accountEd, peerDeviceId, capability, nowMs))
            if (isLive) requireLiveCapacity(db, peerDeviceId, topic, objectId, canonical.size)
            db.query(SimpleSQLiteQuery(
                "SELECT event_time_ms,sequence,digest FROM device_sync_local_events WHERE topic=? AND object_id=?",
                arrayOf(topic, objectId)
            )).use { cursor ->
                if (cursor.moveToFirst()) {
                    val identical = eventTimeMs == cursor.getLong(0) &&
                        sequence == cursor.getLong(1) && digest.contentEquals(cursor.getBlob(2))
                    require(identical || eventTimeMs > cursor.getLong(0) && sequence > cursor.getLong(1))
                }
            }
            db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                "(topic,object_id,event_time_ms,digest,sequence,delta_json) VALUES (?,?,?,?,?,?)",
                arrayOf(topic, objectId, eventTimeMs, digest, sequence, canonical))
            db.execSQL("INSERT OR REPLACE INTO device_sync_outbox " +
                "(peer_device_id,topic,object_id,event_id,event_time_ms,digest,sequence,delta_json," +
                "transport,next_try_at_ms,attempts,created_at_ms,is_live) " +
                "VALUES (?,?,?,?,?,?,?,?,?,0,0,?,?)",
                arrayOf(peerDeviceId, topic, objectId, eventId, eventTimeMs, digest,
                    sequence, canonical, transport.name, nowMs, if (isLive) 1 else 0))
            db.execSQL("DELETE FROM device_transport_skips WHERE peer_device_id=? AND event_id<>? " +
                "AND event_id NOT IN (SELECT event_id FROM device_sync_outbox WHERE peer_device_id=?)",
                arrayOf(peerDeviceId, eventId, peerDeviceId))
            db.setTransactionSuccessful()
            return event
        } finally {
            db.endTransaction()
        }
    }

    /** A Tor skip only backs off Tor retries; it never touches ACKs or cursors. */
    fun recordTorSkip(accountEd: ByteArray, localDeviceId: String, peerDeviceId: String,
                      eventId: String, digestHex: String, topic: String, objectId: String,
                      eventTimeMs: Long, nowMs: Long = System.currentTimeMillis()): Boolean {
        if (!validSettlementShape(eventId, digestHex, topic, objectId, eventTimeMs) ||
            !authorized(accountEd, localDeviceId, peerDeviceId, topic, nowMs)) return false
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val event = currentEvent(db, peerDeviceId, topic, objectId) ?: return false
            if (!matches(event, eventId, digestHex, eventTimeMs)) return false
            val skipAttempts: Int = db.query(SimpleSQLiteQuery(
                "SELECT attempts FROM device_transport_skips WHERE peer_device_id=? AND event_id=?",
                arrayOf(peerDeviceId, eventId)
            )).use { if (it.moveToFirst()) it.getInt(0) else 0 }
            val delay = (60_000L shl skipAttempts.coerceIn(0, 8)).coerceAtMost(21_600_000L)
            val next: Long = nowMs + delay
            db.execSQL("INSERT OR REPLACE INTO device_transport_skips " +
                "(peer_device_id,event_id,next_try_at_ms,attempts) VALUES (?,?,?,?)",
                arrayOf<Any>(peerDeviceId, eventId, next, skipAttempts + 1))
            db.setTransactionSuccessful()
            return true
        } finally {
            db.endTransaction()
        }
    }

    /** Only an authenticated exact settlement of the current revision clears work. */
    fun settle(accountEd: ByteArray, localDeviceId: String, peerDeviceId: String,
               transport: Transport, eventId: String, digestHex: String,
               topic: String, objectId: String, eventTimeMs: Long,
               liveNegotiated: Boolean = false,
               nowMs: Long = System.currentTimeMillis()): Boolean {
        if (!validSettlementShape(eventId, digestHex, topic, objectId, eventTimeMs) ||
            transport == Transport.TOR && topic !in torTopics &&
                !(topic in DeviceSyncTorPolicy.liveTopics && liveNegotiated) ||
            transport == Transport.NEARBY && topic !in nearbyTopics ||
            !authorized(accountEd, localDeviceId, peerDeviceId, topic, nowMs)) return false
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val event = currentEvent(db, peerDeviceId, topic, objectId) ?: return false
            if (!matches(event, eventId, digestHex, eventTimeMs)) return false
            if (transport == Transport.TOR && (event.transport != Transport.TOR ||
                    event.isLive != (topic in DeviceSyncTorPolicy.liveTopics))) return false
            db.execSQL("DELETE FROM device_sync_outbox WHERE peer_device_id=? AND topic=? " +
                "AND object_id=? AND event_id=?", arrayOf(peerDeviceId, topic, objectId, eventId))
            db.execSQL("INSERT OR REPLACE INTO device_sync_acks " +
                "(peer_device_id,topic,object_id,event_id,event_time_ms,digest,acknowledged_at_ms) " +
                "VALUES (?,?,?,?,?,?,?)", arrayOf(peerDeviceId, topic, objectId,
                    eventId, eventTimeMs, event.digest, nowMs))
            db.execSQL("DELETE FROM device_transport_skips WHERE peer_device_id=? AND event_id=?",
                arrayOf(peerDeviceId, eventId))
            db.setTransactionSuccessful()
            return true
        } finally {
            db.endTransaction()
        }
    }

    private fun authorized(accountEd: ByteArray, local: String, peer: String,
                           topic: String, nowMs: Long): Boolean {
        if (accountEd.size != 32 || local.length != 43 || peer.length != 43 || local == peer) return false
        val capability = if (topic == "groups" || topic == "group_links") 0x06 else 0x02
        return roster.isLocalAuthorized(accountEd, local, capability, nowMs) &&
            roster.isAuthorized(accountEd, peer, capability, nowMs)
    }

    /** A full queue rejects preparation; its source revision remains in the capture log. */
    private fun requireLiveCapacity(db: androidx.sqlite.db.SupportSQLiteDatabase,
                                    peer: String, topic: String, objectId: String,
                                    newBytes: Int) {
        require(newBytes in 1..MAX_LIVE_BYTES)
        val oldBytes = db.query(SimpleSQLiteQuery(
            "SELECT length(delta_json) FROM device_sync_outbox " +
                "WHERE peer_device_id=? AND topic=? AND object_id=? AND is_live=1",
            arrayOf(peer, topic, objectId)
        )).use { if (it.moveToFirst()) it.getLong(0) else null }
        db.query(SimpleSQLiteQuery(
            "SELECT COUNT(*),COALESCE(SUM(length(delta_json)),0) FROM device_sync_outbox " +
                "WHERE peer_device_id=? AND is_live=1", arrayOf(peer)
        )).use { cursor ->
            check(cursor.moveToFirst())
            val count = cursor.getLong(0) + if (oldBytes == null) 1 else 0
            val total = cursor.getLong(1) - (oldBytes ?: 0L) + newBytes
            require(count <= MAX_LIVE_REVISIONS && total <= MAX_LIVE_BYTES) {
                "Live outbox capacity reached"
            }
        }
    }

    private fun validSettlementShape(eventId: String, digest: String, topic: String,
                                     objectId: String, eventTimeMs: Long): Boolean =
        eventId.matches(Regex("[0-9a-f]{64}")) && digest.matches(Regex("[0-9a-f]{64}")) &&
            topic in nearbyTopics && objectId.isNotEmpty() && objectId.length <= 512 &&
            eventTimeMs in 1..9_007_199_254_740_991L

    private fun currentEvent(db: androidx.sqlite.db.SupportSQLiteDatabase, peer: String,
                             topic: String, objectId: String): Event? =
        db.query(SimpleSQLiteQuery("SELECT event_id,event_time_ms,digest,sequence,delta_json,transport,attempts,is_live " +
            "FROM device_sync_outbox WHERE peer_device_id=? AND topic=? AND object_id=?",
            arrayOf(peer, topic, objectId))).use { cursor ->
            if (!cursor.moveToFirst()) null else Event(peer, topic, objectId,
                cursor.getString(0), cursor.getLong(1), cursor.getBlob(2), cursor.getLong(3),
                cursor.getBlob(4), Transport.valueOf(cursor.getString(5)), cursor.getInt(6),
                cursor.getInt(7) == 1)
        }

    private fun matches(event: Event, eventId: String, digestHex: String, timeMs: Long): Boolean =
        event.eventId == eventId && event.eventTimeMs == timeMs &&
            event.digest.toHex() == digestHex

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }

    companion object {
        const val MAX_LIVE_REVISIONS = 256
        const val MAX_LIVE_BYTES = 16 * 1024 * 1024
    }
}
