package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.LinkedChatStore
import com.securelegion.crypto.RustBridge
import org.json.JSONObject

/** Applies only contacts whose account keys are already pinned on this install. */
internal class DeviceSyncContactReceiver(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val linked: LinkedChatStore? = null
) {
    private val chunks = DeviceSyncChunkStore(database, roster)
    private var pendingScanAfterId = 0L

    fun receive(accountEd: ByteArray, localDeviceId: String,
                part: DeviceSyncChunkStore.Part,
                nowMs: Long = System.currentTimeMillis()): DeviceSyncChunkStore.Result {
        require(part.topic == "contacts")
        return chunks.receive(accountEd, localDeviceId, part, nowMs) { db, canonical ->
            require(canonical.size in 2..400_000)
            val contact = DeviceSyncContactDelta.parse(
                JSONObject(canonical.toString(Charsets.UTF_8)), nowMs)
            require(Base64.encodeToString(contact.publicKey, Base64.NO_WRAP) == part.objectId)
            require(!contact.publicKey.contentEquals(accountEd))
            applyVersioned(db, part, contact, canonical, nowMs)
        }
    }

    /** Retry durable unknown-contact work when a verified contact card arrives. */
    fun drainPending(accountEd: ByteArray, localDeviceId: String,
                     nowMs: Long = System.currentTimeMillis()): List<DeviceSyncChunkStore.Part> {
        require(accountEd.size == 32 && localDeviceId.length == 43)
        val db = database.openHelper.writableDatabase
        val committed = ArrayList<DeviceSyncChunkStore.Part>()
        fun nextRows(afterId: Long) = db.query(SimpleSQLiteQuery(
            "SELECT id,peer_device_id,object_id,sequence,event_time_ms,delta_json,event_id,digest " +
                "FROM device_sync_pending WHERE topic='contacts' AND reason='missing_pinned_contact' " +
                "AND id>? ORDER BY id LIMIT 25", arrayOf(afterId)
        )).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(Pending(cursor.getLong(0), cursor.getString(1),
                    cursor.getString(2), cursor.getLong(3), cursor.getLong(4),
                    cursor.getBlob(5), cursor.getString(6), cursor.getBlob(7)))
            }
        }
        var rows = nextRows(pendingScanAfterId)
        if (rows.isEmpty() && pendingScanAfterId != 0L) {
            pendingScanAfterId = 0L
            rows = nextRows(0L)
        }
        for (row in rows) {
            pendingScanAfterId = row.id
            if (!roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs) ||
                !roster.isAuthorized(accountEd, row.peer, 0x02, nowMs)) continue
            try {
                require(row.eventTimeMs in 1..nowMs + 300_000L &&
                    row.sequence > 0 && row.digest.size == 32 &&
                    row.delta.size in 2..400_000 &&
                    row.eventId.matches(Regex("[0-9a-f]{64}")))
                val identity = RustBridge.deviceHistoryIdentity(row.delta, "contacts",
                    row.objectId, row.eventTimeMs)
                try {
                    require(identity.size >= 66 && identity.copyOfRange(0, 32)
                        .contentEquals(row.digest) && identity.copyOfRange(32, 64)
                        .toHex() == row.eventId)
                } finally { identity.fill(0) }
                val contact = DeviceSyncContactDelta.parse(
                    JSONObject(row.delta.toString(Charsets.UTF_8)), nowMs)
                require(Base64.encodeToString(contact.publicKey, Base64.NO_WRAP) == row.objectId)
                require(!contact.publicKey.contentEquals(accountEd))
                val part = DeviceSyncChunkStore.Part(row.peer, "contacts", row.objectId,
                    row.eventId, row.digest.toHex(), row.eventTimeMs, row.sequence,
                    0, 1, row.delta)
                db.beginTransaction()
                var applied = false
                try {
                    require(roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs) &&
                        roster.isAuthorized(accountEd, row.peer, 0x02, nowMs))
                    applied = applyVersioned(db, part, contact, row.delta, nowMs)
                    if (applied) {
                        db.execSQL("DELETE FROM device_sync_pending WHERE id=?", arrayOf(row.id))
                        db.execSQL("DELETE FROM device_sync_chunks WHERE peer_device_id=? " +
                            "AND topic='contacts' AND chunk_id=?",
                            arrayOf(row.peer, "hist:${row.eventId}"))
                    }
                    db.setTransactionSuccessful()
                } finally { db.endTransaction() }
                if (applied) committed.add(part)
            } catch (_: Exception) {
                // Preserve this row for a future card or repair while other work proceeds.
            }
        }
        return committed
    }

    private data class Pending(val id: Long, val peer: String, val objectId: String,
                               val sequence: Long, val eventTimeMs: Long,
                               val delta: ByteArray, val eventId: String,
                               val digest: ByteArray)

    private fun applyVersioned(db: SupportSQLiteDatabase,
                               part: DeviceSyncChunkStore.Part,
                               contact: DeviceSyncContactDelta.Contact,
                               canonical: ByteArray, nowMs: Long): Boolean {
        val pinnedX = if (!contact.deleted) {
            val existingPin = if (linked != null) db.query(SimpleSQLiteQuery(
                "SELECT x25519 FROM linked_chat_contacts WHERE account_ed=? " +
                    "AND blocked=0 LIMIT 1", arrayOf(part.objectId)
            )).use { if (it.moveToFirst()) it.getBlob(0) else null }
            else db.query(SimpleSQLiteQuery(
                "SELECT x25519PublicKeyBase64 FROM contacts WHERE publicKeyBase64=? " +
                    "AND friendshipStatus='CONFIRMED' AND isBlocked=0 LIMIT 1",
                arrayOf(part.objectId)
            )).use { if (it.moveToFirst()) Base64.decode(it.getString(0), Base64.NO_WRAP)
                else null }
            if (existingPin != null) require(existingPin.contentEquals(contact.x25519Key!!)) {
                "Contact account key rebind" }
            existingPin
        } else null
        val digest = ByteArray(32) { i ->
            part.digestHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        val prior = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,digest FROM device_sync_versions " +
                "WHERE peer_device_id=? AND topic='contacts' AND object_id=?",
            arrayOf(part.peerDeviceId, part.objectId)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
        if (prior != null && (prior.first > part.eventTimeMs ||
                prior.first == part.eventTimeMs && prior.second.toHex() >= part.digestHex)) {
            advanceCursor(db, part, nowMs)
            return true
        }
        val local = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,digest FROM device_sync_local_events " +
                "WHERE topic='contacts' AND object_id=?", arrayOf(part.objectId)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
        val incomingWins = local == null || part.eventTimeMs > local.first ||
            part.eventTimeMs == local.first && part.digestHex > local.second.toHex()
        if (incomingWins && !applyPinnedContact(db, part, contact, canonical, digest, nowMs)) {
            deferUnknownContact(db, part, canonical, digest, nowMs)
            return false
        }
        if (incomingWins && contact.deviceRoster != null &&
            (pinnedX != null || linked != null)) {
            // A linked contact first imported from an authenticated own-device
            // delta is pinned by applyPinnedContact above, in this transaction.
            roster.acceptSignedRosterInTransaction(db, contact.deviceRoster,
                contact.publicKey, null, nowMs)
        }
        db.execSQL("INSERT OR REPLACE INTO device_sync_versions " +
            "(peer_device_id,topic,object_id,event_time_ms,digest) " +
            "VALUES (?,'contacts',?,?,?)",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs, digest))
        advanceCursor(db, part, nowMs)
        db.execSQL("DELETE FROM device_sync_pending WHERE peer_device_id=? " +
            "AND topic='contacts' AND object_id=? AND event_time_ms<=?",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs))
        return true
    }

    private fun applyPinnedContact(db: SupportSQLiteDatabase,
                                   part: DeviceSyncChunkStore.Part,
                                   contact: DeviceSyncContactDelta.Contact,
                                   canonical: ByteArray, digest: ByteArray,
                                   nowMs: Long): Boolean {
        if (linked != null) return linked.applyContact(db, contact, nowMs)
        val existing = db.query(SimpleSQLiteQuery(
            "SELECT id,x25519PublicKeyBase64 FROM contacts WHERE publicKeyBase64=? LIMIT 1",
            arrayOf(part.objectId)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getString(1) else null }
        if (existing == null && !contact.deleted) return false
        if (existing != null && !contact.deleted) {
            require(Base64.decode(existing.second, Base64.NO_WRAP)
                .contentEquals(contact.x25519Key!!)) { "Contact account key rebind" }
        }
        db.execSQL("UPDATE device_sync_import_guard SET depth=depth+1 WHERE id=1")
        try {
            if (contact.deleted) {
                if (existing != null) {
                    db.execSQL("DELETE FROM device_sync_contact_profiles WHERE contact_id=?",
                        arrayOf(existing.first))
                    db.execSQL("DELETE FROM contacts WHERE id=?", arrayOf(existing.first))
                }
                db.execSQL("INSERT INTO device_sync_deletions(topic,object_id,event_time_ms) " +
                    "VALUES ('contacts',?,?) ON CONFLICT(topic,object_id) DO UPDATE SET " +
                    "event_time_ms=MAX(event_time_ms,excluded.event_time_ms)",
                    arrayOf(part.objectId, part.eventTimeMs))
            } else {
                val id = existing!!.first
                db.execSQL("UPDATE contacts SET displayName=?," +
                    "messagingOnion=COALESCE(?,messagingOnion)," +
                    "friendRequestOnion=CASE WHEN ? IS NULL THEN friendRequestOnion ELSE ? END " +
                    "WHERE id=?",
                    arrayOf(contact.displayName, contact.messagingOnion,
                        contact.friendRequestOnion, contact.friendRequestOnion, id))
                if (contact.avatarPresent && shouldApplyAvatar(db, id,
                        contact.profileVersion)) {
                    db.execSQL("UPDATE contacts SET profilePictureBase64=? WHERE id=?",
                        arrayOf(contact.avatar, id))
                    contact.profileVersion?.let { version ->
                        db.execSQL("INSERT OR REPLACE INTO device_sync_contact_profiles " +
                            "(contact_id,timestamp_ms,event_id) VALUES (?,?,?)",
                            arrayOf(id, version.timestampMs, version.eventId))
                    }
                }
            }
        } finally {
            db.execSQL("UPDATE device_sync_import_guard SET depth=depth-1 WHERE id=1")
        }
        db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
            "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
            "VALUES ('contacts',?,?,?,?,?)",
            arrayOf(part.objectId, part.eventTimeMs, digest, part.sequence, canonical))
        db.execSQL("INSERT INTO device_sync_source_changes " +
            "(topic,object_id,kind,changed_at_ms) VALUES ('contacts',?,?,?)",
            arrayOf(part.objectId, if (contact.deleted) "delete" else "upsert", nowMs))
        return true
    }

    private fun shouldApplyAvatar(db: SupportSQLiteDatabase, contactId: Long,
                                  incoming: DeviceSyncContactDelta.Version?): Boolean {
        val prior = db.query(SimpleSQLiteQuery(
            "SELECT timestamp_ms,event_id FROM device_sync_contact_profiles WHERE contact_id=?",
            arrayOf(contactId)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getString(1) else null }
        return if (incoming == null) prior == null else prior == null ||
            incoming.timestampMs > prior.first || incoming.timestampMs == prior.first &&
            incoming.eventId > prior.second
    }

    private fun deferUnknownContact(db: SupportSQLiteDatabase,
                                    part: DeviceSyncChunkStore.Part,
                                    canonical: ByteArray, digest: ByteArray,
                                    nowMs: Long) {
        val existing = db.query(SimpleSQLiteQuery(
            "SELECT event_id,digest,delta_json FROM device_sync_pending WHERE " +
                "peer_device_id=? AND topic='contacts' AND object_id=? AND event_time_ms=?",
            arrayOf(part.peerDeviceId, part.objectId, part.eventTimeMs)
        )).use { if (it.moveToFirst()) Triple(it.getString(0), it.getBlob(1),
            it.getBlob(2)) else null }
        if (existing != null) {
            require(existing.first == part.eventId && existing.second.contentEquals(digest) &&
                existing.third.contentEquals(canonical)) { "Conflicting deferred contact" }
            return
        }
        val queued = db.query(SimpleSQLiteQuery(
            "SELECT COUNT(*),COALESCE(SUM(length(delta_json)),0) FROM device_sync_pending " +
                "WHERE peer_device_id=?", arrayOf(part.peerDeviceId)
        )).use { check(it.moveToFirst()); it.getLong(0) to it.getLong(1) }
        require(queued.first < 256 && queued.second + canonical.size <= 16L * 1024 * 1024)
        db.execSQL("INSERT OR IGNORE INTO device_sync_pending " +
            "(peer_device_id,topic,object_id,sequence,event_time_ms,delta_json,reason," +
            "created_at_ms,event_id,digest,is_live) VALUES (?,'contacts',?,?,?,?,?,?,?,?,0)",
            arrayOf(part.peerDeviceId, part.objectId, part.sequence, part.eventTimeMs,
                canonical, "missing_pinned_contact", nowMs, part.eventId, digest))
    }

    private fun advanceCursor(db: SupportSQLiteDatabase,
                              part: DeviceSyncChunkStore.Part, nowMs: Long) {
        db.execSQL("INSERT INTO device_sync_cursors " +
            "(peer_device_id,topic,pushed_seq,received_seq,updated_at_ms) " +
            "VALUES (?,'contacts',0,?,?) ON CONFLICT(peer_device_id,topic) DO UPDATE SET " +
            "received_seq=MAX(received_seq,excluded.received_seq)," +
            "updated_at_ms=excluded.updated_at_ms",
            arrayOf(part.peerDeviceId, part.sequence, nowMs))
    }

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
