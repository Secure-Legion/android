package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncContactWorkStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject
import java.security.MessageDigest

/** Bounded contact metadata preparation; a socket write never clears its outbox. */
internal class DeviceSyncContactPublisher(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val linked: Boolean = false
) {
    private val work = DeviceSyncContactWorkStore(database, roster, linked)
    private val outbox = DeviceSyncOutboxStore(database, roster)
    private val onion = Regex("[a-z2-7]{56}\\.onion")

    fun prepareBatch(accountEd: ByteArray, localId: String, peerId: String,
                     nowMs: Long = System.currentTimeMillis(),
                     contactRosterNegotiated: Boolean = false) {
        work.initialize(accountEd, localId, peerId, nowMs)
        work.discover(accountEd, localId, peerId, nowMs)
        for (change in work.due(peerId, nowMs)) {
            try {
                val revision = capture(change.objectId, nowMs)
                if (revision != null) queue(accountEd, localId, peerId, revision, nowMs,
                    contactRosterNegotiated)
                work.completeChange(peerId, change.sequence)
            } catch (_: Exception) {
                work.defer(peerId, change.sequence, change.attempts, nowMs)
            }
        }
        val seed = work.nextSeed(peerId)
        if (seed != null) {
            try {
                val revision = capture(seed.objectId, nowMs)
                if (revision != null) queue(accountEd, localId, peerId, revision, nowMs,
                    contactRosterNegotiated)
                work.completeSeed(peerId, seed.contactId)
            } catch (_: Exception) {
                // Keep the seed cursor: a transient failure must not lose this contact.
            }
        } else {
            val deletion = work.nextDeletionSeed(peerId) ?: return
            try {
                val revision = capture(deletion, nowMs)
                if (revision != null) queue(accountEd, localId, peerId, revision, nowMs,
                    contactRosterNegotiated)
                work.completeDeletionSeed(peerId, deletion)
            } catch (_: Exception) {
                // Retain this tombstone for the next old-work turn.
            }
        }
    }

    private fun capture(objectId: String, nowMs: Long): Revision? {
        if (objectId.length != 44) return null
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val row = if (linked) db.query(SimpleSQLiteQuery(
                "SELECT rowid,display_name,account_ed,x25519," +
                    "friend_request_onion,messaging_onion,created_at_ms " +
                    "FROM linked_chat_contacts WHERE account_ed=? LIMIT 1",
                arrayOf(objectId)
            )).use { cursor ->
                if (!cursor.moveToFirst()) null else ContactRow(cursor.getLong(0),
                    cursor.getString(1), cursor.getString(2),
                    Base64.encodeToString(cursor.getBlob(3), Base64.NO_WRAP),
                    if (cursor.isNull(4)) null else cursor.getString(4),
                    if (cursor.isNull(5)) null else cursor.getString(5),
                    null, cursor.getLong(6), "CONFIRMED")
            } else db.query(SimpleSQLiteQuery(
                "SELECT id,displayName,publicKeyBase64,x25519PublicKeyBase64," +
                    "friendRequestOnion,messagingOnion,profilePictureBase64," +
                    "addedTimestamp,friendshipStatus FROM contacts " +
                    "WHERE publicKeyBase64=? LIMIT 1", arrayOf(objectId)
            )).use { cursor ->
                if (!cursor.moveToFirst()) null else ContactRow(cursor.getLong(0),
                    cursor.getString(1), cursor.getString(2), cursor.getString(3),
                    cursor.getString(4), cursor.getString(5), cursor.getString(6),
                    cursor.getLong(7), cursor.getString(8))
            }
            val old = db.query(SimpleSQLiteQuery(
                "SELECT event_time_ms,sequence,digest,delta_json FROM device_sync_local_events " +
                    "WHERE topic='contacts' AND object_id=?", arrayOf(objectId)
            )).use { if (it.moveToFirst()) Revision(objectId, it.getLong(0),
                it.getLong(1), it.getBlob(2), it.getBlob(3)) else null }
            if (linked && old != null) {
                // Linked contacts are controlled by authenticated own-device
                // revisions. Relay their exact canonical snapshot, including
                // avatar fields that this wallet-free projection does not need.
                db.setTransactionSuccessful()
                return old
            }
            val delta = if (row == null) {
                val deletedAt = db.query(SimpleSQLiteQuery(
                    "SELECT event_time_ms FROM device_sync_deletions WHERE " +
                        "topic='contacts' AND object_id=?", arrayOf(objectId)
                )).use { if (it.moveToFirst()) it.getLong(0) else null }
                if (deletedAt == null) { db.setTransactionSuccessful(); return null }
                JSONObject().put("public_key", objectId).put("deleted", true)
            } else {
                if (row.friendshipStatus != "CONFIRMED") {
                    db.setTransactionSuccessful()
                    return null
                }
                snapshot(db, row, old, nowMs)
            }
            DeviceSyncContactDelta.parse(delta, nowMs)
            val eventTime = maxOf(nowMs, (old?.eventTimeMs ?: 0L) + 1)
            val identity = RustBridge.deviceHistoryIdentity(
                delta.toString().toByteArray(Charsets.UTF_8), "contacts", objectId, eventTime)
            try {
                require(identity.size >= 66)
                val digest = identity.copyOfRange(0, 32)
                if (old != null && old.digest.contentEquals(digest)) {
                    db.setTransactionSuccessful()
                    return old
                }
                val canonical = identity.copyOfRange(64, identity.size)
                val sequence = (old?.sequence ?: 0L) + 1
                db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                    "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
                    "VALUES ('contacts',?,?,?,?,?)",
                    arrayOf(objectId, eventTime, digest, sequence, canonical))
                db.setTransactionSuccessful()
                return Revision(objectId, eventTime, sequence, digest, canonical)
            } finally { identity.fill(0) }
        } finally { db.endTransaction() }
    }

    private fun snapshot(db: androidx.sqlite.db.SupportSQLiteDatabase, row: ContactRow,
                         old: Revision?, nowMs: Long): JSONObject {
        // A contact's wallet address and private chat state are never inferred.
        require(Base64.decode(row.ed, Base64.NO_WRAP).size == 32 &&
            Base64.decode(row.x, Base64.NO_WRAP).size == 32)
        val delta = JSONObject().put("public_key", row.ed).put("x25519_pub", row.x)
            .put("display_name", row.name)
            .put("messaging_onion", row.messaging?.takeIf(onion::matches) ?: JSONObject.NULL)
            .put("friend_request_onion", row.friendRequest?.takeIf(onion::matches)
                ?: JSONObject.NULL)
            .put("friendship_status", 3)
            .put("created_at", row.addedAt.coerceIn(1L, nowMs))
        val previousAvatar = old?.let { revision ->
            runCatching { JSONObject(revision.delta.toString(Charsets.UTF_8)) }
                .getOrNull()?.opt("avatar")
        }
        if (row.avatar != null || previousAvatar != null) {
            val avatar = row.avatar ?: JSONObject.NULL
            val candidate = JSONObject(delta.toString()).put("avatar", avatar)
            if (runCatching { DeviceSyncContactDelta.parse(candidate, nowMs) }.isSuccess) {
                val stored = db.query(SimpleSQLiteQuery(
                    "SELECT timestamp_ms,event_id FROM device_sync_contact_profiles " +
                        "WHERE contact_id=?", arrayOf(row.id)
                )).use { if (it.moveToFirst()) it.getLong(0) to it.getString(1) else null }
                val unchanged = previousAvatar == avatar
                val version = if (unchanged && stored != null) stored else {
                    val nextTime = maxOf(nowMs, (stored?.first ?: 0L) + 1)
                    val hash = MessageDigest.getInstance("SHA-256")
                        .digest((row.avatar ?: "deleted").toByteArray(Charsets.UTF_8))
                        .toHex()
                    db.execSQL("INSERT OR REPLACE INTO device_sync_contact_profiles " +
                        "(contact_id,timestamp_ms,event_id) VALUES (?,?,?)",
                        arrayOf(row.id, nextTime, hash))
                    nextTime to hash
                }
                candidate.put("profile_version", JSONObject()
                    .put("timestamp", version.first).put("event_id", version.second))
                return candidate
            }
        }
        return delta
    }

    private fun queue(accountEd: ByteArray, localId: String, peerId: String,
                      revision: Revision, nowMs: Long,
                      contactRosterNegotiated: Boolean) {
        require(roster.isLocalAuthorized(accountEd, localId, 0x02, nowMs) &&
            roster.isAuthorized(accountEd, peerId, 0x02, nowMs))
        val db = database.openHelper.readableDatabase
        val publicRoster = if (contactRosterNegotiated &&
            runCatching { java.util.Base64.getDecoder().decode(revision.objectId).size == 32 }
                .getOrDefault(false)) roster.fetchSignedRoster(
                    java.util.Base64.getDecoder().decode(revision.objectId)) else null
        val delta = if (publicRoster != null &&
            !JSONObject(revision.delta.toString(Charsets.UTF_8)).optBoolean("deleted")) {
            JSONObject(revision.delta.toString(Charsets.UTF_8))
                .put("device_roster", java.util.Base64.getEncoder().encodeToString(publicRoster))
                .toString().toByteArray(Charsets.UTF_8)
        } else revision.delta
        val identity = RustBridge.deviceHistoryIdentity(delta, "contacts",
            revision.objectId, revision.eventTimeMs)
        try {
            require(identity.size >= 66)
            val digest = identity.copyOfRange(0, 32)
            val eventId = identity.copyOfRange(32, 64).toHex()
            val pending = db.query(SimpleSQLiteQuery(
                "SELECT event_id FROM device_sync_outbox WHERE peer_device_id=? " +
                    "AND topic='contacts' AND object_id=?",
                arrayOf(peerId, revision.objectId)
            )).use { if (it.moveToFirst()) it.getString(0) else null }
            if (pending == eventId) return
            val ack = db.query(SimpleSQLiteQuery(
                "SELECT event_id FROM device_sync_acks WHERE peer_device_id=? " +
                    "AND topic='contacts' AND object_id=?",
                arrayOf(peerId, revision.objectId)
            )).use { if (it.moveToFirst()) it.getString(0) else null }
            if (ack == eventId) return
            val observed = db.query(SimpleSQLiteQuery(
                "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                    "peer_device_id=? AND topic='contacts' AND object_id=?",
                arrayOf(peerId, revision.objectId)
            )).use { if (it.moveToFirst()) it.getLong(0) to it.getBlob(1) else null }
            if (observed != null && observed.first == revision.eventTimeMs &&
                observed.second.contentEquals(digest)) return
            outbox.enqueue(accountEd, localId, peerId, "contacts", revision.objectId,
                revision.eventTimeMs, revision.sequence, identity.copyOfRange(64, identity.size),
                DeviceSyncOutboxStore.Transport.TOR, nowMs = nowMs)
        } finally { identity.fill(0) }
    }

    private data class ContactRow(val id: Long, val name: String, val ed: String,
                                  val x: String, val friendRequest: String?,
                                  val messaging: String?, val avatar: String?,
                                  val addedAt: Long, val friendshipStatus: String)
    private data class Revision(val objectId: String, val eventTimeMs: Long,
                                val sequence: Long, val digest: ByteArray,
                                val delta: ByteArray)
    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
