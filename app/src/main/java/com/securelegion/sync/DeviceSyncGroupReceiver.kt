package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/** Imports verified own-device group operations without creating chat contacts. */
internal class DeviceSyncGroupReceiver(database: SecureLegionDatabase,
                                       roster: DeviceRosterStore) {
    private val chunks = DeviceSyncChunkStore(database, roster)

    fun receive(account: ByteArray, local: String, part: DeviceSyncChunkStore.Part,
                nowMs: Long = System.currentTimeMillis()): DeviceSyncChunkStore.Result {
        require(part.topic == "groups" || part.topic == "group_links")
        return chunks.receive(account, local, part, nowMs) apply@{ db, canonical ->
            val delta = JSONObject(canonical.toString(Charsets.UTF_8))
            val snapshot = DeviceSyncGroupDelta.parse(delta, part.topic, part.objectId)
            // The legacy reader cannot interpret SLGO01/SLGE01 mixed history.
            val delegated = db.query(SimpleSQLiteQuery(
                "SELECT 1 FROM delegated_group_states WHERE group_id=? LIMIT 1",
                arrayOf(part.objectId)
            )).use { it.moveToFirst() }
            if (delegated) return@apply false
            val digest = part.digestHex.hexBytes()
            val prior = db.query(SimpleSQLiteQuery(
                "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                    "peer_device_id=? AND topic=? AND object_id=?",
                arrayOf(part.peerDeviceId, part.topic, part.objectId)
            )).use { c -> if (c.moveToFirst()) c.getLong(0) to c.getBlob(1) else null }
            if (prior != null && (prior.first > part.eventTimeMs ||
                    prior.first == part.eventTimeMs && prior.second.toHex() >= part.digestHex)) {
                advance(db, part, nowMs)
                true
            } else {
                val applied = if (snapshot == null) {
                    deleteGroup(db, part)
                    true
                } else applySnapshot(db, account, part, snapshot)
                if (applied) {
                    db.execSQL("INSERT OR REPLACE INTO device_sync_versions " +
                        "(peer_device_id,topic,object_id,event_time_ms,digest) " +
                        "VALUES (?,?,?,?,?)", arrayOf(part.peerDeviceId, part.topic,
                        part.objectId, part.eventTimeMs, digest))
                    db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                        "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
                        "VALUES (?,?,?,?,?,?)", arrayOf(part.topic, part.objectId,
                        part.eventTimeMs, digest, part.sequence, canonical))
                    advance(db, part, nowMs)
                }
                applied
            }
        }
    }

    private fun applySnapshot(db: SupportSQLiteDatabase, account: ByteArray,
                              part: DeviceSyncChunkStore.Part,
                              snapshot: DeviceSyncGroupDelta.Snapshot): Boolean {
        val group = snapshot.groupId
        val tombstone = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms FROM device_sync_deletions WHERE topic='groups' " +
                "AND object_id=?", arrayOf(group)
        )).use { if (it.moveToFirst()) it.getLong(0) else null }
        if (tombstone != null && tombstone >= part.eventTimeMs) return true
        val existingSecret = db.query(SimpleSQLiteQuery(
            "SELECT groupSecretB64 FROM groups WHERE groupId=?", arrayOf(group)
        )).use { if (it.moveToFirst()) it.getString(0) else null }
        if (existingSecret != null) require(Base64.decode(existingSecret, Base64.NO_WRAP)
            .contentEquals(snapshot.secret)) { "Group secret changed" }

        val operations = LinkedHashMap<String, ByteArray>()
        db.query(SimpleSQLiteQuery("SELECT opBytes FROM crdt_op_log WHERE groupId=?",
            arrayOf(group))).use { c -> while (c.moveToNext()) {
            val op = c.getBlob(0)
            operations[MessageDigest.getInstance("SHA-256").digest(op).toHex()] = op
        } }
        for (op in unpack(snapshot.packedOps)) {
            operations[MessageDigest.getInstance("SHA-256").digest(op).toHex()] = op
        }
        val merged = ByteArrayOutputStream()
        for (key in operations.keys.sorted()) {
            val op = operations.getValue(key)
            if (op.size !in 1..66_560 || merged.size() + 4L + op.size >
                23L * 1024 * 1024) return false
            val size = op.size
            merged.write(byteArrayOf((size ushr 24).toByte(), (size ushr 16).toByte(),
                (size ushr 8).toByte(), size.toByte()))
            merged.write(op)
        }
        val packed = merged.toByteArray()
        if (!DeviceSyncGroupDelta.validFraming(packed) ||
            !RustBridge.crdtLoadGroup(group, packed)) return false
        val members = JSONArray(RustBridge.crdtQuery(group, "members", "{}"))
        val accountHex = account.toHex()
        var own: JSONObject? = null
        var count = 0
        for (i in 0 until members.length()) {
            val member = members.getJSONObject(i)
            if (member.optString("pubkey_hex").lowercase() == accountHex) own = member
            if (member.optBoolean("accepted") && !member.optBoolean("removed")) count++
        }
        require(own != null && !own.optBoolean("removed")) { "Account is not a group member" }
        val metadata = JSONObject(RustBridge.crdtQuery(group, "metadata", "{}"))
        val name = metadata.optString("name").filter { !it.isISOControl() }
            .take(128).ifBlank { "Group" }
        if (existingSecret == null) {
            db.execSQL("INSERT INTO groups " +
                "(groupId,name,groupSecretB64,createdAt,lastActivityTimestamp," +
                "isMuted,memberCount,isPendingInvite,isPinned,unreadCount) " +
                "VALUES (?,?,?,?,?,0,?,?,0,0)",
                arrayOf(group, name, Base64.encodeToString(snapshot.secret, Base64.NO_WRAP),
                    part.eventTimeMs, part.eventTimeMs, count,
                    if (own.optBoolean("accepted")) 0 else 1))
        } else {
            db.execSQL("UPDATE groups SET name=?,memberCount=? WHERE groupId=?",
                arrayOf(name, count, group))
        }
        for ((hash, op) in operations) {
            db.execSQL("INSERT OR IGNORE INTO crdt_op_log " +
                "(opId,groupId,opType,opBytes,lamport,createdAt) VALUES (?,?,?,?,0,?)",
                arrayOf("sha256:$hash", group,
                    if (part.topic == "group_links") "GroupLinkSync" else "Received",
                    op, part.eventTimeMs))
        }
        return true
    }

    private fun deleteGroup(db: SupportSQLiteDatabase, part: DeviceSyncChunkStore.Part) {
        val group = part.objectId
        db.execSQL("DELETE FROM crdt_op_log WHERE groupId=?", arrayOf(group))
        db.execSQL("DELETE FROM groups WHERE groupId=?", arrayOf(group))
        db.execSQL("INSERT INTO device_sync_deletions(topic,object_id,event_time_ms) " +
            "VALUES ('groups',?,?) ON CONFLICT(topic,object_id) DO UPDATE SET " +
            "event_time_ms=MAX(event_time_ms,excluded.event_time_ms)",
            arrayOf(group, part.eventTimeMs))
        RustBridge.crdtUnloadGroup(group)
    }

    private fun advance(db: SupportSQLiteDatabase, part: DeviceSyncChunkStore.Part,
                        nowMs: Long) {
        db.execSQL("INSERT INTO device_sync_cursors " +
            "(peer_device_id,topic,pushed_seq,received_seq,updated_at_ms) " +
            "VALUES (?,?,0,?,?) ON CONFLICT(peer_device_id,topic) DO UPDATE SET " +
            "received_seq=MAX(received_seq,excluded.received_seq)," +
            "updated_at_ms=excluded.updated_at_ms",
            arrayOf(part.peerDeviceId, part.topic, part.sequence, nowMs))
    }

    private fun unpack(packed: ByteArray): List<ByteArray> {
        require(DeviceSyncGroupDelta.validFraming(packed))
        val output = ArrayList<ByteArray>()
        var offset = 0
        while (offset < packed.size) {
            val size = ((packed[offset].toInt() and 255) shl 24) or
                ((packed[offset + 1].toInt() and 255) shl 16) or
                ((packed[offset + 2].toInt() and 255) shl 8) or
                (packed[offset + 3].toInt() and 255)
            offset += 4
            output.add(packed.copyOfRange(offset, offset + size))
            offset += size
        }
        return output
    }

    private fun String.hexBytes() = ByteArray(length / 2) { i ->
        substring(2 * i, 2 * i + 2).toInt(16).toByte()
    }
    private fun ByteArray.toHex() = joinToString("") {
        "%02x".format(it.toInt() and 255)
    }
}
