package com.securelegion.sync

import java.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/** Only signed connection operations may enter the Tor metadata queue. */
internal class DeviceSyncGroupLinkPublisher(private val database: SecureLegionDatabase,
                                            private val roster: DeviceRosterStore) {
    private val outbox = DeviceSyncOutboxStore(database, roster)

    fun prepare(account: ByteArray, local: String, peer: String,
                nowMs: Long = System.currentTimeMillis()) {
        require(roster.isLocalAuthorized(account, local, 0x06, nowMs) &&
            roster.isAuthorized(account, peer, 0x06, nowMs))
        val db = database.openHelper.readableDatabase
        val groups = db.query(SimpleSQLiteQuery(
            "SELECT groupId,groupSecretB64 FROM groups ORDER BY groupId"
        )).use { c -> buildList {
            while (c.moveToNext()) add(c.getString(0) to c.getString(1))
        } }
        for ((group, secret64) in groups) {
            if (!roster.isLocalAuthorized(account, local, 0x06) ||
                !roster.isAuthorized(account, peer, 0x06)) break
            if (!group.matches(Regex("[0-9a-f]{64}"))) continue
            val secret = runCatching { Base64.getDecoder().decode(secret64) }.getOrNull()
                ?: continue
            if (secret.size != 32 || Base64.getEncoder().encodeToString(secret) != secret64)
                continue
            val stream = ByteArrayOutputStream()
            val complete = ByteArrayOutputStream()
            var accepted = 0
            var overflow = false
            db.query(SimpleSQLiteQuery("SELECT opBytes FROM crdt_op_log " +
                "WHERE groupId=? ORDER BY lamport,opId", arrayOf(group))).use { c ->
                while (c.moveToNext()) {
                    val op = c.getBlob(0)
                    if (op.size !in 1..66_560) { overflow = true; break }
                    val framed = byteArrayOf((op.size ushr 24).toByte(),
                        (op.size ushr 16).toByte(), (op.size ushr 8).toByte(),
                        op.size.toByte()) + op
                    if (complete.size() + framed.size > 23 * 1024 * 1024) {
                        overflow = true; break
                    }
                    complete.write(framed)
                    if (op.size > 65_536) continue
                    if (!RustBridge.validateDeviceGroupLinkOps(framed)) continue
                    if (++accepted > 256 || stream.size() + framed.size > 5_900_000) {
                        overflow = true; break
                    }
                    stream.write(framed)
                }
            }
            if (overflow) continue
            val fullOps = complete.toByteArray()
            val validGroup = fullOps.isNotEmpty() &&
                RustBridge.crdtLoadGroup(group, fullOps)
            fullOps.fill(0)
            if (!validGroup) continue
            val members = JSONArray(RustBridge.crdtQuery(group, "members", "{}"))
            val ownAccount = account.toHex()
            if ((0 until members.length()).none { index ->
                    val member = members.getJSONObject(index)
                    member.optString("pubkey_hex").lowercase() == ownAccount &&
                        !member.optBoolean("removed")
                }) continue
            val packed = stream.toByteArray()
            if (packed.isEmpty() || !RustBridge.validateDeviceGroupLinkOps(packed)) continue
            val digest = MessageDigest.getInstance("SHA-256").digest(packed).toHex()
            val id = "$group:$digest"
            val delta = JSONObject().put("group_snapshot_id", id).put("group_id", group)
                .put("packed_ops", Base64.getEncoder().encodeToString(packed))
                .put("group_secret", secret64)
            DeviceSyncGroupDelta.parse(delta, "group_links", id)
            val old = db.query(SimpleSQLiteQuery(
                "SELECT event_time_ms,sequence,digest FROM device_sync_local_events " +
                    "WHERE topic='group_links' AND object_id=?", arrayOf(id)
            )).use { c -> if (c.moveToFirst()) Triple(c.getLong(0), c.getLong(1), c.getBlob(2))
                else null }
            val raw = delta.toString().toByteArray(Charsets.UTF_8)
            val proposedTime = maxOf(nowMs, (old?.first ?: 0L) + 1)
            val proposed = RustBridge.deviceHistoryIdentity(raw, "group_links", id, proposedTime)
            try {
                require(proposed.size >= 66)
                val unchanged = old != null && old.third.contentEquals(proposed.copyOfRange(0, 32))
                val time = if (unchanged) old!!.first else proposedTime
                val sequence = if (unchanged) old!!.second else (old?.second ?: 0L) + 1
                val identity = if (unchanged) RustBridge.deviceHistoryIdentity(raw,
                    "group_links", id, time) else proposed
                try {
                    val event = identity.copyOfRange(32, 64).toHex()
                    if (known(db, "device_sync_outbox", peer, id, event) ||
                        known(db, "device_sync_acks", peer, id, event)) continue
                    val observed = db.query(SimpleSQLiteQuery(
                        "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                            "peer_device_id=? AND topic='group_links' AND object_id=?",
                        arrayOf(peer, id)
                    )).use { c -> if (c.moveToFirst()) c.getLong(0) to c.getBlob(1)
                        else null }
                    if (observed != null && observed.first == time &&
                        observed.second.contentEquals(identity.copyOfRange(0, 32))) continue
                    outbox.enqueue(account, local, peer, "group_links", id,
                        time, sequence, identity.copyOfRange(64, identity.size),
                        DeviceSyncOutboxStore.Transport.TOR, nowMs = nowMs)
                } finally { if (identity !== proposed) identity.fill(0) }
            } finally { proposed.fill(0); raw.fill(0); packed.fill(0); secret.fill(0) }
        }
    }

    private fun known(db: androidx.sqlite.db.SupportSQLiteDatabase, table: String,
                      peer: String, id: String, event: String): Boolean =
        db.query(SimpleSQLiteQuery("SELECT event_id FROM $table WHERE peer_device_id=? " +
            "AND topic='group_links' AND object_id=?", arrayOf(peer, id)))
            .use { it.moveToFirst() && it.getString(0) == event }

    private fun ByteArray.toHex() = joinToString("") {
        "%02x".format(it.toInt() and 255)
    }
}
