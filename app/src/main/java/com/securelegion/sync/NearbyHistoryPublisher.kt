package com.securelegion.sync

import android.content.Context
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.DelegatedGroupOwnHistory
import com.securelegion.database.DelegatedGroupStateStore
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncContactWorkStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.util.Base64

/** Captures the owner's archive in bounded ID pages before a Nearby transfer. */
internal class NearbyHistoryPublisher(private val context: Context,
                                      private val database: SecureLegionDatabase,
                                      private val roster: DeviceRosterStore,
                                      private val keys: KeyManager) {
    private val messageExporter = DeviceSyncLivePublisher(context, database, roster, keys)
    private val outbox = DeviceSyncOutboxStore(database, roster)

    fun prepare(account: ByteArray, local: String, peer: String,
                peerCapabilities: Set<String>, progress: (String) -> Unit,
                checkActive: () -> Unit) {
        val contacts = DeviceSyncContactPublisher(database, roster)
        val contactWork = DeviceSyncContactWorkStore(database, roster)
        // A contact is a dependency of message import. Finish the bounded
        // contact seed before sending message history over this session.
        for (attempt in 0 until 100_000) {
            checkActive()
            val beforeSeed = contactWork.nextSeed(peer)
            val beforeDeletion = contactWork.nextDeletionSeed(peer)
            contacts.prepareBatch(account, local, peer)
            val afterSeed = contactWork.nextSeed(peer)
            val afterDeletion = contactWork.nextDeletionSeed(peer)
            if (afterSeed == null && afterDeletion == null) break
            check(beforeSeed != afterSeed || beforeDeletion != afterDeletion) {
                "Contact history needs repair before transfer"
            }
        }
        check(contactWork.nextSeed(peer) == null &&
            contactWork.nextDeletionSeed(peer) == null) {
            "Contact history exceeds the transfer preparation limit"
        }
        val settings = DeviceSyncAccountSettingsPublisher(database, roster)
        settings.capturePrimary(context, keys)
        settings.enqueueForPeer(account, local, peer)
        if ("group_snapshots_v1" in peerCapabilities &&
            roster.isLocalAuthorized(account, local, 0x06) &&
            roster.isAuthorized(account, peer, 0x06)) {
            prepareGroups(account, local, peer, peerCapabilities, checkActive)
        }
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

    private fun prepareGroups(account: ByteArray, local: String, peer: String,
                              peerCapabilities: Set<String>,
                              checkActive: () -> Unit) {
        val db = database.openHelper.readableDatabase
        val groups = db.query(SimpleSQLiteQuery(
            "SELECT groupId,groupSecretB64 FROM groups ORDER BY groupId"
        )).use { c -> buildList {
            while (c.moveToNext()) add(c.getString(0) to c.getString(1))
        } }
        for ((groupId, secret64) in groups) {
            checkActive()
            if (!groupId.matches(Regex("[0-9a-f]{64}"))) continue
            if (DelegatedGroupStateStore(database).isAdopted(groupId)) {
                if ("delegated_groups_v1" !in peerCapabilities) continue
                val identity = LocalDeviceIdentity.loadExisting(context)
                try {
                    require(identity.deviceId == local)
                    val delta = DelegatedGroupOwnHistory(database).export(
                        groupId, account, identity)
                    val id = delta.getString("group_snapshot_id")
                    val changedAt = db.query(SimpleSQLiteQuery(
                        "SELECT MAX(changed_at_ms) FROM device_sync_source_changes " +
                            "WHERE topic='groups' AND object_id=?",
                        arrayOf(groupId))).use { c ->
                        if (c.moveToFirst() && !c.isNull(0)) c.getLong(0) else 0L
                    }
                    if (!hasPending(peer, "groups", id))
                        queue(account, local, peer, "groups", id,
                            delta, maxOf(System.currentTimeMillis(), changedAt + 1))
                } finally { identity.close() }
                continue
            }
            val secret = runCatching { Base64.getDecoder().decode(secret64) }.getOrNull()
                ?: continue
            if (secret.size != 32 || Base64.getEncoder().encodeToString(secret) != secret64)
                continue
            val stream = ByteArrayOutputStream()
            db.query(SimpleSQLiteQuery("SELECT opBytes FROM crdt_op_log " +
                "WHERE groupId=? ORDER BY lamport,opId", arrayOf(groupId))).use { c ->
                var count = 0
                while (c.moveToNext()) {
                    val op = c.getBlob(0)
                    require(op.size in 1..66_560 && ++count <= 500_000 &&
                        stream.size() + 4L + op.size <= 23L * 1024 * 1024)
                    val size = op.size
                    stream.write(byteArrayOf((size ushr 24).toByte(),
                        (size ushr 16).toByte(), (size ushr 8).toByte(), size.toByte()))
                    stream.write(op)
                }
            }
            val packed = stream.toByteArray()
            if (packed.isEmpty() || !DeviceSyncGroupDelta.validFraming(packed) ||
                !RustBridge.crdtLoadGroup(groupId, packed)) continue
            val members = JSONArray(RustBridge.crdtQuery(groupId, "members", "{}"))
            val ownAccount = account.toHex()
            val authorizedMember = (0 until members.length()).any { index ->
                val member = members.getJSONObject(index)
                member.optString("pubkey_hex").lowercase() == ownAccount &&
                    !member.optBoolean("removed")
            }
            if (!authorizedMember) continue
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(packed).toHex()
            val id = "$groupId:$digest"
            if (hasPending(peer, "groups", id)) continue
            val delta = JSONObject().put("group_snapshot_id", id)
                .put("group_id", groupId)
                .put("packed_ops", Base64.getEncoder().encodeToString(packed))
                .put("group_secret", secret64)
            DeviceSyncGroupDelta.parse(delta, "groups", id)
            queue(account, local, peer, "groups", id, delta, System.currentTimeMillis())
            packed.fill(0)
            secret.fill(0)
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
