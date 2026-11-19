package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceGroupFrame

/** Promotes an inbound C2 receipt only after exact own-account archive settlement. */
internal class DelegatedGroupAccountAck(private val database: SecureLegionDatabase) {
    data class Due(val id: String, val onion: String, val wire: ByteArray)

    private val rosters = DeviceRosterStore(database)
    private val trust = DelegatedGroupRosterTrust(database)

    fun due(account: ByteArray, identity: LocalDeviceIdentity,
            nowMs: Long = System.currentTimeMillis()): List<Due> {
        if (!rosters.isLocalAuthorized(account, identity.deviceId, 0x06, nowMs))
            return emptyList()
        val db = database.openHelper.writableDatabase
        val rows = db.query(SimpleSQLiteQuery("SELECT id,group_id,sender_account," +
            "sender_device,accepted_at_ms FROM delegated_group_inbound_receipts " +
            "WHERE local_device=? AND account_ack_sent_at_ms=0 " +
            "ORDER BY accepted_at_ms,id LIMIT 4", arrayOf(identity.deviceId))).use { c ->
            buildList {
                while (c.moveToNext()) add(Row(c.getString(0), c.getString(1),
                    c.getString(2), c.getString(3), c.getLong(4)))
            }
        }
        val result = ArrayList<Due>()
        for (row in rows) {
            db.beginTransaction()
            try {
                if (!rosters.isLocalAuthorized(account, identity.deviceId, 0x06, nowMs))
                    continue
                val current = db.query(SimpleSQLiteQuery("SELECT ack," +
                    "account_ack_sent_at_ms FROM delegated_group_inbound_receipts " +
                    "WHERE id=? AND local_device=?", arrayOf(row.id, identity.deviceId)))
                    .use { c -> if (c.moveToFirst()) c.getBlob(0) to c.getLong(1)
                        else null } ?: continue
                if (current.second != 0L) continue
                var ack = DeviceGroupFrame.parse(current.first)
                if (ack.kind == DeviceGroupFrame.Kind.DEVICE_STORAGE_ACK) {
                    if (!allInstallationsHaveHistory(db, account, identity.deviceId,
                            row.groupId, row.acceptedAtMs, nowMs)) continue
                    val signed = rosters.fetchSignedRoster(account) ?: continue
                    ack = DeviceGroupFrame.promoteCommittedAck(ack, account, identity,
                        signed, nowMs)
                    db.execSQL("UPDATE delegated_group_inbound_receipts SET ack=? " +
                        "WHERE id=? AND account_ack_sent_at_ms=0",
                        arrayOf(ack.wire, row.id))
                }
                if (ack.kind != DeviceGroupFrame.Kind.ACCOUNT_STORAGE_ACK ||
                    !ack.verify(identity.signingPublicKey, 0x06, nowMs)) continue
                val sender = hexBytes(row.senderAccount)
                if (!ack.recipientAccount.contentEquals(sender) ||
                    ack.recipientDeviceId != row.senderDevice) continue
                val endpoint = trust.endpointForInTransaction(db, sender,
                    row.senderDevice, nowMs) ?: continue
                result.add(Due(row.id, endpoint.onion, ack.wire))
                db.setTransactionSuccessful()
            } finally { db.endTransaction() }
        }
        return result
    }

    fun markSent(id: String, nowMs: Long = System.currentTimeMillis()) {
        database.openHelper.writableDatabase.execSQL("UPDATE " +
            "delegated_group_inbound_receipts SET account_ack_sent_at_ms=? " +
            "WHERE id=? AND account_ack_sent_at_ms=0",
            arrayOf(nowMs, id))
    }

    private fun allInstallationsHaveHistory(db: SupportSQLiteDatabase,
            account: ByteArray, local: String, group: String,
            acceptedAtMs: Long, nowMs: Long): Boolean {
        val peers = db.query(SimpleSQLiteQuery("SELECT deviceId,capabilities " +
            "FROM authorized_devices WHERE accountEd=? AND expiresAtMs>? " +
            "AND issuedAtMs<=? AND deviceId<>?",
            arrayOf(b64(account), nowMs, nowMs, local))).use { c ->
            buildList { while (c.moveToNext()) add(c.getString(0) to c.getInt(1)) }
        }
        if (peers.isEmpty()) return true
        if (peers.any { it.second and 0x06 != 0x06 }) return false
        val snapshots = db.query(SimpleSQLiteQuery("SELECT object_id,event_time_ms," +
            "digest,delta_json FROM device_sync_local_events WHERE topic='groups' " +
            "AND object_id LIKE ? AND event_time_ms>? " +
            "ORDER BY event_time_ms DESC LIMIT 32",
            arrayOf("$group:dg1:%", acceptedAtMs))).use { c ->
            buildList { while (c.moveToNext()) add(Snapshot(c.getString(0),
                c.getLong(1), c.getBlob(2), c.getBlob(3))) }
        }
        for (snapshot in snapshots) {
            val identity = RustBridge.deviceHistoryIdentity(snapshot.delta,
                "groups", snapshot.id, snapshot.time)
            try {
                if (identity.size < 66 || !snapshot.digest.contentEquals(
                        identity.copyOfRange(0, 32))) continue
                val eventId = hex(identity.copyOfRange(32, 64))
                if (peers.all { (peer, _) ->
                    db.query(SimpleSQLiteQuery("SELECT 1 FROM device_sync_acks " +
                        "WHERE peer_device_id=? AND topic='groups' AND object_id=? " +
                        "AND event_id=? AND event_time_ms=? AND digest=?",
                        arrayOf(peer, snapshot.id, eventId, snapshot.time,
                            snapshot.digest))).use { it.moveToFirst() }
                }) return true
            } finally { identity.fill(0) }
        }
        return false
    }

    private data class Row(val id: String, val groupId: String,
        val senderAccount: String, val senderDevice: String,
        val acceptedAtMs: Long)
    private data class Snapshot(val id: String, val time: Long,
        val digest: ByteArray, val delta: ByteArray)
    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 255)
    }
    private fun hexBytes(value: String): ByteArray {
        require(value.matches(Regex("[0-9a-f]{64}")))
        return ByteArray(32) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
