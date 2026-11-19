package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.sync.DeviceGroupFrame
import org.json.JSONArray
import org.json.JSONObject

/** Private group_history_v:1 over authenticated own-account Nearby SYNC. */
internal class DelegatedGroupOwnHistory(private val database: SecureLegionDatabase) {
    private val states = DelegatedGroupStateStore(database)
    private val trust = DelegatedGroupRosterTrust(database)
    private val rosters = DeviceRosterStore(database)

    fun export(groupId: String, account: ByteArray, identity: LocalDeviceIdentity,
               nowMs: Long = System.currentTimeMillis()): JSONObject {
        require(rosters.isLocalAuthorized(account, identity.deviceId, 0x06, nowMs) &&
            states.isAdopted(groupId))
        val db = database.openHelper.readableDatabase
        val state = states.loadInTransaction(db, groupId, account, nowMs)
        try {
            val marker = db.query(SimpleSQLiteQuery("SELECT state_hash,op_count FROM " +
                "delegated_group_states WHERE group_id=?", arrayOf(groupId))).use { cursor ->
                if (cursor.moveToFirst()) Pair(cursor.getString(0), cursor.getInt(1)) else null
            } ?: throw IllegalStateException("Group is not adopted")
            val summary = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "read_state").put("state", state.context),
                groupKey = state.groupKey)
            require(marker.first == summary.getString("state_hash") &&
                marker.second == summary.getInt("op_count"))
            val certificate = db.query(SimpleSQLiteQuery("SELECT certificate FROM " +
                "authorized_devices WHERE accountEd=? AND deviceId=? AND isSelf=1",
                arrayOf(b64(account), identity.deviceId))).use { cursor ->
                if (cursor.moveToFirst()) cursor.getBlob(0) else null
            } ?: throw IllegalStateException("Local group certificate unavailable")
            val attestation = identity.withSyncKeys { seed, _ ->
                DeviceGroupProtocolBridge.execute(JSONObject()
                    .put("operation", "attest_history")
                    .put("state", state.context).put("certificate", b64(certificate)),
                    signingSeed = seed, groupKey = state.groupKey)
            }
            val packed = Base64.decode(state.context.getString("existing_local"),
                Base64.DEFAULT)
            try {
                require(packed.isNotEmpty() && packed.size <= 24 * 1024 * 1024)
                val delta = JSONObject().put("group_history_v", 1)
                    .put("group_snapshot_id", "$groupId:dg1:${hex(DeviceGroupFrame.hash(packed))}")
                    .put("group_id", groupId).put("packed_ops", b64(packed))
                    .put("group_secret", b64(state.groupKey))
                    .put("receipt", attestation.getString("receipt"))
                    .put("ratifications", state.context.getJSONArray("ratifications"))
                    .put("rosters", state.context.getJSONArray("rosters"))
                require(delta.toString().toByteArray(Charsets.UTF_8).size <=
                    32 * 1024 * 1024)
                return delta
            } finally { packed.fill(0) }
        } finally { state.groupKey.fill(0) }
    }

    fun applyInTransaction(db: SupportSQLiteDatabase, canonical: ByteArray,
                           part: DeviceSyncChunkStore.Part, account: ByteArray,
                           nowMs: Long): Boolean {
        require(db.inTransaction() && part.topic == "groups" &&
            rosters.isAuthorized(account, part.peerDeviceId, 0x06, nowMs))
        val delta = JSONObject(canonical.toString(Charsets.UTF_8))
        require(delta.keys().asSequence().toSet() == setOf("group_history_v",
            "group_snapshot_id", "group_id", "packed_ops", "group_secret",
            "receipt", "ratifications", "rosters") &&
            delta.getInt("group_history_v") == 1)
        val groupId = delta.getString("group_id")
        require(groupId.matches(Regex("[0-9a-f]{64}")))
        val packed = strictB64(delta.getString("packed_ops"), 24 * 1024 * 1024)
        val key = strictB64(delta.getString("group_secret"), 32)
        val receipt = strictB64(delta.getString("receipt"), 408)
        try {
            require(packed.isNotEmpty() && key.size == 32 && receipt.size == 408 &&
                part.objectId == "$groupId:dg1:${hex(DeviceGroupFrame.hash(packed))}" &&
                delta.getString("group_snapshot_id") == part.objectId)
            val proofArray = delta.getJSONArray("ratifications")
            val rosterArray = delta.getJSONArray("rosters")
            require(proofArray.length() <= 4096 && rosterArray.length() <= 128)
            val proofs = ArrayList<ByteArray>()
            val observed = ArrayList<ByteArray>()
            val newlyPinned = HashSet<String>()
            try {
                val proofIds = HashSet<String>()
                for (index in 0 until proofArray.length()) {
                    val proof = strictB64(proofArray.getString(index), 134)
                    require(proof.size == 134 &&
                        proofIds.add(hex(proof.copyOfRange(6, 38))))
                    proofs.add(proof)
                }
                val accounts = HashSet<String>()
                for (index in 0 until rosterArray.length()) {
                    val row = rosterArray.getJSONObject(index)
                    require(row.keys().asSequence().toSet() ==
                        setOf("account_public", "encoded"))
                    val principal = strictB64(row.getString("account_public"), 32)
                    val encoded = strictB64(row.getString("encoded"), 32 * 1024)
                    require(principal.size == 32 && encoded.isNotEmpty() &&
                        accounts.add(b64(principal)))
                    if (principal.contentEquals(account)) {
                        trust.observeOwn(account, encoded, nowMs)
                    } else {
                        if (trust.observeInTransaction(db, principal, encoded,
                                account, nowMs)) newlyPinned.add(hex(principal))
                        observed.add(principal)
                    }
                }
                val exists = db.query(SimpleSQLiteQuery("SELECT 1 FROM groups " +
                    "WHERE groupId=?", arrayOf(groupId))).use { it.moveToFirst() }
                val summary = if (exists) states.applyLiveInTransaction(db,
                    groupId, account, packed, proofs, observed,
                    historyReceipt = receipt, incomingKey = key, nowMs = nowMs)
                else states.applyFirstInviteInTransaction(db, groupId, account,
                    account, packed, key, receipt, proofs, observed,
                    ownHistory = true, nowMs = nowMs)
                val principals = HashSet<String>()
                val members = summary.getJSONArray("members")
                for (index in 0 until members.length())
                    principals.add(members.getJSONObject(index).getString("pubkey_hex"))
                val historical = HashSet<String>()
                val history = summary.getJSONArray("historical_principals")
                for (index in 0 until history.length()) historical.add(history.getString(index))
                for (principal in observed) {
                    val hex = hex(principal)
                    require(hex in principals || hex in historical)
                    if (hex !in principals && hex in newlyPinned)
                        db.execSQL("DELETE FROM delegated_group_trusted_rosters " +
                            "WHERE account_ed=?", arrayOf(b64(principal)))
                }
                db.execSQL("DELETE FROM device_sync_deletions WHERE topic='groups' " +
                    "AND object_id=?", arrayOf(groupId))
                val digest = hexBytes(part.digestHex)
                db.execSQL("INSERT OR REPLACE INTO device_sync_versions " +
                    "(peer_device_id,topic,object_id,event_time_ms,digest) " +
                    "VALUES (?,?,?,?,?)", arrayOf(part.peerDeviceId, "groups",
                        part.objectId, part.eventTimeMs, digest))
                db.execSQL("INSERT OR REPLACE INTO device_sync_local_events " +
                    "(topic,object_id,event_time_ms,digest,sequence,delta_json) " +
                    "VALUES (?,?,?,?,?,?)", arrayOf("groups", part.objectId,
                        part.eventTimeMs, digest, part.sequence, canonical))
                db.execSQL("INSERT INTO device_sync_cursors " +
                    "(peer_device_id,topic,pushed_seq,received_seq,updated_at_ms) " +
                    "VALUES (?,'groups',0,?,?) ON CONFLICT(peer_device_id,topic) " +
                    "DO UPDATE SET received_seq=MAX(received_seq,excluded.received_seq)," +
                    "updated_at_ms=excluded.updated_at_ms", arrayOf(part.peerDeviceId,
                        part.sequence, nowMs))
                return true
            } finally {
                proofs.forEach { it.fill(0) }
                observed.forEach { it.fill(0) }
            }
        } finally { packed.fill(0); key.fill(0); receipt.fill(0) }
    }

    private fun strictB64(value: String, max: Int): ByteArray {
        require(value.length <= ((max + 2) / 3) * 4)
        val bytes = Base64.decode(value, Base64.DEFAULT)
        require(bytes.size <= max && b64(bytes) == value)
        return bytes
    }
    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 255)
    }
    private fun hexBytes(value: String): ByteArray {
        require(value.matches(Regex("[0-9a-f]{64}")))
        return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
