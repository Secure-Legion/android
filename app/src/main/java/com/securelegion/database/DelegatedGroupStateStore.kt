package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.sync.DeviceGroupFrame
import org.json.JSONArray
import org.json.JSONObject

/** Builds native mixed-history input from committed SQLCipher rows only. */
internal class DelegatedGroupStateStore(private val database: SecureLegionDatabase) {
    data class State(val context: JSONObject, val groupKey: ByteArray,
                     val committedCount: Int)

    fun read(groupId: String, account: ByteArray,
             nowMs: Long = System.currentTimeMillis()): JSONObject {
        val db = database.openHelper.readableDatabase
        val state = loadInTransaction(db, groupId, account, nowMs)
        try {
            val result = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "read_state").put("state", state.context),
                groupKey = state.groupKey)
            val marker = db.query(SimpleSQLiteQuery("SELECT state_hash,op_count " +
                "FROM delegated_group_states WHERE group_id=?", arrayOf(groupId)))
                .use { cursor -> if (cursor.moveToFirst()) Pair(cursor.getString(0),
                    cursor.getInt(1)) else null }
            if (marker != null) require(marker.first == result.getString("state_hash") &&
                marker.second == result.getInt("op_count")) {
                "Delegated group state hash mismatch"
            }
            return result.apply { remove("group_secret"); remove("keyring") }
        } finally { state.groupKey.fill(0) }
    }

    fun loadInTransaction(db: SupportSQLiteDatabase, groupId: String,
                          account: ByteArray, nowMs: Long): State {
        require(groupId.matches(Regex("[0-9a-f]{64}")) && account.size == 32 &&
            nowMs in 1..9_007_199_254_740_991L)
        val key = db.query(SimpleSQLiteQuery("SELECT groupSecretB64 FROM groups " +
            "WHERE groupId=?", arrayOf(groupId))).use { cursor ->
            require(cursor.moveToFirst()) { "Missing group" }
            Base64.decode(cursor.getString(0), Base64.DEFAULT)
        }
        require(key.size == 32)
        try {
            val operations = ArrayList<ByteArray>()
            var packedLength = 0
            db.query(SimpleSQLiteQuery("SELECT l.opId,l.opBytes,a.operation_hash " +
                "FROM crdt_op_log l LEFT JOIN delegated_group_acceptance a " +
                "ON a.op_id=l.opId WHERE l.groupId=? ORDER BY l.lamport,l.opId",
                arrayOf(groupId))).use { cursor ->
                while (cursor.moveToNext()) {
                    require(operations.size < 500_000)
                    val op = cursor.getBlob(1)
                    require(op.size in 1..69_632 && packedLength + 4L + op.size <=
                        24L * 1024 * 1024)
                    val delegated = op.size >= 6 &&
                        (op.copyOfRange(0, 6).contentEquals("SLGO01".toByteArray()) ||
                            op.copyOfRange(0, 6).contentEquals("SLGE01".toByteArray()))
                    val receipt = if (cursor.isNull(2)) null else cursor.getString(2)
                    require((!delegated || receipt != null) &&
                        (receipt == null || receipt == hex(DeviceGroupFrame.hash(op)))) {
                        "Unaccepted delegated group operation"
                    }
                    packedLength += 4 + op.size
                    operations.add(op)
                }
            }
            val packed = ByteArray(packedLength)
            try {
                var at = 0
                for (op in operations) {
                    for (i in 0..3) packed[at + i] =
                        (op.size ushr (24 - 8 * i)).toByte()
                    at += 4
                    op.copyInto(packed, at)
                    at += op.size
                }
                val rosterAccounts = HashSet<String>()
                rosterAccounts.add(b64(account))
                db.query(SimpleSQLiteQuery("SELECT pubkeyHex FROM group_peers WHERE groupId=?",
                    arrayOf(groupId))).use { cursor ->
                    while (cursor.moveToNext()) {
                        val hex = cursor.getString(0)
                        if (hex.matches(Regex("[0-9a-fA-F]{64}")))
                            rosterAccounts.add(b64(hex.chunked(2).map { it.toInt(16).toByte() }
                                .toByteArray()))
                    }
                }
                require(rosterAccounts.size <= 128)
                val rosters = JSONArray()
                for (identity in rosterAccounts.sorted()) {
                    db.query(SimpleSQLiteQuery("SELECT signedRoster FROM device_rosters " +
                        "WHERE accountEd=?", arrayOf(identity))).use { cursor ->
                        if (cursor.moveToFirst()) rosters.put(JSONObject()
                            .put("account_public", identity)
                            .put("encoded", b64(cursor.getBlob(0))))
                    }
                }
                val ratifications = JSONArray()
                db.query(SimpleSQLiteQuery("SELECT proof FROM delegated_group_ratifications " +
                    "WHERE group_id=? ORDER BY operation_hash", arrayOf(groupId)))
                    .use { cursor ->
                        while (cursor.moveToNext()) {
                            require(ratifications.length() < 4096)
                            ratifications.put(b64(cursor.getBlob(0)))
                        }
                    }
                val state = JSONObject().put("group_id", groupId)
                    .put("account_public", b64(account))
                    .put("existing_local", b64(packed))
                    .put("rosters", rosters)
                    .put("ratifications", ratifications)
                    .put("now_ms", nowMs)
                return State(state, key, operations.size)
            } finally {
                packed.fill(0)
                operations.forEach { it.fill(0) }
            }
        } catch (error: Exception) {
            key.fill(0)
            throw IllegalStateException("Delegated group state unavailable")
        }
    }

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
