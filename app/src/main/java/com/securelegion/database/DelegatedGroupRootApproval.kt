package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.sync.DeviceGroupFrame
import org.json.JSONObject

/** Primary-only, local approval of accepted own-account historical hashes. */
internal class DelegatedGroupRootApproval(private val database: SecureLegionDatabase) {
    fun approveMissing(groupId: String, account: ByteArray,
                       identity: LocalDeviceIdentity, keys: KeyManager,
                       nowMs: Long = System.currentTimeMillis()): Int {
        require(account.size == 32 && keys.getSigningPublicKey()
            .contentEquals(account))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            require(DeviceRosterStore(database).isLocalAuthorized(account,
                identity.deviceId, 0x04, nowMs))
            val primary = db.query(SimpleSQLiteQuery("SELECT primaryDeviceId FROM " +
                "device_rosters WHERE accountEd=?", arrayOf(b64(account))))
                .use { cursor -> if (cursor.moveToFirst()) cursor.getString(0)
                    else null }
            if (primary != identity.deviceId) return 0
            val missing = DelegatedGroupStateStore(database)
                .missingHistoryAuthority(groupId, account, nowMs)[b64(account)]
                ?: return 0
            val seed = keys.getSigningKeyBytes()
            val proofs = ArrayList<ByteArray>()
            try {
                require(seed.size == 32)
                for (hash in missing.distinct().take(16)) {
                    val record = db.query(SimpleSQLiteQuery("SELECT l.opBytes FROM " +
                        "delegated_group_acceptance a JOIN crdt_op_log l " +
                        "ON l.opId=a.op_id AND l.groupId=a.group_id " +
                        "WHERE a.group_id=? AND a.operation_hash=? LIMIT 1",
                        arrayOf(groupId, hash))).use { cursor ->
                        if (cursor.moveToFirst()) cursor.getBlob(0) else null
                    } ?: continue
                    require(hash == hex(DeviceGroupFrame.hash(record)))
                    val descriptor = DeviceGroupProtocolBridge.execute(JSONObject()
                        .put("operation", "inspect")
                        .put("encoded", b64(record)))
                    require(descriptor.getString("hash") == hash &&
                        descriptor.getString("account_public") == b64(account))
                    proofs.add(DeviceGroupProtocolBridge.ratifyExact(record, hash, seed))
                }
            } finally { seed.fill(0) }
            if (proofs.isEmpty()) return 0
            try {
                DelegatedGroupStateStore(database).applyRatificationsInTransaction(
                    db, groupId, account, proofs, nowMs)
                db.execSQL("INSERT INTO device_sync_source_changes " +
                    "(topic,object_id,kind,changed_at_ms) " +
                    "VALUES ('groups',?,'upsert',?)", arrayOf(groupId, nowMs))
                db.setTransactionSuccessful()
                return proofs.size
            } finally { proofs.forEach { it.fill(0) } }
        } finally { db.endTransaction() }
    }

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 255)
    }
}
