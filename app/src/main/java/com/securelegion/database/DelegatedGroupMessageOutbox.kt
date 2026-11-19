package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import org.json.JSONObject
import java.security.SecureRandom

/** Durable, installation owned Pending text. No transport sends these rows. */
internal class DelegatedGroupMessageOutbox(private val database: SecureLegionDatabase) {
    data class Pending(val id: String, val groupId: String, val text: String,
                       val createdAtMs: Long)

    fun enqueue(groupId: String, account: ByteArray, localDeviceId: String,
                text: String, nowMs: Long = System.currentTimeMillis()): Pending {
        val normalized = text.trim()
        val utf8 = normalized.toByteArray(Charsets.UTF_8)
        require(groupId.matches(Regex("[0-9a-f]{64}")) && account.size == 32 &&
            localDeviceId.matches(Regex("[A-Za-z0-9_-]{43}")) &&
            utf8.size in 1..MAX_TEXT_BYTES && nowMs > 0)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            requireAuthorized(db, account, localDeviceId, nowMs)
            val state = DelegatedGroupStateStore(database)
                .loadInTransaction(db, groupId, account, nowMs)
            try {
                val summary = DeviceGroupProtocolBridge.execute(JSONObject()
                    .put("operation", "read_state").put("state", state.context),
                    groupKey = state.groupKey)
                require(!summary.optBoolean("deleted") &&
                    !summary.optBoolean("pending_invite") &&
                    !summary.optBoolean("needs_rekey") &&
                    summary.optString("our_role") in setOf("Owner", "Admin", "Member")) {
                    "Group cannot send"
                }
                if (summary.optString("our_role") == "Member") {
                    val metadata = summary.getJSONArray("metadata")
                    for (index in 0 until metadata.length()) {
                        val entry = metadata.getJSONObject(index)
                        if (entry.optString("key") == "AllowMemberSendMessages") {
                            val value = Base64.decode(entry.getString("value"), Base64.DEFAULT)
                            require(value.size == 1 && value[0] == 1.toByte()) {
                                "Member sending disabled"
                            }
                        }
                    }
                }
            } finally { state.groupKey.fill(0) }
            val capacity = db.query("SELECT count(*), " +
                "COALESCE(sum(length(CAST(text AS BLOB))),0) " +
                "FROM delegated_group_message_outbox").use { cursor ->
                cursor.moveToFirst()
                Pair(cursor.getInt(0), cursor.getLong(1))
            }
            require(capacity.first < MAX_PENDING &&
                capacity.second + utf8.size <= MAX_PENDING_BYTES)
            val pending = Pending("pending_" + ByteArray(32).also {
                SecureRandom().nextBytes(it)
            }.joinToString("") { "%02x".format(it.toInt() and 0xff) }, groupId,
                normalized, nowMs)
            db.execSQL("INSERT INTO delegated_group_message_outbox " +
                "(id,group_id,local_device,text,created_at_ms,next_try_at_ms) " +
                "VALUES (?,?,?,?,?,0)", arrayOf(pending.id, groupId, localDeviceId,
                    normalized, nowMs))
            db.setTransactionSuccessful()
            return pending
        } catch (error: Exception) {
            throw IllegalStateException("Group message cannot be queued")
        } finally {
            utf8.fill(0)
            db.endTransaction()
        }
    }

    /** Cancellation succeeds only while the original intent still exists. */
    fun cancel(id: String, account: ByteArray, localDeviceId: String,
               nowMs: Long = System.currentTimeMillis()): Boolean {
        require(id.matches(Regex("pending_[0-9a-f]{64}")) &&
            account.size == 32 && localDeviceId.length == 43)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            requireAuthorized(db, account, localDeviceId, nowMs)
            val exists = db.query(SimpleSQLiteQuery("SELECT 1 FROM " +
                "delegated_group_message_outbox WHERE id=? AND local_device=?",
                arrayOf(id, localDeviceId))).use { it.moveToFirst() }
            if (exists) db.execSQL("DELETE FROM delegated_group_message_outbox " +
                "WHERE id=? AND local_device=?", arrayOf(id, localDeviceId))
            db.setTransactionSuccessful()
            return exists
        } finally { db.endTransaction() }
    }

    fun due(account: ByteArray, localDeviceId: String,
            nowMs: Long = System.currentTimeMillis()): List<Pending> {
        require(account.size == 32 && localDeviceId.length == 43)
        requireAuthorized(database.openHelper.readableDatabase,
            account, localDeviceId, nowMs)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT id,group_id,text,created_at_ms FROM " +
                "delegated_group_message_outbox WHERE local_device=? AND " +
                "next_try_at_ms<=? ORDER BY created_at_ms,id LIMIT 32",
            arrayOf(localDeviceId, nowMs))).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(Pending(cursor.getString(0),
                    cursor.getString(1), cursor.getString(2), cursor.getLong(3)))
            }
        }
    }

    /** Promote one Pending intent and its delivery ownership in one SQLCipher commit. */
    fun convert(id: String, account: ByteArray, identity: LocalDeviceIdentity,
                nowMs: Long = System.currentTimeMillis()): String {
        require(id.matches(Regex("pending_[0-9a-f]{64}")) && account.size == 32)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            requireAuthorized(db, account, identity.deviceId, nowMs)
            val pending = db.query(SimpleSQLiteQuery("SELECT group_id,text FROM " +
                "delegated_group_message_outbox WHERE id=? AND local_device=?",
                arrayOf(id, identity.deviceId))).use { cursor ->
                if (cursor.moveToFirst()) Pair(cursor.getString(0), cursor.getString(1))
                else null
            } ?: throw IllegalArgumentException("Pending message unavailable")
            val stateStore = DelegatedGroupStateStore(database)
            val state = stateStore.loadInTransaction(db, pending.first, account, nowMs)
            try {
                val marker = db.query(SimpleSQLiteQuery("SELECT state_hash,op_count FROM " +
                    "delegated_group_states WHERE group_id=?", arrayOf(pending.first)))
                    .use { cursor -> if (cursor.moveToFirst()) Pair(cursor.getString(0),
                        cursor.getInt(1)) else null }
                    ?: throw IllegalStateException("Group is not adopted")
                val current = DeviceGroupProtocolBridge.execute(JSONObject()
                    .put("operation", "read_state").put("state", state.context),
                    groupKey = state.groupKey)
                require(marker.first == current.getString("state_hash") &&
                    marker.second == current.getInt("op_count") &&
                    !current.getBoolean("deleted") &&
                    !current.getBoolean("pending_invite") &&
                    !current.getBoolean("needs_rekey") &&
                    current.getString("our_role") in setOf("Owner", "Admin", "Member"))
                val certificate = db.query(SimpleSQLiteQuery("SELECT certificate FROM " +
                    "authorized_devices WHERE accountEd=? AND deviceId=? AND isSelf=1",
                    arrayOf(Base64.encodeToString(account, Base64.NO_WRAP),
                        identity.deviceId))).use { cursor ->
                    if (cursor.moveToFirst()) cursor.getBlob(0) else null
                } ?: throw IllegalStateException("Local group certificate unavailable")
                val nonce = ByteArray(24).also(SecureRandom()::nextBytes)
                val plain = pending.second.toByteArray(Charsets.UTF_8)
                val ciphertext = try {
                    RustBridge.xchacha20Encrypt(plain, state.groupKey, nonce)
                } finally { plain.fill(0) }
                try {
                    val request = JSONObject().put("operation", "create_operation")
                        .put("state", state.context)
                        .put("certificate", Base64.encodeToString(certificate,
                            Base64.NO_WRAP))
                        .put("mutation", JSONObject().put("kind", "msg_add")
                            .put("ciphertext", Base64.encodeToString(ciphertext,
                                Base64.NO_WRAP))
                            .put("nonce", Base64.encodeToString(nonce, Base64.NO_WRAP)))
                    val created = identity.withSyncKeys { seed, _ ->
                        DeviceGroupProtocolBridge.execute(request, signingSeed = seed,
                            groupKey = state.groupKey)
                    }
                    val encoded = Base64.decode(created.getString("encoded"), Base64.DEFAULT)
                    try {
                        require(encoded.size in 1..69_632)
                        val packed = ByteArray(4 + encoded.size)
                        packed[0] = (encoded.size ushr 24).toByte()
                        packed[1] = (encoded.size ushr 16).toByte()
                        packed[2] = (encoded.size ushr 8).toByte()
                        packed[3] = encoded.size.toByte()
                        encoded.copyInto(packed, 4)
                        try {
                            val summary = stateStore.applyLiveInTransaction(db, pending.first,
                                account, packed, nowMs = nowMs)
                            val opId = created.getJSONObject("descriptor").getString("op_id")
                            val local = Base64.encodeToString(account, Base64.NO_WRAP)
                            db.execSQL("INSERT INTO delegated_group_origins " +
                                "(op_id,group_id,local_device,created_at_ms) VALUES (?,?,?,?)",
                                arrayOf(opId, pending.first, identity.deviceId, nowMs))
                            val members = summary.getJSONArray("members")
                            for (index in 0 until members.length()) {
                                val member = members.getJSONObject(index)
                                if (!member.getBoolean("accepted") ||
                                    member.getBoolean("removed") ||
                                    member.getBoolean("banned")) continue
                                val target = Base64.encodeToString(
                                    member.getString("pubkey_hex").chunked(2)
                                        .map { it.toInt(16).toByte() }.toByteArray(),
                                    Base64.NO_WRAP)
                                if (target != local) db.execSQL("INSERT INTO " +
                                    "delegated_group_targets (op_id,target_account,mode) " +
                                    "VALUES (?,?,'live')", arrayOf(opId, target))
                            }
                            db.execSQL("DELETE FROM delegated_group_message_outbox " +
                                "WHERE id=? AND local_device=?",
                                arrayOf(id, identity.deviceId))
                            db.execSQL("INSERT INTO device_sync_source_changes " +
                                "(topic,object_id,kind,changed_at_ms) " +
                                "VALUES ('groups',?,'upsert',?)",
                                arrayOf(pending.first, nowMs))
                            db.setTransactionSuccessful()
                            return opId
                        } finally { packed.fill(0) }
                    } finally { encoded.fill(0) }
                } finally { ciphertext.fill(0); nonce.fill(0) }
            } finally { state.groupKey.fill(0) }
        } finally { db.endTransaction() }
    }

    private fun requireAuthorized(db: SupportSQLiteDatabase, account: ByteArray,
                                  localDeviceId: String, nowMs: Long) {
        val accountB64 = Base64.encodeToString(account, Base64.NO_WRAP)
        val authorized = db.query(SimpleSQLiteQuery("SELECT 1 FROM authorized_devices " +
            "WHERE accountEd=? AND deviceId=? AND isSelf=1 AND " +
            "(capabilities & 4)=4 AND issuedAtMs<=? AND expiresAtMs>? LIMIT 1",
            arrayOf(accountB64, localDeviceId, nowMs, nowMs))).use { it.moveToFirst() }
        require(authorized) { "Local group certificate unavailable" }
    }

    companion object {
        private const val MAX_TEXT_BYTES = 30 * 1024
        private const val MAX_PENDING = 256
        private const val MAX_PENDING_BYTES = 8L * 1024 * 1024
    }
}
