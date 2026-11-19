package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.crypto.RustBridge
import com.securelegion.crypto.LocalDeviceIdentity
import java.security.SecureRandom
import com.securelegion.sync.DeviceGroupFrame
import org.json.JSONArray
import org.json.JSONObject

/** Builds native mixed-history input from committed SQLCipher rows only. */
internal class DelegatedGroupStateStore(private val database: SecureLegionDatabase) {
    data class State(val context: JSONObject, val groupKey: ByteArray,
                     val committedCount: Int)
    data class DisplayMessage(val id: String, val author: String,
                              val timestampMs: Long, val text: String,
                              val deleted: Boolean, val pendingDelivery: Boolean)
    data class DisplayState(val summary: JSONObject, val messages: List<DisplayMessage>)

    fun createGroup(name: String, account: ByteArray,
                    identity: LocalDeviceIdentity,
                    nowMs: Long = System.currentTimeMillis()): String {
        val title = name.trim()
        require(title.isNotEmpty() && title.length <= 256 &&
            title.none { it.isISOControl() } && account.size == 32)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            require(DeviceRosterStore(database).isLocalAuthorized(account,
                identity.deviceId, 0x04, nowMs))
            val ownRoster = DeviceRosterStore(database).fetchSignedRoster(account)
                ?: throw IllegalStateException("Local group roster unavailable")
            val certificate = db.query(SimpleSQLiteQuery("SELECT certificate FROM " +
                "authorized_devices WHERE accountEd=? AND deviceId=? AND isSelf=1",
                arrayOf(b64(account), identity.deviceId))).use { cursor ->
                if (cursor.moveToFirst()) cursor.getBlob(0) else null
            } ?: throw IllegalStateException("Local group certificate unavailable")
            val random = SecureRandom()
            var groupId: String
            do {
                groupId = hex(ByteArray(32).also(random::nextBytes))
            } while (db.query(SimpleSQLiteQuery("SELECT 1 FROM groups WHERE groupId=?",
                arrayOf(groupId))).use { it.moveToFirst() })
            val key = ByteArray(32).also(random::nextBytes)
            try {
                val context = JSONObject().put("group_id", groupId)
                    .put("account_public", b64(account))
                    .put("existing_local", b64(ByteArray(0)))
                    .put("rosters", JSONArray().put(JSONObject()
                        .put("account_public", b64(account))
                        .put("encoded", b64(ownRoster))))
                    .put("ratifications", JSONArray()).put("now_ms", nowMs)
                val created = identity.withSyncKeys { seed, _ ->
                    DeviceGroupProtocolBridge.execute(JSONObject()
                        .put("operation", "create_operation")
                        .put("state", context).put("certificate", b64(certificate))
                        .put("mutation", JSONObject().put("kind", "group_create")
                            .put("name", title)), signingSeed = seed, groupKey = key)
                }
                val info = created.getJSONObject("descriptor")
                val summary = created.getJSONObject("summary")
                val encoded = Base64.decode(created.getString("encoded"), Base64.DEFAULT)
                val selected = Base64.decode(summary.getString("group_secret"),
                    Base64.DEFAULT)
                try {
                    require(encoded.size in 1..69_632 && selected.size == 32 &&
                        selected.contentEquals(key) &&
                        info.getString("group_id") == groupId &&
                        info.getString("op_type") == "GroupCreate" &&
                        info.getString("hash") == hex(DeviceGroupFrame.hash(encoded)))
                    db.execSQL("INSERT INTO groups (groupId,name,groupSecretB64,createdAt," +
                        "lastActivityTimestamp,isMuted,memberCount,isPendingInvite,isPinned," +
                        "unreadCount) VALUES (?,?,?,?,?,0,1,0,0,0)",
                        arrayOf(groupId, title.take(32), b64(selected), nowMs, nowMs))
                    db.execSQL("INSERT INTO crdt_op_log " +
                        "(opId,groupId,opType,opBytes,lamport,createdAt) " +
                        "VALUES (?,?,?,?,?,?)", arrayOf(info.getString("op_id"), groupId,
                            "GroupCreate", encoded, info.getLong("lamport"), nowMs))
                    db.execSQL("INSERT INTO delegated_group_acceptance " +
                        "(op_id,group_id,operation_hash,accepted_at_ms) " +
                        "VALUES (?,?,?,?)", arrayOf(info.getString("op_id"), groupId,
                            info.getString("hash"), nowMs))
                    val keyring = summary.getJSONArray("keyring")
                    var currentFound = false
                    for (index in 0 until keyring.length()) {
                        val row = keyring.getJSONObject(index)
                        val epoch = row.getString("epoch")
                        val secret = Base64.decode(row.getString("key"), Base64.DEFAULT)
                        require(epoch.matches(Regex("[0-9a-f]{64}")) && secret.size == 32)
                        try {
                            if (epoch == summary.getString("current_epoch")) {
                                require(row.getBoolean("eligible") &&
                                    secret.contentEquals(selected))
                                currentFound = true
                            }
                            db.execSQL("INSERT INTO delegated_group_keys " +
                                "(group_id,epoch,secret,eligible) VALUES (?,?,?,?)",
                                arrayOf(groupId, epoch, secret,
                                    if (row.getBoolean("eligible")) 1 else 0))
                        } finally { secret.fill(0) }
                    }
                    require(currentFound)
                    db.execSQL("INSERT INTO delegated_group_principals " +
                        "(group_id,account_ed) VALUES (?,?)",
                        arrayOf(groupId, b64(account)))
                    db.execSQL("INSERT INTO delegated_group_states " +
                        "(group_id,state_hash,op_count,updated_at_ms) VALUES (?,?,?,?)",
                        arrayOf(groupId, summary.getString("state_hash"),
                            summary.getInt("op_count"), nowMs))
                    db.setTransactionSuccessful()
                    return groupId
                } finally { encoded.fill(0); selected.fill(0) }
            } finally { key.fill(0) }
        } finally { db.endTransaction() }
    }

    fun acceptInvite(groupId: String, account: ByteArray,
                     identity: LocalDeviceIdentity,
                     nowMs: Long = System.currentTimeMillis()): Boolean {
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            require(DeviceRosterStore(database).isLocalAuthorized(account,
                identity.deviceId, 0x04, nowMs))
            val state = loadInTransaction(db, groupId, account, nowMs)
            try {
                val current = DeviceGroupProtocolBridge.execute(JSONObject()
                    .put("operation", "read_state").put("state", state.context),
                    groupKey = state.groupKey)
                if (!current.getBoolean("pending_invite")) return false
                val certificate = db.query(SimpleSQLiteQuery("SELECT certificate FROM " +
                    "authorized_devices WHERE accountEd=? AND deviceId=? AND isSelf=1",
                    arrayOf(b64(account), identity.deviceId))).use { cursor ->
                    if (cursor.moveToFirst()) cursor.getBlob(0) else null
                } ?: throw IllegalStateException("Local group certificate unavailable")
                val created = identity.withSyncKeys { seed, _ ->
                    DeviceGroupProtocolBridge.execute(JSONObject()
                        .put("operation", "create_operation")
                        .put("state", state.context).put("certificate", b64(certificate))
                        .put("mutation", JSONObject().put("kind", "member_accept")
                            .put("invite_op_id", current.getString("invite_op_id"))),
                        signingSeed = seed, groupKey = state.groupKey)
                }
                if (created.optBoolean("unchanged")) return false
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
                        val summary = applyLiveInTransaction(db, groupId, account,
                            packed, nowMs = nowMs)
                        val opId = created.getJSONObject("descriptor").getString("op_id")
                        db.execSQL("INSERT INTO delegated_group_origins " +
                            "(op_id,group_id,local_device,created_at_ms) VALUES (?,?,?,?)",
                            arrayOf(opId, groupId, identity.deviceId, nowMs))
                        val members = summary.getJSONArray("members")
                        for (index in 0 until members.length()) {
                            val member = members.getJSONObject(index)
                            if (!member.getBoolean("accepted") ||
                                member.getBoolean("removed") ||
                                member.getBoolean("banned")) continue
                            val target = b64(hexBytes(member.getString("pubkey_hex")))
                            if (target != b64(account)) db.execSQL("INSERT INTO " +
                                "delegated_group_targets (op_id,target_account,mode) " +
                                "VALUES (?,?,'live')", arrayOf(opId, target))
                        }
                        db.execSQL("INSERT INTO device_sync_source_changes " +
                            "(topic,object_id,kind,changed_at_ms) " +
                            "VALUES ('groups',?,'upsert',?)",
                            arrayOf(groupId, nowMs))
                        db.setTransactionSuccessful()
                        return true
                    } finally { packed.fill(0) }
                } finally { encoded.fill(0) }
            } finally { state.groupKey.fill(0) }
        } finally { db.endTransaction() }
    }

    fun inviteMember(groupId: String, account: ByteArray,
                     invited: ByteArray, identity: LocalDeviceIdentity,
                     nowMs: Long = System.currentTimeMillis()): String {
        require(invited.size == 32 && !invited.contentEquals(account))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            require(DeviceRosterStore(database).isLocalAuthorized(account,
                identity.deviceId, 0x04, nowMs))
            val state = loadInTransaction(db, groupId, account, nowMs)
            try {
                val certificate = db.query(SimpleSQLiteQuery("SELECT certificate FROM " +
                    "authorized_devices WHERE accountEd=? AND deviceId=? AND isSelf=1",
                    arrayOf(b64(account), identity.deviceId))).use { cursor ->
                    if (cursor.moveToFirst()) cursor.getBlob(0) else null
                } ?: throw IllegalStateException("Local group certificate unavailable")
                val created = identity.withSyncKeys { seed, _ ->
                    DeviceGroupProtocolBridge.execute(JSONObject()
                        .put("operation", "create_operation")
                        .put("state", state.context).put("certificate", b64(certificate))
                        .put("mutation", JSONObject().put("kind", "member_invite")
                            .put("account_public", b64(invited)).put("role", "Member")),
                        signingSeed = seed, groupKey = state.groupKey)
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
                        val summary = applyLiveInTransaction(db, groupId, account,
                            packed, nowMs = nowMs)
                        val opId = created.getJSONObject("descriptor").getString("op_id")
                        db.execSQL("INSERT INTO delegated_group_origins " +
                            "(op_id,group_id,local_device,created_at_ms) VALUES (?,?,?,?)",
                            arrayOf(opId, groupId, identity.deviceId, nowMs))
                        val members = summary.getJSONArray("members")
                        for (index in 0 until members.length()) {
                            val member = members.getJSONObject(index)
                            if (member.getBoolean("removed") ||
                                member.getBoolean("banned")) continue
                            val target = b64(hexBytes(member.getString("pubkey_hex")))
                            if (target == b64(account)) continue
                            val mode = if (target == b64(invited)) "invite" else "live"
                            if (mode == "live" && !member.getBoolean("accepted")) continue
                            db.execSQL("INSERT INTO delegated_group_targets " +
                                "(op_id,target_account,mode) VALUES (?,?,?)",
                                arrayOf(opId, target, mode))
                        }
                        db.execSQL("INSERT INTO device_sync_source_changes " +
                            "(topic,object_id,kind,changed_at_ms) " +
                            "VALUES ('groups',?,'upsert',?)", arrayOf(groupId, nowMs))
                        db.setTransactionSuccessful()
                        return opId
                    } finally { packed.fill(0) }
                } finally { encoded.fill(0) }
            } finally { state.groupKey.fill(0) }
        } finally { db.endTransaction() }
    }

    fun isAdopted(groupId: String): Boolean = database.openHelper.readableDatabase
        .query(SimpleSQLiteQuery("SELECT 1 FROM delegated_group_states WHERE group_id=?",
            arrayOf(groupId))).use { it.moveToFirst() }

    fun display(groupId: String, account: ByteArray,
                nowMs: Long = System.currentTimeMillis()): DisplayState {
        val db = database.openHelper.readableDatabase
        val state = loadInTransaction(db, groupId, account, nowMs)
        try {
            val summary = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "read_state").put("state", state.context),
                groupKey = state.groupKey)
            val marker = db.query(SimpleSQLiteQuery("SELECT state_hash,op_count FROM " +
                "delegated_group_states WHERE group_id=?", arrayOf(groupId))).use { cursor ->
                if (cursor.moveToFirst()) Pair(cursor.getString(0), cursor.getInt(1)) else null
            } ?: throw IllegalStateException("Group is not adopted")
            require(marker.first == summary.getString("state_hash") &&
                marker.second == summary.getInt("op_count"))
            val messages = ArrayList<DisplayMessage>()
            val page = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "read_messages").put("state", state.context)
                .put("after", JSONObject.NULL).put("limit", 100)
                .put("include_local_dispositions", true).put("recent", true),
                groupKey = state.groupKey)
            val rows = page.getJSONArray("messages")
            for (index in 0 until rows.length()) {
                    val row = rows.getJSONObject(index)
                    val epoch = row.optString("cipher_epoch")
                    val key = if (epoch.isNotEmpty() && epoch != "null")
                        db.query(SimpleSQLiteQuery("SELECT secret FROM delegated_group_keys " +
                            "WHERE group_id=? AND epoch=?", arrayOf(groupId, epoch)))
                            .use { cursor -> if (cursor.moveToFirst()) cursor.getBlob(0)
                                else null } else state.groupKey.copyOf()
                    val deleted = row.getBoolean("deleted")
                    val text = try {
                        if (deleted) "Message deleted" else if (key == null) "[Encrypted]"
                        else runCatching {
                            val cipher = Base64.decode(row.getString("ciphertext_b64"),
                                Base64.DEFAULT)
                            val nonce = Base64.decode(row.getString("nonce_b64"),
                                Base64.DEFAULT)
                            if (nonce.size != 24) "[Encrypted]" else
                                RustBridge.xchacha20Decrypt(cipher, key, nonce)
                                    ?.toString(Charsets.UTF_8) ?: "[Encrypted]"
                        }.getOrDefault("[Encrypted]")
                    } finally { key?.fill(0) }
                    messages.add(DisplayMessage(row.getString("msg_id"),
                        row.getString("author"), row.getLong("timestamp_ms"), text,
                        deleted, row.optString("local_disposition") == "not_delivered"))
            }
            return DisplayState(summary, messages)
        } finally { state.groupKey.fill(0) }
    }

    /** Preview and publish a live C2 delta inside the caller's receipt transaction. */
    fun applyLiveInTransaction(db: SupportSQLiteDatabase, groupId: String,
                               account: ByteArray, incoming: ByteArray,
                               ratifications: List<ByteArray> = emptyList(),
                               observedAccounts: List<ByteArray> = emptyList(),
                               historyReceipt: ByteArray? = null,
                               incomingKey: ByteArray? = null,
                               foreignSource: ByteArray? = null,
                               nowMs: Long = System.currentTimeMillis()): JSONObject {
        require(db.inTransaction() && incoming.size in 5..24 * 1024 * 1024 &&
            ratifications.size <= 4096 && ratifications.all { it.size == 134 } &&
            observedAccounts.size <= 128 && observedAccounts.all { it.size == 32 } &&
            (historyReceipt == null && incomingKey == null ||
                historyReceipt?.size == 408 && incomingKey?.size == 32) &&
            (foreignSource == null || foreignSource.size == 32 &&
                historyReceipt != null && !foreignSource.contentEquals(account)))
        val historical = historyReceipt != null
        val records = unpack(incoming, if (historical) 500_000 else 1_000)
        require(records.isNotEmpty())
        val state = loadInTransaction(db, groupId, account, nowMs, observedAccounts)
        try {
            val oldMarker = db.query(SimpleSQLiteQuery(
                "SELECT state_hash,op_count FROM delegated_group_states WHERE group_id=?",
                arrayOf(groupId))).use { cursor ->
                if (cursor.moveToFirst()) Pair(cursor.getString(0), cursor.getInt(1)) else null
            }
            if (oldMarker != null) {
                val old = DeviceGroupProtocolBridge.execute(JSONObject()
                    .put("operation", "read_state")
                    .put("state", state.context), groupKey = state.groupKey)
                require(oldMarker.first == old.getString("state_hash") &&
                    oldMarker.second == old.getInt("op_count"))
            }
            val proofs = state.context.getJSONArray("ratifications")
            for (proof in ratifications) proofs.put(b64(proof))
            val request = JSONObject().put("operation",
                if (foreignSource != null) "preview_reinvite" else
                    if (historical) "preview_history" else "preview_live")
                .put("state", state.context).put("incoming", b64(incoming))
            if (historical) request.put("receipt", b64(historyReceipt!!))
                .put("incoming_key", b64(incomingKey!!))
            if (foreignSource != null) request.put("source_account", b64(foreignSource))
            val summary = DeviceGroupProtocolBridge.execute(request,
                groupKey = state.groupKey)
            val infos = summary.getJSONArray("incoming_ops")
            require(infos.length() == records.size)
            val key = Base64.decode(summary.getString("group_secret"), Base64.DEFAULT)
            require(key.size == 32)
            try {
                val keyring = summary.getJSONArray("keyring")
                var selected = false
                for (index in 0 until keyring.length()) {
                    val row = keyring.getJSONObject(index)
                    val epoch = row.getString("epoch")
                    val secret = Base64.decode(row.getString("key"), Base64.DEFAULT)
                    require(epoch.matches(Regex("[0-9a-f]{64}")) && secret.size == 32)
                    try {
                        if (epoch == summary.getString("current_epoch")) {
                            require(row.getBoolean("eligible") && secret.contentEquals(key))
                            selected = true
                        }
                        val prior = db.query(SimpleSQLiteQuery("SELECT secret FROM " +
                            "delegated_group_keys WHERE group_id=? AND epoch=?",
                            arrayOf(groupId, epoch))).use { cursor ->
                            if (cursor.moveToFirst()) cursor.getBlob(0) else null
                        }
                        require(prior == null || prior.contentEquals(secret))
                        db.execSQL("INSERT OR REPLACE INTO delegated_group_keys " +
                            "(group_id,epoch,secret,eligible) VALUES (?,?,?,?)",
                            arrayOf(groupId, epoch, secret,
                                if (row.getBoolean("eligible")) 1 else 0))
                    } finally { secret.fill(0) }
                }
                require(selected)
                val name = summary.getString("name").filter { it.code >= 32 && it.code != 127 }
                    .take(32)
                val last = summary.optJSONObject("last_message")
                val preview = if (last == null) null else if (last.getBoolean("deleted"))
                    "Message deleted" else {
                    val epoch = last.optString("cipher_epoch")
                    val previewKey = if (epoch.isEmpty() || epoch == "null") key.copyOf()
                        else db.query(SimpleSQLiteQuery("SELECT secret FROM " +
                            "delegated_group_keys WHERE group_id=? AND epoch=?",
                            arrayOf(groupId, epoch))).use { cursor ->
                            if (cursor.moveToFirst()) cursor.getBlob(0) else null
                        }
                    try {
                        if (previewKey == null) "[Encrypted]" else runCatching {
                            val cipher = Base64.decode(last.getString("ciphertext_b64"),
                                Base64.DEFAULT)
                            val nonce = Base64.decode(last.getString("nonce_b64"),
                                Base64.DEFAULT)
                            RustBridge.xchacha20Decrypt(cipher, previewKey, nonce)
                                ?.toString(Charsets.UTF_8)?.take(100) ?: "[Encrypted]"
                        }.getOrDefault("[Encrypted]")
                    } finally { previewKey?.fill(0) }
                }
                val members = summary.getJSONArray("members")
                var memberCount = 0
                for (index in 0 until members.length()) {
                    val member = members.getJSONObject(index)
                    if (member.getBoolean("accepted") && !member.getBoolean("removed") &&
                        !member.getBoolean("banned")) memberCount++
                }
                db.execSQL("DELETE FROM delegated_group_principals WHERE group_id=?",
                    arrayOf(groupId))
                for (index in 0 until members.length()) {
                    val member = members.getJSONObject(index)
                    if (!member.getBoolean("removed") && !member.getBoolean("banned"))
                        db.execSQL("INSERT INTO delegated_group_principals " +
                            "(group_id,account_ed) VALUES (?,?)",
                            arrayOf(groupId, b64(hexBytes(member.getString("pubkey_hex")))))
                }
                db.execSQL("UPDATE groups SET name=?,groupSecretB64=?,memberCount=?," +
                    "isPendingInvite=?,lastActivityTimestamp=?,lastMessagePreview=? " +
                    "WHERE groupId=?", arrayOf(name, b64(key),
                        memberCount, if (summary.getBoolean("pending_invite")) 1 else 0,
                        last?.getLong("timestamp_ms") ?: nowMs, preview, groupId))
                var unread = 0
                for (index in records.indices) {
                    val info = infos.getJSONObject(index)
                    val opId = info.getString("op_id")
                    val hash = info.getString("hash")
                    require(info.getString("group_id") == groupId &&
                        hash == hex(DeviceGroupFrame.hash(records[index])) &&
                        opId.length in 1..256)
                    val known = db.query(SimpleSQLiteQuery(
                        "SELECT groupId,opBytes FROM crdt_op_log WHERE opId=?",
                        arrayOf(opId))).use { cursor ->
                        if (cursor.moveToFirst()) Pair(cursor.getString(0), cursor.getBlob(1))
                        else null
                    }
                    if (known != null) {
                        require(known.first == groupId &&
                            known.second.contentEquals(records[index]))
                    } else {
                        db.execSQL("INSERT INTO crdt_op_log " +
                            "(opId,groupId,opType,opBytes,lamport,createdAt) " +
                            "VALUES (?,?,?,?,?,?)", arrayOf(opId, groupId,
                                info.getString("op_type"), records[index],
                                info.getLong("lamport"), info.getLong("timestamp_ms")))
                        if (!historical && info.getString("op_type") == "MsgAdd" &&
                            info.getString("account_public") != b64(account)) unread++
                    }
                    db.execSQL("INSERT OR IGNORE INTO delegated_group_acceptance " +
                        "(op_id,group_id,operation_hash,accepted_at_ms) VALUES (?,?,?,?)",
                        arrayOf(opId, groupId, hash, nowMs))
                }
                for (proof in ratifications) {
                    val proofHash = hex(proof.copyOfRange(6, 38))
                    db.execSQL("INSERT OR IGNORE INTO delegated_group_ratifications " +
                        "(operation_hash,group_id,proof) VALUES (?,?,?)",
                        arrayOf(proofHash, groupId, proof))
                }
                db.execSQL("INSERT OR REPLACE INTO delegated_group_states " +
                    "(group_id,state_hash,op_count,updated_at_ms) VALUES (?,?,?,?)",
                    arrayOf(groupId, summary.getString("state_hash"),
                        summary.getInt("op_count"), nowMs))
                if (unread > 0) db.execSQL("UPDATE groups SET unreadCount=unreadCount+? " +
                    "WHERE groupId=?", arrayOf(unread, groupId))
                return summary.apply { remove("group_secret"); remove("keyring") }
            } finally { key.fill(0) }
        } finally {
            records.forEach { it.fill(0) }
            state.groupKey.fill(0)
        }
    }

    private fun unpack(packed: ByteArray, maxRecords: Int = 500_000): List<ByteArray> {
        val result = ArrayList<ByteArray>()
        var at = 0
        while (at < packed.size) {
            require(packed.size - at >= 4 && result.size < maxRecords)
            val length = (packed[at].toInt() and 255 shl 24) or
                (packed[at + 1].toInt() and 255 shl 16) or
                (packed[at + 2].toInt() and 255 shl 8) or
                (packed[at + 3].toInt() and 255)
            at += 4
            require(length in 1..69_632 && length <= packed.size - at)
            result.add(packed.copyOfRange(at, at + length))
            at += length
        }
        return result
    }

    fun applyRatificationsInTransaction(db: SupportSQLiteDatabase,
                                        groupId: String, account: ByteArray,
                                        proofs: List<ByteArray>, nowMs: Long): JSONObject {
        require(db.inTransaction() && proofs.size in 1..16 &&
            proofs.all { it.size == 134 })
        val state = loadInTransaction(db, groupId, account, nowMs)
        try {
            val marker = db.query(SimpleSQLiteQuery("SELECT state_hash,op_count FROM " +
                "delegated_group_states WHERE group_id=?", arrayOf(groupId))).use { cursor ->
                if (cursor.moveToFirst()) Pair(cursor.getString(0), cursor.getInt(1)) else null
            } ?: throw IllegalStateException("Group is not adopted")
            val current = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "read_state").put("state", state.context),
                groupKey = state.groupKey)
            require(marker.first == current.getString("state_hash") &&
                marker.second == current.getInt("op_count"))
            val ratifications = state.context.getJSONArray("ratifications")
            proofs.forEach { ratifications.put(b64(it)) }
            val accepted = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "read_state").put("state", state.context),
                groupKey = state.groupKey)
            require(marker.first == accepted.getString("state_hash") &&
                marker.second == accepted.getInt("op_count"))
            for (proof in proofs)
                db.execSQL("INSERT OR IGNORE INTO delegated_group_ratifications " +
                    "(operation_hash,group_id,proof) VALUES (?,?,?)",
                    arrayOf(hex(proof.copyOfRange(6, 38)), groupId, proof))
            return accepted.apply { remove("group_secret"); remove("keyring") }
        } finally { state.groupKey.fill(0) }
    }

    /** A first invitation is authorized by the source's exact SLGH01 receipt. */
    fun applyFirstInviteInTransaction(db: SupportSQLiteDatabase, groupId: String,
                                      account: ByteArray, source: ByteArray,
                                      packed: ByteArray, incomingKey: ByteArray,
                                      receipt: ByteArray,
                                      ratifications: List<ByteArray>,
                                      observedAccounts: List<ByteArray>,
                                      ownHistory: Boolean = false,
                                      nowMs: Long): JSONObject {
        require(db.inTransaction() && groupId.matches(Regex("[0-9a-f]{64}")) &&
            account.size == 32 && source.size == 32 && incomingKey.size == 32 &&
            receipt.size == 408 && packed.size in 5..24 * 1024 * 1024 &&
            ratifications.size <= 4096 && ratifications.all { it.size == 134 } &&
            observedAccounts.size <= 128 && observedAccounts.all { it.size == 32 })
        require(!db.query(SimpleSQLiteQuery("SELECT 1 FROM groups WHERE groupId=?",
            arrayOf(groupId))).use { it.moveToFirst() })
        val records = unpack(packed)
        require(records.isNotEmpty())
        try {
            val rosterAccounts = LinkedHashSet<String>()
            rosterAccounts.add(b64(account))
            rosterAccounts.add(b64(source))
            observedAccounts.forEach { rosterAccounts.add(b64(it)) }
            require(rosterAccounts.size <= 128)
            val rosters = JSONArray()
            for (principal in rosterAccounts) {
                val global = db.query(SimpleSQLiteQuery("SELECT signedRoster FROM " +
                    "device_rosters WHERE accountEd=?", arrayOf(principal))).use { cursor ->
                    if (cursor.moveToFirst()) cursor.getBlob(0) else null
                }
                val encoded = global ?: db.query(SimpleSQLiteQuery("SELECT roster FROM " +
                    "delegated_group_trusted_rosters WHERE account_ed=?",
                    arrayOf(principal))).use { cursor ->
                    if (cursor.moveToFirst()) cursor.getBlob(0) else null
                } ?: throw IllegalStateException("Invitation roster unavailable")
                rosters.put(JSONObject().put("account_public", principal)
                    .put("encoded", b64(encoded)))
            }
            val proofs = JSONArray()
            ratifications.forEach { proofs.put(b64(it)) }
            val context = JSONObject().put("group_id", groupId)
                .put("account_public", b64(account))
                .put("existing_local", b64(ByteArray(0)))
                .put("rosters", rosters).put("ratifications", proofs)
                .put("now_ms", nowMs)
            val request = JSONObject()
                .put("operation", if (ownHistory) "preview_history" else "preview_invite")
                .put("state", context).put("incoming", b64(packed))
                .put("receipt", b64(receipt)).put("incoming_key", b64(incomingKey))
            if (!ownHistory) request.put("source_account", b64(source))
            val summary = DeviceGroupProtocolBridge.execute(request,
                groupKey = incomingKey)
            val infos = summary.getJSONArray("incoming_ops")
            require(infos.length() == records.size &&
                (ownHistory || summary.getBoolean("pending_invite")) &&
                !summary.getBoolean("deleted"))
            val founding = (0 until infos.length()).map { infos.getJSONObject(it) }
                .firstOrNull { it.getString("op_type") == "GroupCreate" }
                ?: throw IllegalArgumentException("Invitation lacks group creation")
            val selected = Base64.decode(summary.getString("group_secret"), Base64.DEFAULT)
            require(selected.size == 32)
            try {
                val name = summary.getString("name").filter {
                    it.code >= 32 && it.code != 127 }.take(32)
                val members = summary.getJSONArray("members")
                var memberCount = 0
                for (index in 0 until members.length()) {
                    val member = members.getJSONObject(index)
                    if (member.getBoolean("accepted") && !member.getBoolean("removed") &&
                        !member.getBoolean("banned")) memberCount++
                }
                db.execSQL("INSERT INTO groups (groupId,name,groupSecretB64,createdAt," +
                    "lastActivityTimestamp,isMuted,memberCount,isPendingInvite,isPinned," +
                    "unreadCount) VALUES (?,?,?,?,?,0,?,?,0,0)",
                    arrayOf(groupId, name, b64(selected),
                        founding.getLong("timestamp_ms"), nowMs, memberCount,
                        if (summary.getBoolean("pending_invite")) 1 else 0))
                val keyring = summary.getJSONArray("keyring")
                var currentFound = false
                for (index in 0 until keyring.length()) {
                    val row = keyring.getJSONObject(index)
                    val epoch = row.getString("epoch")
                    val secret = Base64.decode(row.getString("key"), Base64.DEFAULT)
                    require(epoch.matches(Regex("[0-9a-f]{64}")) && secret.size == 32)
                    try {
                        if (epoch == summary.getString("current_epoch")) {
                            require(row.getBoolean("eligible") &&
                                selected.contentEquals(secret))
                            currentFound = true
                        }
                        db.execSQL("INSERT INTO delegated_group_keys " +
                            "(group_id,epoch,secret,eligible) VALUES (?,?,?,?)",
                            arrayOf(groupId, epoch, secret,
                                if (row.getBoolean("eligible")) 1 else 0))
                    } finally { secret.fill(0) }
                }
                require(currentFound)
                for (index in records.indices) {
                    val info = infos.getJSONObject(index)
                    val opId = info.getString("op_id")
                    val hash = hex(DeviceGroupFrame.hash(records[index]))
                    require(info.getString("group_id") == groupId &&
                        info.getString("hash") == hash)
                    db.execSQL("INSERT INTO crdt_op_log " +
                        "(opId,groupId,opType,opBytes,lamport,createdAt) " +
                        "VALUES (?,?,?,?,?,?)", arrayOf(opId, groupId,
                            info.getString("op_type"), records[index],
                            info.getLong("lamport"), info.getLong("timestamp_ms")))
                    db.execSQL("INSERT INTO delegated_group_acceptance " +
                        "(op_id,group_id,operation_hash,accepted_at_ms) VALUES (?,?,?,?)",
                        arrayOf(opId, groupId, hash, nowMs))
                }
                for (index in 0 until members.length()) {
                    val member = members.getJSONObject(index)
                    if (!member.getBoolean("removed") && !member.getBoolean("banned"))
                        db.execSQL("INSERT INTO delegated_group_principals " +
                            "(group_id,account_ed) VALUES (?,?)", arrayOf(groupId,
                                b64(hexBytes(member.getString("pubkey_hex")))))
                }
                for (proof in ratifications)
                    db.execSQL("INSERT OR IGNORE INTO delegated_group_ratifications " +
                        "(operation_hash,group_id,proof) VALUES (?,?,?)",
                        arrayOf(hex(proof.copyOfRange(6, 38)), groupId, proof))
                db.execSQL("INSERT INTO delegated_group_states " +
                    "(group_id,state_hash,op_count,updated_at_ms) VALUES (?,?,?,?)",
                    arrayOf(groupId, summary.getString("state_hash"),
                        summary.getInt("op_count"), nowMs))
                return summary.apply { remove("group_secret"); remove("keyring") }
            } finally { selected.fill(0) }
        } finally { records.forEach { it.fill(0) } }
    }

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
                          account: ByteArray, nowMs: Long,
                          extraAccounts: List<ByteArray> = emptyList()): State {
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
                extraAccounts.forEach { rosterAccounts.add(b64(it)) }
                db.query(SimpleSQLiteQuery("SELECT account_ed FROM " +
                    "delegated_group_principals WHERE group_id=?", arrayOf(groupId)))
                    .use { cursor ->
                        while (cursor.moveToNext()) rosterAccounts.add(cursor.getString(0))
                    }
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
                        else db.query(SimpleSQLiteQuery("SELECT roster FROM " +
                            "delegated_group_trusted_rosters WHERE account_ed=?",
                            arrayOf(identity))).use { delegated ->
                            if (delegated.moveToFirst()) rosters.put(JSONObject()
                                .put("account_public", identity)
                                .put("encoded", b64(delegated.getBlob(0))))
                        }
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
    private fun hexBytes(hex: String): ByteArray {
        require(hex.matches(Regex("[0-9a-f]{64}")))
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
