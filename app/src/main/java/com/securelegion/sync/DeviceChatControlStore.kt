package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import org.json.JSONObject

/** Authenticated C0 controls remain durable until their exact message arrives. */
internal class DeviceChatControlStore(
    private val encryptText: (String) -> String,
    private val linked: Boolean
) {
    fun accept(db: SupportSQLiteDatabase, accountEd: ByteArray, eventId: String,
               kind: Int, body: ByteArray, timestamp: Long, nowMs: Long): Boolean {
        require(db.inTransaction() && accountEd.size == 32 &&
            eventId.matches(Regex("dev_[A-Za-z0-9_-]{43}")) &&
            kind in setOf(0x10, 0x12, 0x13, 0x14, 0x15) &&
            body.size in 2..67_000)
        ensure(db)
        val account = Base64.encodeToString(accountEd, Base64.NO_WRAP)
        require(contactExists(db, account)) { "Unknown C0 control contact" }
        val json = JSONObject(strictUtf8(body))
        val items = if (kind == 0x15 && json.has("target_message_ids")) {
            require(json.keys().asSequence().toSet() == setOf("target_message_ids"))
            val ids = json.getJSONArray("target_message_ids")
            require(ids.length() in 1..128)
            val seen = HashSet<String>()
            (0 until ids.length()).map { index ->
                require(ids.opt(index) is String)
                val id = ids.getString(index)
                require(validId(id) && seen.add(id))
                JSONObject().put("target_message_id", id)
            }
        } else listOf(json)
        val count = db.query(SimpleSQLiteQuery(
            "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM device_chat_controls"
        )).use { check(it.moveToFirst()); it.getLong(0) to it.getLong(1) }
        require(count.first + items.size <= 4096 &&
            count.second + body.size.toLong() * items.size <= 4L * 1024 * 1024)
        for ((index, item) in items.withIndex()) {
            validate(kind, item)
            val id = if (items.size == 1) eventId else "$eventId:$index"
            val target = item.getString("target_message_id")
            require(!ownedElsewhere(db, account, target)) { "C0 control target contact mismatch" }
            val targetRow = findMessage(db, account, target)
            if (targetRow != null && kind != 0x10)
                require(targetRow.own == (kind == 0x15)) { "C0 control ownership mismatch" }
            val canonical = item.toString()
            val eventTime = if (kind == 0x10 && item.has("updated_at"))
                item.getLong("updated_at") else timestamp
            require(eventTime in 1..nowMs + 300_000L)
            val existing = db.query(SimpleSQLiteQuery(
                "SELECT account_ed,target_id,kind,body,timestamp_ms FROM device_chat_controls " +
                    "WHERE event_id=?", arrayOf(id)
            )).use { c -> if (!c.moveToFirst()) null else listOf(c.getString(0),
                c.getString(1), c.getInt(2).toString(), c.getString(3),
                c.getLong(4).toString()) }
            if (existing != null) require(existing == listOf(account, target,
                    kind.toString(), canonical, eventTime.toString())) {
                "Conflicting C0 control replay"
            } else db.execSQL("INSERT INTO device_chat_controls " +
                "(event_id,account_ed,target_id,kind,body,timestamp_ms) VALUES (?,?,?,?,?,?)",
                arrayOf(id, account, target, kind, canonical, eventTime))
        }
        drain(db, account, nowMs)
        return false // A deferred control has only device-storage provenance.
    }

    fun drainForMessage(db: SupportSQLiteDatabase, accountEd: ByteArray,
                        nowMs: Long = System.currentTimeMillis()) {
        require(db.inTransaction() && accountEd.size == 32)
        ensure(db)
        drain(db, Base64.encodeToString(accountEd, Base64.NO_WRAP), nowMs)
    }

    private fun drain(db: SupportSQLiteDatabase, account: String, nowMs: Long) {
        val pending = db.query(SimpleSQLiteQuery(
            "SELECT event_id,target_id,kind,body,timestamp_ms FROM device_chat_controls " +
                "WHERE account_ed=? ORDER BY timestamp_ms,event_id", arrayOf(account)
        )).use { c -> buildList {
            while (c.moveToNext()) add(Control(c.getString(0), c.getString(1),
                c.getInt(2), c.getString(3), c.getLong(4)))
        } }
        for (control in pending) {
            val row = findMessage(db, account, control.target) ?: continue
            if (row.status == 8) {
                db.execSQL("DELETE FROM device_chat_controls WHERE event_id=?",
                    arrayOf(control.event))
                continue
            }
            val shouldBeOwn = control.kind == 0x15
            if (control.kind != 0x10 && row.own != shouldBeOwn) {
                // The target establishes provenance only after it arrives.
                db.execSQL("DELETE FROM device_chat_controls WHERE event_id=?",
                    arrayOf(control.event))
                continue
            }
            val body = JSONObject(control.body)
            if (control.kind == 0x12 && row.type != "TEXT") {
                db.execSQL("DELETE FROM device_chat_controls WHERE event_id=?",
                    arrayOf(control.event))
                continue
            }
            if (newVersion(db, account, control, nowMs)) {
                when (control.kind) {
                    0x15 -> if (linked) db.execSQL(
                        "UPDATE linked_chat_messages SET read=1,status=MAX(status,3) " +
                            "WHERE message_id=? AND account_ed=? AND sent_by_me=1",
                        arrayOf(control.target, account))
                    else db.execSQL("UPDATE messages SET isRead=1,status=MAX(status,3)," +
                        "messageDelivered=1 WHERE messageId=? AND contactId=? AND isSentByMe=1",
                        arrayOf(control.target, row.contactId))
                    0x12 -> {
                        val encrypted = encryptText(body.getString("new_text"))
                        if (linked) db.execSQL("UPDATE linked_chat_messages SET " +
                            "encrypted_content=?,edited=1 WHERE message_id=? AND account_ed=?",
                            arrayOf(encrypted, control.target, account))
                        else db.execSQL("UPDATE messages SET encryptedContent=?,isEdited=1 " +
                            "WHERE messageId=? AND contactId=?", arrayOf(encrypted,
                            control.target, row.contactId))
                    }
                    0x13 -> {
                        val ttl = body.getDouble("ttl")
                        if (linked) db.execSQL("UPDATE linked_chat_messages SET " +
                            "self_destruct_ttl=? WHERE message_id=? AND account_ed=? " +
                            "AND self_destruct_at IS NULL", arrayOf(ttl, control.target, account))
                        else db.execSQL("UPDATE messages SET selfDestructTtl=? " +
                            "WHERE messageId=? AND contactId=? AND selfDestructAt IS NULL",
                            arrayOf(ttl, control.target, row.contactId))
                    }
                    0x14 -> {
                        if (linked) db.execSQL("UPDATE linked_chat_messages SET " +
                            "encrypted_content='',media_path=NULL,status=8 " +
                            "WHERE message_id=? AND account_ed=? AND sent_by_me=0",
                            arrayOf(control.target, account))
                        else db.execSQL("UPDATE messages SET encryptedContent=''," +
                            "attachmentData=NULL,voiceFilePath=NULL,status=8 " +
                            "WHERE messageId=? AND contactId=? AND isSentByMe=0",
                            arrayOf(control.target, row.contactId))
                        db.execSQL("INSERT INTO device_sync_deletions " +
                            "(topic,object_id,event_time_ms) VALUES ('messages',?,?) " +
                            "ON CONFLICT(topic,object_id) DO UPDATE SET " +
                            "event_time_ms=MAX(event_time_ms,excluded.event_time_ms)",
                            arrayOf(control.target, control.time))
                    }
                    0x10 -> if (!linked) db.execSQL("INSERT INTO message_reactions " +
                        "(contactId,targetMessageId,reactorPubKey,emoji,isRemoved,createdAt,updatedAt) " +
                        "VALUES (?,?,?,?,?,?,?) ON CONFLICT(contactId,targetMessageId,reactorPubKey) " +
                        "DO UPDATE SET emoji=excluded.emoji,isRemoved=excluded.isRemoved," +
                        "updatedAt=excluded.updatedAt WHERE excluded.updatedAt>=updatedAt",
                        arrayOf(row.contactId, control.target, account,
                            body.getString("emoji"), if (body.getBoolean("present")) 0 else 1,
                            control.time, control.time))
                    else db.execSQL("INSERT INTO linked_chat_reactions " +
                        "(account_ed,target_id,emoji,removed,updated_at_ms) VALUES (?,?,?,?,?) " +
                        "ON CONFLICT(account_ed,target_id) DO UPDATE SET emoji=excluded.emoji," +
                        "removed=excluded.removed,updated_at_ms=excluded.updated_at_ms " +
                        "WHERE excluded.updated_at_ms>=updated_at_ms",
                        arrayOf(account, control.target, body.getString("emoji"),
                            if (body.getBoolean("present")) 0 else 1, control.time))
                }
                db.execSQL("INSERT INTO device_sync_source_changes " +
                    "(topic,object_id,kind,changed_at_ms) VALUES ('messages',?,?,?)",
                    arrayOf(control.target,
                        if (control.kind == 0x15) "receipt" else "body", nowMs))
            }
            db.execSQL("DELETE FROM device_chat_controls WHERE event_id=?",
                arrayOf(control.event))
        }
    }

    private fun newVersion(db: SupportSQLiteDatabase, account: String,
                           control: Control, nowMs: Long): Boolean {
        val old = db.query(SimpleSQLiteQuery("SELECT timestamp_ms,event_id FROM " +
            "device_chat_control_versions WHERE account_ed=? AND target_id=? AND kind=?",
            arrayOf(account, control.target, control.kind)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getString(1) else null }
        if (old != null && (control.time < old.first ||
                control.time == old.first && control.event <= old.second)) return false
        require(control.time in 1..nowMs + 300_000L)
        db.execSQL("INSERT OR REPLACE INTO device_chat_control_versions " +
            "(account_ed,target_id,kind,timestamp_ms,event_id) VALUES (?,?,?,?,?)",
            arrayOf(account, control.target, control.kind, control.time, control.event))
        return true
    }

    private fun findMessage(db: SupportSQLiteDatabase, account: String, target: String): Row? =
        if (linked) db.query(SimpleSQLiteQuery("SELECT account_ed,sent_by_me,type,status " +
            "FROM linked_chat_messages WHERE message_id=? LIMIT 1", arrayOf(target)
        )).use { c -> if (!c.moveToFirst() || c.getString(0) != account)
            null else Row(null, c.getInt(1) == 1, c.getString(2), c.getInt(3)) }
        else db.query(SimpleSQLiteQuery("SELECT m.contactId,m.isSentByMe,m.messageType," +
            "m.status,c.publicKeyBase64 FROM messages m JOIN contacts c ON c.id=m.contactId " +
            "WHERE m.messageId=? LIMIT 1", arrayOf(target)
        )).use { c -> if (!c.moveToFirst() || c.getString(4) != account)
            null else Row(c.getLong(0), c.getInt(1) == 1, c.getString(2), c.getInt(3)) }

    private fun ownedElsewhere(db: SupportSQLiteDatabase, account: String,
                               target: String): Boolean =
        if (linked) db.query(SimpleSQLiteQuery("SELECT 1 FROM linked_chat_messages " +
            "WHERE message_id=? AND account_ed<>? LIMIT 1", arrayOf(target, account)
        )).use { it.moveToFirst() }
        else db.query(SimpleSQLiteQuery("SELECT 1 FROM messages m JOIN contacts c " +
            "ON c.id=m.contactId WHERE m.messageId=? AND c.publicKeyBase64<>? LIMIT 1",
            arrayOf(target, account)
        )).use { it.moveToFirst() }

    private fun contactExists(db: SupportSQLiteDatabase, account: String): Boolean =
        db.query(SimpleSQLiteQuery(if (linked)
            "SELECT 1 FROM linked_chat_contacts WHERE account_ed=? AND blocked=0 LIMIT 1"
        else "SELECT 1 FROM contacts WHERE publicKeyBase64=? AND " +
            "friendshipStatus='CONFIRMED' AND isBlocked=0 LIMIT 1", arrayOf(account)
        )).use { it.moveToFirst() }

    private fun validate(kind: Int, body: JSONObject) {
        val keys = body.keys().asSequence().toSet()
        require(body.opt("target_message_id") is String &&
            validId(body.getString("target_message_id")))
        val allowed = when (kind) {
            0x10 -> setOf("target_message_id", "target_blob_id", "emoji",
                "emoji_codepoint", "present", "updated_at")
            0x12 -> setOf("target_message_id", "target_blob_id", "new_text")
            0x13 -> setOf("target_message_id", "target_blob_id", "ttl")
            else -> setOf("target_message_id", "target_blob_id")
        }
        require(keys.all { it in allowed })
        if (body.has("target_blob_id")) require(body.opt("target_blob_id") is String &&
            body.getString("target_blob_id").length <= 256)
        when (kind) {
            0x12 -> require(body.opt("new_text") is String &&
                body.getString("new_text").isNotBlank() &&
                body.getString("new_text").toByteArray().size <= 65_536)
            0x13 -> require(body.opt("ttl") is Number &&
                body.getDouble("ttl").isFinite() && body.getDouble("ttl") in 1.0..604_800.0)
            0x10 -> require(body.opt("emoji") is String &&
                body.getString("emoji").length <= 32 && body.opt("present") is Boolean &&
                (!body.getBoolean("present") || body.getString("emoji").isNotEmpty()))
        }
        if (body.has("emoji_codepoint")) require(body.opt("emoji_codepoint") is String &&
            body.getString("emoji_codepoint").length <= 64)
        if (body.has("updated_at")) require(body.opt("updated_at") is Int ||
            body.opt("updated_at") is Long)
    }

    private fun ensure(db: SupportSQLiteDatabase) {
        db.execSQL("CREATE TABLE IF NOT EXISTS device_chat_controls (event_id TEXT NOT NULL " +
            "PRIMARY KEY,account_ed TEXT NOT NULL,target_id TEXT NOT NULL,kind INTEGER NOT NULL," +
            "body TEXT NOT NULL,timestamp_ms INTEGER NOT NULL)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_device_chat_controls_target ON " +
            "device_chat_controls(account_ed,target_id)")
        db.execSQL("CREATE TABLE IF NOT EXISTS device_chat_control_versions (" +
            "account_ed TEXT NOT NULL,target_id TEXT NOT NULL,kind INTEGER NOT NULL," +
            "timestamp_ms INTEGER NOT NULL,event_id TEXT NOT NULL," +
            "PRIMARY KEY(account_ed,target_id,kind))")
        db.execSQL("CREATE TABLE IF NOT EXISTS linked_chat_reactions (account_ed TEXT NOT NULL," +
            "target_id TEXT NOT NULL,emoji TEXT NOT NULL,removed INTEGER NOT NULL," +
            "updated_at_ms INTEGER NOT NULL,PRIMARY KEY(account_ed,target_id))")
    }

    private fun validId(id: String) = id.isNotEmpty() && id.length <= 256 &&
        id.none { it.code < 32 }
    private fun strictUtf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
    private data class Control(val event: String, val target: String, val kind: Int,
                               val body: String, val time: Long)
    private data class Row(val contactId: Long?, val own: Boolean, val type: String,
                           val status: Int)
}
