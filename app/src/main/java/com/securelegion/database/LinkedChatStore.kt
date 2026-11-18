package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.sync.DeviceSyncContactDelta
import com.securelegion.sync.DeviceSyncMediaFiles
import com.securelegion.sync.DeviceSyncMessageDelta
import com.securelegion.sync.DeviceSyncReceiptDelta
import org.json.JSONObject

/** Wallet-free contact and chat projection for a seedless linked profile. */
internal class LinkedChatStore(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val encryptText: (String) -> String,
    private val media: DeviceSyncMediaFiles
) {
    data class Contact(val accountEd: ByteArray, val displayName: String,
                       val x25519: ByteArray)

    fun ensureSchema() {
        val db = database.openHelper.writableDatabase
        db.execSQL("CREATE TABLE IF NOT EXISTS linked_chat_contacts (" +
            "account_ed TEXT NOT NULL PRIMARY KEY,x25519 BLOB NOT NULL," +
            "display_name TEXT NOT NULL,messaging_onion TEXT," +
            "friend_request_onion TEXT,created_at_ms INTEGER NOT NULL," +
            "updated_at_ms INTEGER NOT NULL,blocked INTEGER NOT NULL DEFAULT 0)")
        db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_linked_chat_contacts_x " +
            "ON linked_chat_contacts(x25519)")
        db.execSQL("CREATE TABLE IF NOT EXISTS linked_chat_messages (" +
            "message_id TEXT NOT NULL PRIMARY KEY,account_ed TEXT NOT NULL," +
            "encrypted_content TEXT NOT NULL,type TEXT NOT NULL," +
            "sent_by_me INTEGER NOT NULL,timestamp_ms INTEGER NOT NULL," +
            "status INTEGER NOT NULL,media_path TEXT,voice_duration INTEGER," +
            "reply_to_id TEXT,read INTEGER NOT NULL DEFAULT 0," +
            "edited INTEGER NOT NULL DEFAULT 0,imported INTEGER NOT NULL DEFAULT 0)")
        db.execSQL("CREATE INDEX IF NOT EXISTS index_linked_chat_messages_contact_time " +
            "ON linked_chat_messages(account_ed,timestamp_ms)")
    }

    fun contact(db: SupportSQLiteDatabase, accountEd: ByteArray): Contact? {
        require(accountEd.size == 32)
        return db.query(SimpleSQLiteQuery("SELECT display_name,x25519 FROM " +
            "linked_chat_contacts WHERE account_ed=? AND blocked=0",
            arrayOf(Base64.encodeToString(accountEd, Base64.NO_WRAP)))).use { cursor ->
            if (!cursor.moveToFirst()) null else Contact(accountEd.copyOf(),
                cursor.getString(0), cursor.getBlob(1))
        }
    }

    /** Called only from an authenticated own-device history transaction. */
    fun applyContact(db: SupportSQLiteDatabase,
                     delta: DeviceSyncContactDelta.Contact,
                     nowMs: Long): Boolean {
        require(db.inTransaction() && delta.publicKey.size == 32)
        val account = Base64.encodeToString(delta.publicKey, Base64.NO_WRAP)
        if (delta.deleted) {
            db.execSQL("DELETE FROM linked_chat_contacts WHERE account_ed=?",
                arrayOf(account))
            return true
        }
        val x = requireNotNull(delta.x25519Key)
        val name = requireNotNull(delta.displayName)
        val existingX = db.query(SimpleSQLiteQuery(
            "SELECT x25519 FROM linked_chat_contacts WHERE account_ed=?",
            arrayOf(account))).use { if (it.moveToFirst()) it.getBlob(0) else null }
        if (existingX != null) require(existingX.contentEquals(x)) {
            "Linked contact account key rebind"
        }
        // The containing own-device frame is authenticated. A public recipient
        // roster is still accepted only after account-signature verification.
        delta.deviceRoster?.let {
            roster.acceptSignedRosterInTransaction(db, it, delta.publicKey, null, nowMs)
        }
        db.execSQL("INSERT INTO linked_chat_contacts " +
            "(account_ed,x25519,display_name,messaging_onion," +
            "friend_request_onion,created_at_ms,updated_at_ms,blocked) " +
            "VALUES (?,?,?,?,?,?,?,0) ON CONFLICT(account_ed) DO UPDATE SET " +
            "display_name=excluded.display_name," +
            "messaging_onion=excluded.messaging_onion," +
            "friend_request_onion=excluded.friend_request_onion," +
            "updated_at_ms=excluded.updated_at_ms",
            arrayOf(account, x, name, delta.messagingOnion,
                delta.friendRequestOnion, delta.createdAtMs ?: nowMs, nowMs))
        return true
    }

    /** Returns false while the required trusted contact has not arrived. */
    fun applyMessage(db: SupportSQLiteDatabase,
                     delta: DeviceSyncMessageDelta.Message): Boolean {
        require(db.inTransaction())
        if (delta.deleted) {
            db.execSQL("UPDATE linked_chat_messages SET encrypted_content=''," +
                "media_path=NULL,status=8 WHERE message_id=? AND imported=1",
                arrayOf(delta.id))
            return true
        }
        require(delta.type in setOf("TEXT", "IMAGE", "VOICE") &&
            delta.contactX25519?.size == 32 && delta.sentByMe != null &&
            delta.timestampMs != null && delta.status != null)
        val account = db.query(SimpleSQLiteQuery(
            "SELECT account_ed FROM linked_chat_contacts WHERE x25519=? AND blocked=0",
            arrayOf(delta.contactX25519))).use {
            if (it.moveToFirst()) it.getString(0) else null
        } ?: return false
        val existing = db.query(SimpleSQLiteQuery("SELECT account_ed,sent_by_me,type," +
            "status,imported,timestamp_ms FROM linked_chat_messages WHERE message_id=?",
            arrayOf(delta.id))).use { cursor ->
            if (!cursor.moveToFirst()) null else arrayOf(cursor.getString(0),
                cursor.getInt(1).toString(), cursor.getString(2),
                cursor.getInt(3).toString(), cursor.getInt(4).toString(),
                cursor.getLong(5).toString())
        }
        if (existing != null) {
            require(existing[0] == account &&
                existing[1] == (if (delta.sentByMe) "1" else "0") &&
                existing[2] == delta.type &&
                existing[5] == delta.timestampMs.toString()) {
                "Linked message identity rebind"
            }
            if (existing[3] == "8") return true
            val merged = DeviceSyncReceiptDelta.mergeStatus(existing[3].toInt(),
                delta.status)
            val imported = existing[4] == "1"
            val content = if (imported && delta.type == "TEXT")
                encryptText(requireNotNull(delta.content)) else null
            val mediaPath = if (imported && delta.type != "TEXT") media.store(delta)
                else null
            db.execSQL("UPDATE linked_chat_messages SET status=?," +
                "encrypted_content=COALESCE(?,encrypted_content)," +
                "media_path=COALESCE(?,media_path),read=MAX(read,?)," +
                "edited=MAX(edited,?) WHERE message_id=?",
                arrayOf(merged, content, mediaPath, if (delta.read) 1 else 0,
                    if (delta.edited) 1 else 0, delta.id))
            return true
        }
        val content = if (delta.type == "TEXT")
            encryptText(requireNotNull(delta.content)) else ""
        val mediaPath = if (delta.type != "TEXT") media.store(delta) else null
        db.execSQL("INSERT INTO linked_chat_messages (message_id,account_ed," +
            "encrypted_content,type,sent_by_me,timestamp_ms,status,media_path," +
            "voice_duration,reply_to_id,read,edited,imported) " +
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
            arrayOf(delta.id, account, content, delta.type,
                if (delta.sentByMe) 1 else 0, delta.timestampMs, delta.status,
                mediaPath, delta.voiceDuration, delta.replyToId,
                if (delta.read) 1 else 0, if (delta.edited) 1 else 0))
        return true
    }

    fun applyDirect(db: SupportSQLiteDatabase, senderAccount: ByteArray,
                    logicalId: String, text: String, type: String,
                    timestampMs: Long, mediaPath: String? = null,
                    duration: Int? = null, replyTo: String? = null): Boolean {
        require(db.inTransaction() && senderAccount.size == 32 &&
            type in setOf("TEXT", "IMAGE", "VOICE"))
        val account = Base64.encodeToString(senderAccount, Base64.NO_WRAP)
        require(contact(db, senderAccount) != null) { "Unknown linked C0 contact" }
        val old = db.query(SimpleSQLiteQuery("SELECT account_ed,sent_by_me,type," +
            "timestamp_ms " +
            "FROM linked_chat_messages WHERE message_id=?", arrayOf(logicalId)))
            .use { if (!it.moveToFirst()) null else listOf(it.getString(0),
                it.getInt(1).toString(), it.getString(2), it.getLong(3).toString()) }
        if (old != null) {
            require(old[0] == account && old[1] == "0" && old[2] == type &&
                old[3] == timestampMs.toString()) {
                "Linked C0 message identity conflict"
            }
            return false
        }
        db.execSQL("INSERT INTO linked_chat_messages (message_id,account_ed," +
            "encrypted_content,type,sent_by_me,timestamp_ms,status,media_path," +
            "voice_duration,reply_to_id,read,edited,imported) " +
            "VALUES (?,?,?,?,0,?,2,?,?,?,0,0,0)",
            arrayOf(logicalId, account, if (type == "TEXT") encryptText(text)
                else "", type, timestampMs, mediaPath, duration, replyTo))
        db.execSQL("INSERT INTO device_sync_source_changes " +
            "(topic,object_id,kind,changed_at_ms) " +
            "VALUES ('messages',?,'body',?)",
            arrayOf(logicalId, System.currentTimeMillis()))
        return false
    }

    fun applyReceipt(db: SupportSQLiteDatabase,
                     receipt: DeviceSyncReceiptDelta.Receipt): Boolean {
        require(db.inTransaction())
        val prior = db.query(SimpleSQLiteQuery("SELECT status,sent_by_me,read " +
            "FROM linked_chat_messages WHERE message_id=?", arrayOf(receipt.messageId)))
            .use { if (!it.moveToFirst()) null else intArrayOf(it.getInt(0),
                it.getInt(1), it.getInt(2)) } ?: return false
        if (prior[0] == 8) return true
        val delivered = receipt.messageDelivered || receipt.status in setOf(2, 3)
        val merged = DeviceSyncReceiptDelta.mergeStatus(prior[0], receipt.status).let {
            if (delivered) DeviceSyncReceiptDelta.mergeStatus(it, 2) else it
        }
        db.execSQL("UPDATE linked_chat_messages SET status=?,read=? " +
            "WHERE message_id=?", arrayOf(merged,
                if (prior[2] == 1 || receipt.status == 3 && prior[1] == 0) 1 else 0,
                receipt.messageId))
        return true
    }

    fun exportReceipt(db: SupportSQLiteDatabase, messageId: String): JSONObject? =
        db.query(SimpleSQLiteQuery("SELECT status FROM linked_chat_messages " +
            "WHERE message_id=?", arrayOf(messageId))).use { cursor ->
            if (!cursor.moveToFirst() || cursor.getInt(0) !in 0..7) null
            else JSONObject().put("message_id", messageId)
                .put("status", cursor.getInt(0))
                .put("message_delivered", cursor.getInt(0) in setOf(2, 3))
        }
}
