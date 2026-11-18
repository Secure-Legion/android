package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.DeviceSyncSourceCapture

/** Applies a validated text copy inside the same transaction as its history cursor. */
internal object DeviceSyncTextMessageStore {
    /** False means the pinned contact has not arrived yet. */
    fun applyInTransaction(db: SupportSQLiteDatabase,
                           message: DeviceSyncMessageDelta.Message,
                           encryptForLocalProfile: (String) -> String): Boolean {
        require(db.inTransaction())
        if (message.deleted) {
            DeviceSyncSourceCapture.suppressDuringImport(db) {
                db.execSQL("UPDATE messages SET encryptedContent='',attachmentData=NULL," +
                    "voiceFilePath=NULL,replyToMessageId=NULL,status=8 " +
                    "WHERE messageId=? AND isDeviceSyncImported=1", arrayOf(message.id))
            }
            return true
        }
        require(message.type == "TEXT" && message.content != null &&
            message.contactX25519?.size == 32 && message.sentByMe != null &&
            message.timestampMs != null && message.status != null &&
            message.voiceData == null && message.attachmentData == null &&
            message.attachmentType == null)
        val contactX = Base64.encodeToString(message.contactX25519, Base64.NO_WRAP)
        val contactId = db.query(SimpleSQLiteQuery(
            "SELECT id FROM contacts WHERE x25519PublicKeyBase64=? " +
                "AND friendshipStatus='CONFIRMED' LIMIT 1", arrayOf(contactX)
        )).use { if (it.moveToFirst()) it.getLong(0) else null } ?: return false
        val existing = db.query(SimpleSQLiteQuery(
            "SELECT contactId,isSentByMe,messageType,status,isDeviceSyncImported " +
                "FROM messages WHERE messageId=? LIMIT 1", arrayOf(message.id)
        )).use { cursor ->
            if (!cursor.moveToFirst()) null else Existing(cursor.getLong(0),
                cursor.getInt(1) == 1, cursor.getString(2), cursor.getInt(3),
                cursor.getInt(4) == 1)
        }
        if (existing != null) {
            require(existing.contactId == contactId &&
                existing.sentByMe == message.sentByMe && existing.type == "TEXT") {
                "Message identity rebind"
            }
            if (existing.status == 8) return true
            val mergedStatus = DeviceSyncReceiptDelta.mergeStatus(existing.status,
                message.status)
            val encrypted = if (existing.imported) encryptForLocalProfile(message.content)
                else null
            DeviceSyncSourceCapture.suppressDuringImport(db) {
                db.execSQL("UPDATE messages SET " +
                    "encryptedContent=COALESCE(?,encryptedContent),status=?," +
                    "isRead=MAX(isRead,?),isEdited=MAX(isEdited,?)," +
                    "pingDelivered=MAX(pingDelivered,?)," +
                    "messageDelivered=MAX(messageDelivered,?) WHERE messageId=?",
                    arrayOf(encrypted, mergedStatus, if (message.read) 1 else 0,
                        if (message.edited) 1 else 0,
                        if (message.pingDelivered) 1 else 0,
                        if (message.messageDelivered) 1 else 0, message.id))
            }
            return true
        }
        // Imported copies have no local PING, signature, nonce or delivery job.
        val encrypted = encryptForLocalProfile(message.content)
        DeviceSyncSourceCapture.suppressDuringImport(db) {
            db.execSQL("INSERT INTO messages " +
                "(contactId,messageId,encryptedContent,isSentByMe,timestamp,status," +
                "signatureBase64,nonceBase64,messageNonce,messageType,isRead," +
                "requiresReadReceipt,retryCount,pingDelivered,messageDelivered," +
                "tapDelivered,replyToMessageId,isEdited,selfDestructAt," +
                "selfDestructTtl,isPinned,isDeviceSyncImported) " +
                "VALUES (?,?,?,?,?,?,?,?,?,'TEXT',?,0,0,?,?,0,?,?,?,?,0,1)",
                arrayOf(contactId, message.id, encrypted, if (message.sentByMe) 1 else 0,
                    message.timestampMs, message.status, "", "", 0L,
                    if (message.read) 1 else 0,
                    if (message.pingDelivered) 1 else 0,
                    if (message.messageDelivered) 1 else 0,
                    message.replyToId,
                    if (message.edited) 1 else 0,
                    message.selfDestructAtMs, message.selfDestructTtl))
        }
        return true
    }

    private data class Existing(val contactId: Long, val sentByMe: Boolean,
                                val type: String, val status: Int,
                                val imported: Boolean)
}
