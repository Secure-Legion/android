package com.securelegion.sync

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.DeviceSyncSourceCapture
import org.json.JSONObject

/** Direct-message receipt delta. Caller must authenticate, authorize and version the PUSH. */
internal object DeviceSyncReceiptDelta {
    data class Receipt(val messageId: String, val status: Int,
                       val pingDelivered: Boolean, val messageDelivered: Boolean)

    fun parse(delta: JSONObject): Receipt {
        val keys = delta.keys().asSequence().toSet()
        require("message_id" in keys && "status" in keys &&
            keys.all { it in setOf("message_id", "status", "ping_delivered", "message_delivered") })
        require(delta.opt("message_id") is String)
        val id = delta.getString("message_id")
        require(id.isNotEmpty() && id.length <= 256)
        val rawStatus = delta.opt("status")
        require(rawStatus is Int && rawStatus in 0..7)
        for (key in listOf("ping_delivered", "message_delivered"))
            require(!delta.has(key) || delta.opt(key) is Boolean)
        return Receipt(id, rawStatus, delta.optBoolean("ping_delivered", false),
            delta.optBoolean("message_delivered", false))
    }

    fun export(db: SupportSQLiteDatabase, messageId: String): JSONObject? {
        require(messageId.isNotEmpty() && messageId.length <= 256)
        return db.query(SimpleSQLiteQuery("SELECT status,pingDelivered,messageDelivered " +
            "FROM messages WHERE messageId=? LIMIT 1", arrayOf(messageId))).use { cursor ->
            if (!cursor.moveToFirst() || cursor.getInt(0) !in 0..7) null
            else JSONObject().put("message_id", messageId)
                .put("status", cursor.getInt(0)).put("ping_delivered", cursor.getInt(1) == 1)
                .put("message_delivered", cursor.getInt(2) == 1)
        }
    }

    /** False means a missing message dependency; the caller must retain the event. */
    fun applyInTransaction(db: SupportSQLiteDatabase, receipt: Receipt): Boolean {
        require(db.inTransaction())
        val current = db.query(SimpleSQLiteQuery(
            "SELECT status,isSentByMe,isRead,pingDelivered,messageDelivered " +
                "FROM messages WHERE messageId=? LIMIT 1", arrayOf(receipt.messageId)
        )).use { cursor ->
            if (!cursor.moveToFirst()) null else intArrayOf(cursor.getInt(0), cursor.getInt(1),
                cursor.getInt(2), cursor.getInt(3), cursor.getInt(4))
        } ?: return false
        if (current[0] == 8) return true // Local expiry is terminal.
        val delivered = receipt.messageDelivered || receipt.status in setOf(2, 3)
        val merged = mergeStatus(current[0], receipt.status).let {
            if (delivered) mergeStatus(it, 2) else it
        }
        DeviceSyncSourceCapture.suppressDuringImport(db) {
            db.execSQL("UPDATE messages SET status=?,isRead=?,pingDelivered=?,messageDelivered=? " +
                "WHERE messageId=?", arrayOf(
                    merged,
                    if (current[2] == 1 || receipt.status == 3 && current[1] == 0) 1 else 0,
                    if (current[3] == 1 || receipt.pingDelivered) 1 else 0,
                    if (current[4] == 1 || delivered) 1 else 0,
                    receipt.messageId
                ))
        }
        return true
    }

    /** Wire values follow the direct-message protocol; failure is not delivery. */
    fun mergeStatus(current: Int, incoming: Int): Int {
        val rank = intArrayOf(0, 4, 5, 6, 1, 2, 2, 3)
        require(current in rank.indices && incoming in rank.indices)
        return if (rank[incoming] > rank[current]) incoming else current
    }
}
