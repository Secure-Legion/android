package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Transactional C0 application import. Unsupported types are never acknowledged. */
internal class DeviceChatPayloadStore(
    private val encryptForLocalProfile: (String) -> String
) {
    fun apply(db: SupportSQLiteDatabase, senderAccount: ByteArray,
              logicalId: String, plaintext: ByteArray,
              nowMs: Long = System.currentTimeMillis()): Boolean {
        require(db.inTransaction() && senderAccount.size == 32 &&
            logicalId.matches(Regex("dev_[A-Za-z0-9_-]{43}")) &&
            plaintext.size in 15..(5 * 1024 * 1024 + 64) && plaintext[0] == 1.toByte())
        val timestamp = readU64(plaintext, 1)
        val ttl = readU32(plaintext, 9)
        require(timestamp in 1..DeviceTransportFrame.MAX_COUNTER &&
            timestamp <= nowMs + 300_000L &&
            (ttl == 0L || ttl in 1_000L..604_800_000L))
        val contact = db.query(SimpleSQLiteQuery(
            "SELECT id FROM contacts WHERE publicKeyBase64=? AND isBlocked=0 " +
                "AND friendshipStatus='CONFIRMED' LIMIT 1",
            arrayOf(Base64.encodeToString(senderAccount, Base64.NO_WRAP))
        )).use { if (it.moveToFirst()) it.getLong(0) else null }
            ?: throw IllegalArgumentException("Unknown C0 contact")
        val type = plaintext[13].toInt() and 0xff
        require(type == 0x00) { "C0 payload type is not supported yet" }
        val body = plaintext.copyOfRange(14, plaintext.size)
        val content = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(body)).toString()
        require(body.size <= 65_536 && content.isNotBlank())
        val existing = db.query(SimpleSQLiteQuery(
            "SELECT contactId,isSentByMe,messageType FROM messages WHERE messageId=? LIMIT 1",
            arrayOf(logicalId)
        )).use { c -> if (!c.moveToFirst()) null else Triple(c.getLong(0),
            c.getInt(1), c.getString(2)) }
        if (existing != null) {
            require(existing.first == contact && existing.second == 0 &&
                existing.third == "TEXT") { "C0 message identity conflict" }
            return true
        }
        db.execSQL("INSERT INTO messages " +
            "(contactId,messageId,encryptedContent,isSentByMe,timestamp,status," +
            "signatureBase64,nonceBase64,messageNonce,messageType,isRead," +
            "requiresReadReceipt,retryCount,pingDelivered,messageDelivered,tapDelivered,isEdited," +
            "selfDestructTtl,isPinned,isDeviceSyncImported) " +
            "VALUES (?,?,?,0,?,2,'','',0,'TEXT',0,0,0,0,1,0,0,?,0,0)",
            arrayOf(contact, logicalId, encryptForLocalProfile(content),
                timestamp, if (ttl == 0L) null else ttl.toDouble() / 1_000.0))
        return true
    }

    private fun readU64(bytes: ByteArray, start: Int): Long =
        (0..7).fold(0L) { n, i -> (n shl 8) or (bytes[start + i].toLong() and 0xff) }
    private fun readU32(bytes: ByteArray, start: Int): Long =
        (0..3).fold(0L) { n, i -> (n shl 8) or (bytes[start + i].toLong() and 0xff) }
}
