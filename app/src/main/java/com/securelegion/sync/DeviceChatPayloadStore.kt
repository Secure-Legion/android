package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.LinkedChatStore
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import org.json.JSONObject

/** Transactional C0 application import. Unsupported types are never acknowledged. */
internal class DeviceChatPayloadStore(
    private val encryptForLocalProfile: (String) -> String,
    private val storeMedia: (String, String, ByteArray) -> String = { _, _, _ ->
        throw IllegalArgumentException("C0 media storage unavailable")
    },
    private val linked: LinkedChatStore? = null
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
        val contact = if (linked != null) null else db.query(SimpleSQLiteQuery(
            "SELECT id FROM contacts WHERE publicKeyBase64=? AND isBlocked=0 " +
                "AND friendshipStatus='CONFIRMED' LIMIT 1",
            arrayOf(Base64.encodeToString(senderAccount, Base64.NO_WRAP))
        )).use { if (it.moveToFirst()) it.getLong(0) else null }
            ?: if (linked == null) throw IllegalArgumentException("Unknown C0 contact") else null
        val type = plaintext[13].toInt() and 0xff
        val messageType = when (type) {
            0x00, 0x11 -> "TEXT"
            0x02 -> "IMAGE"
            0x01 -> "VOICE"
            else -> throw IllegalArgumentException("Unsupported C0 payload type")
        }
        val body = plaintext.copyOfRange(14, plaintext.size)
        val existing = if (linked != null) null else db.query(SimpleSQLiteQuery(
            "SELECT contactId,isSentByMe,messageType,timestamp " +
                "FROM messages WHERE messageId=? LIMIT 1",
            arrayOf(logicalId)
        )).use { c -> if (!c.moveToFirst()) null else listOf(c.getLong(0),
            c.getInt(1).toLong(), c.getString(2), c.getLong(3)) }
        if (existing != null) {
            require(existing[0] == contact && existing[1] == 0L &&
                existing[2] == messageType && existing[3] == timestamp) {
                "C0 message identity conflict"
            }
            return false
        }
        val content: String
        var replyTo: String? = null
        var mediaPath: String? = null
        var duration: Int? = null
        when (type) {
            0x00 -> {
                require(body.size <= 65_536)
                content = strictUtf8(body)
                require(content.isNotBlank())
            }
            0x11 -> {
                require(body.size <= 67_000)
                val objectValue = JSONObject(strictUtf8(body))
                require(objectValue.keys().asSequence().toSet() in setOf(
                    setOf("text", "reply_to_message_id", "reply_to_text", "reply_to_self"),
                    setOf("text", "reply_to_message_id", "reply_to_text", "reply_to_self",
                        "reply_to_blob_id")))
                require(objectValue.opt("text") is String &&
                    objectValue.opt("reply_to_message_id") is String &&
                    objectValue.opt("reply_to_text") is String &&
                    objectValue.opt("reply_to_self") is Boolean)
                content = objectValue.getString("text")
                val target = objectValue.getString("reply_to_message_id")
                val quote = objectValue.getString("reply_to_text")
                val self = objectValue.getBoolean("reply_to_self")
                val blob = if (objectValue.has("reply_to_blob_id")) {
                    require(objectValue.opt("reply_to_blob_id") is String)
                    objectValue.getString("reply_to_blob_id")
                } else ""
                require(content.isNotBlank() && content.toByteArray().size <= 65_536 &&
                    target.isNotEmpty() && target.length <= 256 && quote.length <= 1_024 &&
                    blob.length <= 256)
                replyTo = "$target||${if (self) "S" else "R"}||$blob||$quote"
            }
            0x02 -> {
                require(body.size in 1..4 * 1024 * 1024)
                content = ""
                mediaPath = storeMedia("IMAGE", logicalId, body.copyOf())
            }
            0x01 -> {
                require(body.size in 5..(5 * 1024 * 1024 + 4))
                val seconds = readU32(body, 0)
                require(seconds in 1..600)
                duration = seconds.toInt()
                content = ""
                mediaPath = storeMedia("VOICE", logicalId,
                    body.copyOfRange(4, body.size))
            }
            else -> error("Validated above")
        }
        if (linked != null) return linked.applyDirect(db, senderAccount,
            logicalId, content, messageType, timestamp, mediaPath, duration, replyTo)
        db.execSQL("INSERT INTO messages " +
            "(contactId,messageId,encryptedContent,isSentByMe,timestamp,status," +
            "signatureBase64,nonceBase64,messageNonce,messageType,isRead," +
            "requiresReadReceipt,retryCount,pingDelivered,messageDelivered,tapDelivered,isEdited," +
            "attachmentType,attachmentData,voiceDuration,voiceFilePath,replyToMessageId," +
            "selfDestructTtl,isPinned,isDeviceSyncImported) " +
            "VALUES (?,?,?,0,?,2,'','',0,?,0,0,0,0,1,0,0,?,?,?,?,?,?,0,0)",
            arrayOf(requireNotNull(contact), logicalId, if (content.isEmpty()) "" else
                encryptForLocalProfile(content), timestamp, messageType,
                if (messageType == "IMAGE") "image" else null,
                if (messageType == "IMAGE") mediaPath else null,
                duration, if (messageType == "VOICE") mediaPath else null,
                replyTo, if (ttl == 0L) null else ttl.toDouble() / 1_000.0))
        return false
    }

    private fun strictUtf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()

    private fun readU64(bytes: ByteArray, start: Int): Long =
        (0..7).fold(0L) { n, i -> (n shl 8) or (bytes[start + i].toLong() and 0xff) }
    private fun readU32(bytes: ByteArray, start: Int): Long =
        (0..3).fold(0L) { n, i -> (n shl 8) or (bytes[start + i].toLong() and 0xff) }
}
