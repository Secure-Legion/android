package com.securelegion.sync

import android.util.Base64
import android.content.Context
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncLiveCaptureStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import org.json.JSONObject
import java.io.File

/** Turns refreshed source IDs into durable live outbox revisions. */
internal class DeviceSyncLivePublisher(
    private val context: Context,
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val keyManager: KeyManager
) {
    private val capture = DeviceSyncLiveCaptureStore(database, roster)
    private val outbox = DeviceSyncOutboxStore(database, roster)

    fun prepareBatch(account: ByteArray, local: String, peer: String,
                     nowMs: Long = System.currentTimeMillis()) {
        capture.initialize(account, local, peer, true, nowMs)
        capture.discover(account, local, peer, true, nowMs)
        for (work in capture.due(peer, nowMs, 2)) {
            try {
                val delta = if (work.kind == "import")
                    relayDelta(work.topic, work.objectId, nowMs)
                    else if (work.topic == "messages") messageDelta(work.objectId, nowMs)
                    else DeviceSyncReceiptDelta.export(database.openHelper.readableDatabase,
                        work.objectId)
                if (delta != null) queue(account, local, peer, work.topic,
                    work.objectId, delta, nowMs)
                capture.completeWork(peer, work.sequence)
            } catch (_: Exception) { capture.defer(peer, work.sequence, nowMs) }
        }
        val seed = capture.seedIds(peer, 1).firstOrNull() ?: return
        try {
            queue(account, local, peer, "messages", seed, messageDelta(seed, nowMs), nowMs)
            capture.completeSeed(peer, seed)
        } catch (_: Exception) { capture.rotateSeed(peer, seed) }
    }

    private fun relayDelta(topic: String, id: String, nowMs: Long): JSONObject {
        require(topic in setOf("messages", "receipts"))
        val bytes = database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT delta_json FROM device_sync_local_events " +
                "WHERE topic=? AND object_id=?", arrayOf(topic, id)
        )).use { if (it.moveToFirst()) it.getBlob(0) else null }
            ?: throw IllegalStateException("Imported live revision missing")
        try {
            val delta = JSONObject(bytes.toString(Charsets.UTF_8))
            if (topic == "messages") require(DeviceSyncMessageDelta.parse(delta, nowMs).id == id)
            else require(DeviceSyncReceiptDelta.parse(delta).messageId == id)
            return delta
        } finally { bytes.fill(0) }
    }

    private fun messageDelta(id: String, nowMs: Long): JSONObject {
        require(id.isNotEmpty() && id.length <= 256)
        val row = database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT m.encryptedContent,m.isSentByMe,m.timestamp,m.status,m.messageType," +
                "m.isRead,m.isEdited,m.selfDestructAt,m.selfDestructTtl," +
                "m.pingDelivered,m.messageDelivered,m.replyToMessageId," +
                "c.x25519PublicKeyBase64,m.attachmentData,m.voiceFilePath," +
                "m.voiceDuration FROM messages m JOIN contacts c " +
                "ON c.id=m.contactId WHERE m.messageId=? LIMIT 1", arrayOf(id)
        )).use { c ->
            if (!c.moveToFirst()) null else Row(c.getString(0), c.getInt(1) == 1,
                c.getLong(2), c.getInt(3), c.getString(4), c.getInt(5) == 1,
                c.getInt(6) == 1, if (c.isNull(7)) null else c.getLong(7),
                if (c.isNull(8)) null else c.getDouble(8), c.getInt(9) == 1,
                c.getInt(10) == 1, if (c.isNull(11)) null else c.getString(11),
                c.getString(12), if (c.isNull(13)) null else c.getString(13),
                if (c.isNull(14)) null else c.getString(14),
                if (c.isNull(15)) null else c.getInt(15))
        } ?: return JSONObject().put("message_id", id).put("deleted", true)
        if (row.status == 8 || row.expiry != null && row.expiry <= nowMs)
            return JSONObject().put("message_id", id).put("deleted", true)
        require(row.type in setOf("TEXT", "IMAGE", "VOICE") && row.status in 0..7 &&
            Base64.decode(row.contactX, Base64.NO_WRAP).size == 32)
        val delta = JSONObject().put("message_id", id)
            .put("contact_x25519", row.contactX).put("message_type", row.type)
            .put("is_sent_by_me", row.sent).put("timestamp", row.timestamp)
            .put("status", row.status)
            .put("is_read", row.read).put("is_edited", row.edited)
            .put("ping_delivered", row.ping).put("message_delivered", row.delivered)
        when (row.type) {
            "TEXT" -> delta.put("content", keyManager.decryptMessageContent(row.encrypted))
            "IMAGE" -> {
                val bytes = readMedia(row.attachmentData, "image_messages", 4 * 1024 * 1024)
                try {
                    val plain = keyManager.decryptImageFile(bytes)
                    try { delta.put("attachment_type", "image")
                        .put("attachment_data", Base64.encodeToString(plain, Base64.NO_WRAP)) }
                    finally { plain.fill(0) }
                } finally { bytes.fill(0) }
            }
            "VOICE" -> {
                require(row.voiceDuration != null && row.voiceDuration in 0..86_400)
                val bytes = readMedia(row.voicePath, "voice_messages", 5_242_880)
                try {
                    val plain = keyManager.decryptVoiceFile(bytes)
                    try { delta.put("voice_duration", row.voiceDuration)
                        .put("voice_data", Base64.encodeToString(plain, Base64.NO_WRAP)) }
                    finally { plain.fill(0) }
                } finally { bytes.fill(0) }
            }
        }
        row.reply?.let { delta.put("reply_to_message_id", it) }
        row.expiry?.let { delta.put("self_destruct_at", it) }
        row.ttl?.let { delta.put("self_destruct_ttl", it) }
        DeviceSyncMessageDelta.parse(delta, nowMs)
        return delta
    }

    private fun readMedia(path: String?, folder: String, maxBytes: Int): ByteArray {
        require(path != null)
        val root = File(context.filesDir, folder).canonicalFile
        val file = File(path).canonicalFile
        require(file.parentFile == root && file.isFile && file.length() in 29L..(maxBytes + 64L))
        return file.readBytes()
    }

    private fun queue(account: ByteArray, local: String, peer: String, topic: String,
                      id: String, delta: JSONObject, nowMs: Long) {
        require(roster.isLocalAuthorized(account, local, 0x02, nowMs) &&
            roster.isAuthorized(account, peer, 0x02, nowMs))
        val db = database.openHelper.readableDatabase
        val old = db.query(SimpleSQLiteQuery(
            "SELECT event_time_ms,sequence,digest FROM device_sync_local_events " +
                "WHERE topic=? AND object_id=?", arrayOf(topic, id)
        )).use { c -> if (c.moveToFirst()) Old(c.getLong(0), c.getLong(1),
            c.getBlob(2)) else null }
        val bytes = delta.toString().toByteArray(Charsets.UTF_8)
        val candidateTime = maxOf(nowMs, (old?.time ?: 0L) + 1)
        val candidate = RustBridge.deviceHistoryIdentity(bytes, topic, id, candidateTime)
        try {
            require(candidate.size >= 66)
            val unchanged = old != null && candidate.copyOfRange(0, 32)
                .contentEquals(old.digest)
            val time = if (unchanged) old!!.time else candidateTime
            val sequence = if (unchanged) old!!.sequence else (old?.sequence ?: 0L) + 1
            val identity = if (unchanged) RustBridge.deviceHistoryIdentity(bytes,
                topic, id, time) else candidate
            try {
                val eventId = identity.copyOfRange(32, 64).toHex()
                for (table in listOf("device_sync_outbox", "device_sync_acks")) {
                    val existing = db.query(SimpleSQLiteQuery(
                        "SELECT event_id FROM $table WHERE peer_device_id=? " +
                            "AND topic=? AND object_id=?", arrayOf(peer, topic, id)
                    )).use { c -> if (c.moveToFirst()) c.getString(0) else null }
                    if (existing == eventId) return
                }
                val observed = db.query(SimpleSQLiteQuery(
                    "SELECT event_time_ms,digest FROM device_sync_versions WHERE " +
                        "peer_device_id=? AND topic=? AND object_id=?",
                    arrayOf(peer, topic, id)
                )).use { c -> if (c.moveToFirst()) c.getLong(0) to c.getBlob(1)
                    else null }
                if (observed != null && observed.first == time &&
                    observed.second.contentEquals(identity.copyOfRange(0, 32))) return
                outbox.enqueue(account, local, peer, topic, id, time, sequence,
                    identity.copyOfRange(64, identity.size),
                    DeviceSyncOutboxStore.Transport.TOR,
                    isLive = true, liveNegotiated = true, nowMs = nowMs)
            } finally { if (identity !== candidate) identity.fill(0) }
        } finally { candidate.fill(0); bytes.fill(0) }
    }

    private data class Old(val time: Long, val sequence: Long, val digest: ByteArray)
    private data class Row(val encrypted: String, val sent: Boolean,
                           val timestamp: Long, val status: Int, val type: String,
                           val read: Boolean, val edited: Boolean, val expiry: Long?,
                           val ttl: Double?, val ping: Boolean, val delivered: Boolean,
                           val reply: String?, val contactX: String,
                           val attachmentData: String?, val voicePath: String?,
                           val voiceDuration: Int?)
    private fun ByteArray.toHex() = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
