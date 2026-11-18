package com.securelegion.database

import android.content.Context
import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.entities.Contact
import com.securelegion.sync.DeviceTransportFrame

/** One visible C0 chat event and all recipient-device obligations in one commit. */
internal class DeviceChatOutboundStore(
    private val context: Context,
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val localAccount: ByteArray,
    private val encryptText: (String) -> String
) {
    constructor(context: Context, database: SecureLegionDatabase,
                roster: DeviceRosterStore, keyManager: KeyManager) : this(context,
        database, roster, keyManager.getSigningPublicKey(),
        keyManager::encryptDeviceSyncContent)

    /** Seedless linked profiles have wallet-free contacts and a separate view. */
    fun queueLinkedText(recipientAccount: ByteArray, text: String,
                        nowMs: Long = System.currentTimeMillis()): String =
        queueLinkedApplication(recipientAccount, text,
            text.toByteArray(Charsets.UTF_8), 0x00, nowMs = nowMs)

    fun queueLinkedApplication(recipientAccount: ByteArray, text: String,
                               body: ByteArray, type: Int,
                               mediaPath: String? = null,
                               voiceDuration: Int? = null,
                               nowMs: Long = System.currentTimeMillis()): String {
        require(localAccount.size == 32 && recipientAccount.size == 32 &&
            !localAccount.contentEquals(recipientAccount) &&
            type in setOf(0x00, 0x02, 0x01))
        val messageType = when (type) {
            0x00 -> "TEXT"
            0x02 -> "IMAGE"
            else -> "VOICE"
        }
        if (messageType == "TEXT") require(text.isNotBlank() &&
            text.toByteArray(Charsets.UTF_8).size <= 65_536 &&
            body.contentEquals(text.toByteArray(Charsets.UTF_8)) &&
            mediaPath == null && voiceDuration == null)
        else require(text.isEmpty() && mediaPath != null &&
            mediaPath.startsWith(context.filesDir.canonicalPath +
                java.io.File.separator) &&
            (messageType == "IMAGE" && body.size in 1..4 * 1024 * 1024 &&
                voiceDuration == null || messageType == "VOICE" &&
                body.size in 5..(5 * 1024 * 1024 + 4) &&
                voiceDuration != null && voiceDuration in 1..600))
        val signedRoster = roster.fetchSignedRoster(recipientAccount)
            ?: throw IllegalStateException("Recipient device roster unavailable")
        val recipient = Base64.encodeToString(recipientAccount, Base64.NO_WRAP)
        LocalDeviceIdentity.loadExisting(context).use { identity ->
            require(roster.isLocalAuthorized(localAccount, identity.deviceId, 0x01, nowMs))
            val peers = roster.listAuthorizedDevices(recipientAccount).filter {
                it.capabilities and 0x01 != 0 && it.expiresAtMs > nowMs
            }
            require(peers.isNotEmpty() && peers.size <= 8)
            val sessions = DeviceTransportSessionStore(database, roster)
            val sessionIds = peers.associate { peer ->
                peer.deviceId to sessions.request(localAccount, recipientAccount,
                    peer.deviceId, identity, nowMs).sessionId
            }
            val job = DeviceTransportFrame.randomId()
            val logical = DeviceTransportFrame.logicalId(localAccount, identity.deviceId, job)
            val envelope = ByteArray(14 + body.size)
            envelope[0] = 1
            for (i in 0..7) envelope[1 + i] =
                (nowMs ushr ((7 - i) * 8)).toByte()
            envelope[13] = type.toByte()
            body.copyInto(envelope, 14)
            val db = database.openHelper.writableDatabase
            db.beginTransaction()
            try {
                val current = db.query(SimpleSQLiteQuery(
                    "SELECT signedRoster FROM device_rosters WHERE accountEd=?",
                    arrayOf(recipient))).use {
                    if (it.moveToFirst()) it.getBlob(0) else null
                }
                require(current != null && current.contentEquals(signedRoster) &&
                    roster.isLocalAuthorized(localAccount, identity.deviceId, 0x01, nowMs) &&
                    peers.all { roster.isAuthorized(recipientAccount, it.deviceId, 0x01, nowMs) })
                val contact = db.query(SimpleSQLiteQuery(
                    "SELECT 1 FROM linked_chat_contacts WHERE account_ed=? AND blocked=0",
                    arrayOf(recipient))).use { it.moveToFirst() }
                require(contact) { "Linked contact changed while queueing" }
                val capacity = db.query(SimpleSQLiteQuery(
                    "SELECT COUNT(*),COALESCE(SUM(COALESCE(length(plaintext),0)+" +
                        "COALESCE(length(wire),0)),0) FROM device_transport_jobs"
                )).use { check(it.moveToFirst()); it.getLong(0) to it.getLong(1) }
                require(capacity.first + peers.size <= 256 &&
                    capacity.second + envelope.size.toLong() * peers.size <=
                        64L * 1024 * 1024) { "Transport queue full" }
                for (peer in peers) db.execSQL("INSERT INTO device_transport_jobs " +
                    "(account_ed,peer_device_id,local_device_id,job_id,logical_id," +
                    "session_id,plaintext,created_at_ms) VALUES (?,?,?,?,?,?,?,?)",
                    arrayOf(recipient, peer.deviceId, identity.deviceId, job, logical,
                        sessionIds.getValue(peer.deviceId), envelope, nowMs))
                db.execSQL("INSERT INTO linked_chat_messages (message_id,account_ed," +
                    "encrypted_content,type,sent_by_me,timestamp_ms,status," +
                    "media_path,voice_duration,read,edited,imported) " +
                    "VALUES (?,?,?,?,1,?,0,?,?,0,0,0)",
                    arrayOf(logical, recipient,
                        if (messageType == "TEXT") encryptText(text) else "",
                        messageType, nowMs, mediaPath, voiceDuration))
                db.execSQL("INSERT INTO device_sync_source_changes " +
                    "(topic,object_id,kind,changed_at_ms) " +
                    "VALUES ('messages',?,'body',?)", arrayOf(logical, nowMs))
                db.setTransactionSuccessful()
                return logical
            } finally { db.endTransaction(); envelope.fill(0) }
        }
    }

    fun queueApplication(contact: Contact, text: String, body: ByteArray,
                  type: Int, ttlMs: Long?, readReceipt: Boolean,
                  replyTo: String? = null,
                  mediaPath: String? = null, voiceDuration: Int? = null,
                  nowMs: Long = System.currentTimeMillis()): String {
        val recipientAccount = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)
        require(localAccount.size == 32 && recipientAccount.size == 32 &&
            !localAccount.contentEquals(recipientAccount) &&
            contact.friendshipStatus == "CONFIRMED" && !contact.isBlocked &&
            type in setOf(0x00, 0x11, 0x01, 0x02) &&
            body.isNotEmpty() && body.size <= 5 * 1024 * 1024 + 4 &&
            (ttlMs == null || ttlMs in 1_000L..604_800_000L))
        val messageType = when (type) {
            0x00, 0x11 -> "TEXT"
            0x02 -> "IMAGE"
            else -> "VOICE"
        }
        if (messageType == "TEXT") require(text.isNotBlank() &&
            text.toByteArray(Charsets.UTF_8).size <= 65_536 && body.size <= 67_000 &&
            mediaPath == null && voiceDuration == null)
        else require(text.isEmpty() && mediaPath != null &&
            mediaPath.startsWith(context.filesDir.canonicalPath + java.io.File.separator) &&
            (messageType == "IMAGE" && body.size <= 4 * 1024 * 1024 &&
                voiceDuration == null || messageType == "VOICE" &&
                voiceDuration != null && voiceDuration in 1..600 &&
                body.size in 5..(5 * 1024 * 1024 + 4)))
        val signedRoster = roster.fetchSignedRoster(recipientAccount)
            ?: throw IllegalStateException("Recipient device roster unavailable")
        LocalDeviceIdentity.loadExisting(context).use { identity ->
            require(roster.isLocalAuthorized(localAccount, identity.deviceId, 0x01, nowMs))
            val peers = roster.listAuthorizedDevices(recipientAccount)
                .filter { it.capabilities and 0x01 != 0 && it.expiresAtMs > nowMs }
            require(peers.isNotEmpty() && peers.size <= 8) {
                "No authorized recipient devices"
            }
            val sessions = DeviceTransportSessionStore(database, roster)
            val sessionIds = peers.associate { peer ->
                require(roster.isAuthorized(recipientAccount, peer.deviceId, 0x01, nowMs))
                peer.deviceId to sessions.request(localAccount, recipientAccount,
                    peer.deviceId, identity, nowMs).sessionId
            }
            val job = DeviceTransportFrame.randomId()
            val logical = DeviceTransportFrame.logicalId(localAccount, identity.deviceId, job)
            val envelope = ByteArray(14 + body.size)
            envelope[0] = 1
            for (i in 0..7) envelope[1 + i] =
                (nowMs ushr ((7 - i) * 8)).toByte()
            val ttl = ttlMs ?: 0L
            for (i in 0..3) envelope[9 + i] =
                (ttl ushr ((3 - i) * 8)).toByte()
            envelope[13] = type.toByte()
            body.copyInto(envelope, 14)
            val db = database.openHelper.writableDatabase
            db.beginTransaction()
            try {
                val currentRoster = db.query(SimpleSQLiteQuery(
                    "SELECT signedRoster FROM device_rosters WHERE accountEd=?",
                    arrayOf(Base64.encodeToString(recipientAccount, Base64.NO_WRAP))
                )).use { if (it.moveToFirst()) it.getBlob(0) else null }
                require(currentRoster != null && currentRoster.contentEquals(signedRoster)) {
                    "Recipient roster changed while queueing"
                }
                require(roster.isLocalAuthorized(localAccount, identity.deviceId, 0x01,
                    nowMs) && peers.all { roster.isAuthorized(recipientAccount,
                    it.deviceId, 0x01, nowMs) })
                val pinned = db.query(SimpleSQLiteQuery(
                    "SELECT 1 FROM contacts WHERE id=? AND publicKeyBase64=? " +
                        "AND friendshipStatus='CONFIRMED' AND isBlocked=0",
                    arrayOf(contact.id, contact.publicKeyBase64)
                )).use { it.moveToFirst() }
                require(pinned) { "Contact changed while queueing" }
                val capacity = db.query(SimpleSQLiteQuery(
                    "SELECT COUNT(*),COALESCE(SUM(COALESCE(length(plaintext),0)+" +
                        "COALESCE(length(wire),0)),0) " +
                        "FROM device_transport_jobs"
                )).use { check(it.moveToFirst()); it.getLong(0) to it.getLong(1) }
                require(capacity.first + peers.size <= 256 &&
                    capacity.second + envelope.size.toLong() * peers.size <= 64L * 1024 * 1024) {
                    "Transport queue full"
                }
                for (peer in peers) db.execSQL("INSERT INTO device_transport_jobs " +
                    "(account_ed,peer_device_id,local_device_id,job_id,logical_id," +
                    "session_id,plaintext,created_at_ms) VALUES (?,?,?,?,?,?,?,?)",
                    arrayOf(Base64.encodeToString(recipientAccount, Base64.NO_WRAP),
                        peer.deviceId, identity.deviceId, job, logical,
                        sessionIds.getValue(peer.deviceId), envelope, nowMs))
                db.execSQL("INSERT INTO messages " +
                    "(contactId,messageId,encryptedContent,isSentByMe,timestamp,status," +
                    "signatureBase64,nonceBase64,messageNonce,messageType,isRead," +
                    "requiresReadReceipt,retryCount,pingDelivered,messageDelivered,tapDelivered," +
                    "isEdited,attachmentType,attachmentData,voiceDuration,voiceFilePath," +
                    "replyToMessageId,selfDestructTtl,isPinned,isDeviceSyncImported) " +
                    "VALUES (?,?,?,1,?,0,'','',0,?,0,?,0,0,0,0,0,?,?,?,?,?,?,0,0)",
                    arrayOf(contact.id, logical, if (messageType == "TEXT")
                        encryptText(text) else "", nowMs,
                        messageType, if (readReceipt) 1 else 0,
                        if (messageType == "IMAGE") "image" else null,
                        if (messageType == "IMAGE") mediaPath else null,
                        voiceDuration, if (messageType == "VOICE") mediaPath else null, replyTo,
                        if (ttlMs == null) null else ttlMs.toDouble() / 1_000.0))
                db.setTransactionSuccessful()
                return logical
            } finally { db.endTransaction(); envelope.fill(0) }
        }
    }
}
