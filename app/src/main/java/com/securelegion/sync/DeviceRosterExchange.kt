package com.securelegion.sync

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Build-48 A4 signed roster distribution and A5 committed-hash receipts. */
class DeviceRosterExchange(
    private val database: SecureLegionDatabase,
    private val rosterStore: DeviceRosterStore
) {
    data class Reply(val wire: ByteArray, val onion: String)
    data class Pending(val peerDeviceId: String, val onion: String, val wire: ByteArray,
                       val rosterHash: ByteArray, val attempts: Int)
    data class ContactBootstrap(val contactAccount: String, val onion: String,
                                val wire: ByteArray, val rosterHash: ByteArray)

    fun acceptUpdate(wire: ByteArray, pinnedAccount: ByteArray,
                     identity: LocalDeviceIdentity,
                     nowMs: Long = System.currentTimeMillis()): Reply? {
        require(isStructurallyValid(wire) && wire[0].toInt() and 0xff == A4)
        require(pinnedAccount.size == 32)
        val owner = wire.copyOfRange(11, 43)
        require(owner.contentEquals(pinnedAccount) || isAcceptedContact(owner))
        val signed = wire.copyOfRange(5, wire.size)
        val ownRoster = owner.contentEquals(pinnedAccount)
        val previous = rosterStore.fetchSignedRoster(owner)
        val accepted = rosterStore.acceptSignedRoster(signed, owner,
            if (ownRoster) identity.deviceId else null, nowMs)
        if (!ownRoster && (previous == null || !previous.contentEquals(signed)))
            wakeContactBootstrap(pinnedAccount, owner)
        if (accepted.primaryDeviceId == identity.deviceId) return null
        val primary = rosterStore.authorizedPeer(owner, accepted.primaryDeviceId, 0x07, nowMs)
            ?: throw IllegalArgumentException("Missing primary device")
        return Reply(acknowledgmentFrame(owner, pinnedAccount, identity.deviceId,
            MessageDigest.getInstance("SHA-256").digest(signed), identity), primary.onion)
    }

    /** Claim up to four due public announcements before attempting socket writes. */
    fun contactBootstraps(localAccount: ByteArray, nowMs: Long = System.currentTimeMillis(),
                          reconnect: Boolean = false,
                          targetAccount: ByteArray? = null): List<ContactBootstrap> {
        require(localAccount.size == 32)
        require(targetAccount == null || targetAccount.size == 32)
        ensureBootstrapTable()
        val signed = rosterStore.fetchSignedRoster(localAccount) ?: return emptyList()
        val hash = MessageDigest.getInstance("SHA-256").digest(signed)
        val wire = updateFrame(signed)
        val local = Base64.encodeToString(localAccount, Base64.NO_WRAP)
        val target = targetAccount?.let { Base64.encodeToString(it, Base64.NO_WRAP) } ?: ""
        val db = database.openHelper.writableDatabase
        val rows = db.query(SimpleSQLiteQuery(
            "SELECT c.publicKeyBase64,c.messagingOnion,b.roster_hash,b.onion,b.attempts,b.acked,b.next_try_at_ms " +
                "FROM contacts c LEFT JOIN device_roster_contact_bootstrap b " +
                "ON b.owner_account=? AND b.contact_account=c.publicKeyBase64 " +
                "WHERE c.friendshipStatus='CONFIRMED' " +
                "AND c.isBlocked=0 AND c.publicKeyBase64<>? AND " +
                "(?='' OR c.publicKeyBase64=?) AND length(c.messagingOnion)=62 " +
                "AND (b.contact_account IS NULL OR b.roster_hash<>? OR " +
                "b.onion<>c.messagingOnion OR (b.acked=0 AND " +
                "(b.next_try_at_ms<=? OR ?=1))) " +
                "ORDER BY COALESCE(b.next_try_at_ms,0),c.id LIMIT 16",
            arrayOf<Any>(local, local, target, target, hash, nowMs, if (reconnect) 1 else 0)
        )).use { cursor ->
            buildList {
                while (cursor.moveToNext()) {
                    val onion = cursor.getString(1)
                    if (!ONION.matches(onion)) continue
                    val priorHash = if (cursor.isNull(2)) null else cursor.getBlob(2)
                    val priorOnion = if (cursor.isNull(3)) null else cursor.getString(3)
                    val current = priorHash != null && MessageDigest.isEqual(hash, priorHash) &&
                        priorOnion == onion
                    val acked = current && cursor.getInt(5) != 0
                    val due = !current || reconnect || cursor.getLong(6) <= nowMs
                    if (!acked && due) add(Triple(cursor.getString(0), onion,
                        if (current) cursor.getInt(4) else 0))
                    if (size == 4) break
                }
            }
        }
        val delays = longArrayOf(2_000, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000)
        db.beginTransaction()
        try {
            for ((contact, onion, attempts) in rows) {
                val next = nowMs + delays[attempts.coerceIn(0, delays.lastIndex)]
                db.execSQL("INSERT OR REPLACE INTO device_roster_contact_bootstrap " +
                    "(owner_account,contact_account,onion,roster_hash,next_try_at_ms," +
                    "attempts,acked) VALUES (?,?,?,?,?,?,0)",
                    arrayOf(local, contact, onion, hash, next, attempts + 1))
            }
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
        return rows.map { (contact, onion, _) -> ContactBootstrap(contact, onion, wire, hash) }
    }

    fun canSendBootstrap(localAccount: ByteArray, localDeviceId: String,
                         item: ContactBootstrap): Boolean {
        if (!rosterStore.isLocalAuthorized(localAccount, localDeviceId, 0x02) ||
            !ONION.matches(item.onion)) return false
        val account = Base64.decode(item.contactAccount, Base64.NO_WRAP)
        if (!isAcceptedContact(account)) return false
        val signed = rosterStore.fetchSignedRoster(localAccount) ?: return false
        if (!MessageDigest.isEqual(item.rosterHash,
                MessageDigest.getInstance("SHA-256").digest(signed)) ||
            !item.wire.contentEquals(updateFrame(signed))) return false
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT 1 FROM contacts c JOIN device_roster_contact_bootstrap b " +
                "ON b.contact_account=c.publicKeyBase64 WHERE b.owner_account=? " +
                "AND c.publicKeyBase64=? " +
                "AND c.friendshipStatus='CONFIRMED' AND c.isBlocked=0 " +
                "AND c.messagingOnion=? AND b.onion=? AND b.roster_hash=? AND b.acked=0 LIMIT 1",
            arrayOf(Base64.encodeToString(localAccount, Base64.NO_WRAP),
                item.contactAccount, item.onion, item.onion, item.rosterHash)
        )).use { it.moveToFirst() }
    }

    fun canSendReply(localAccount: ByteArray, localDeviceId: String, reply: Reply): Boolean {
        val wire = reply.wire
        if (!isStructurallyValid(wire) || wire[0].toInt() and 255 != A5 ||
            !wire.copyOfRange(38, 70).contentEquals(localAccount) ||
            !rosterStore.isLocalAuthorized(localAccount, localDeviceId, 0x02)) return false
        val owner = wire.copyOfRange(6, 38)
        if (!owner.contentEquals(localAccount) && !isAcceptedContact(owner)) return false
        val signed = rosterStore.fetchSignedRoster(owner) ?: return false
        if (!MessageDigest.isEqual(wire.copyOfRange(102, 134),
                MessageDigest.getInstance("SHA-256").digest(signed))) return false
        val primary = database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT primaryDeviceId FROM device_rosters WHERE accountEd=?",
            arrayOf(Base64.encodeToString(owner, Base64.NO_WRAP))
        )).use { if (it.moveToFirst()) it.getString(0) else null } ?: return false
        return rosterStore.authorizedPeer(owner, primary, 0x07)?.onion == reply.onion
    }

    fun pendingNotifications(pinnedAccount: ByteArray,
                             nowMs: Long = System.currentTimeMillis(), limit: Int = 16): List<Pending> {
        require(pinnedAccount.size == 32 && limit in 1..64)
        val signed = rosterStore.fetchSignedRoster(pinnedAccount) ?: return emptyList()
        val hash = MessageDigest.getInstance("SHA-256").digest(signed)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        val rows = database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT peer_device_id,onion,roster_hash,attempts FROM device_roster_notifications " +
                "WHERE account_ed=? AND next_try_at_ms<=? ORDER BY next_try_at_ms,peer_device_id LIMIT ?",
            arrayOf(account, nowMs, limit)
        )).use { cursor ->
            buildList {
                while (cursor.moveToNext()) {
                    val rowHash = cursor.getBlob(2)
                    if (MessageDigest.isEqual(rowHash, hash)) add(Pending(cursor.getString(0),
                        cursor.getString(1), updateFrame(signed), rowHash, cursor.getInt(3)))
                }
            }
        }
        return rows
    }

    /** A socket write schedules the next retry. Only a valid A5 removes the row. */
    fun recordAttempt(pinnedAccount: ByteArray, pending: Pending,
                      nowMs: Long = System.currentTimeMillis()) {
        require(pinnedAccount.size == 32)
        val delays = longArrayOf(2_000, 5_000, 10_000, 30_000, 60_000, 120_000)
        val next = nowMs + delays[pending.attempts.coerceIn(0, delays.lastIndex)]
        database.openHelper.writableDatabase.execSQL(
            "UPDATE device_roster_notifications SET attempts=attempts+1,next_try_at_ms=? " +
                "WHERE account_ed=? AND peer_device_id=? AND roster_hash=?",
            arrayOf(next, Base64.encodeToString(pinnedAccount, Base64.NO_WRAP),
                pending.peerDeviceId, pending.rosterHash))
    }

    fun acceptAcknowledgment(wire: ByteArray, pinnedAccount: ByteArray): Boolean {
        if (!isStructurallyValid(wire) || wire[0].toInt() and 0xff != A5 ||
            pinnedAccount.size != 32 || !wire.copyOfRange(6, 38).contentEquals(pinnedAccount)) return false
        val peerAccount = wire.copyOfRange(38, 70)
        val deviceId = Base64.encodeToString(wire.copyOfRange(70, 102),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val hash = wire.copyOfRange(102, 134)
        val signature = wire.copyOfRange(134, 198)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        val db = database.openHelper.writableDatabase
        if (!peerAccount.contentEquals(pinnedAccount)) {
            if (!isAcceptedContact(peerAccount)) return false
            ensureBootstrapTable()
            val peerAccountB64 = Base64.encodeToString(peerAccount, Base64.NO_WRAP)
            db.beginTransaction()
            try {
                val pending = db.query(SimpleSQLiteQuery(
                    "SELECT roster_hash FROM device_roster_contact_bootstrap " +
                    "WHERE owner_account=? AND contact_account=? AND acked=0",
                    arrayOf(Base64.encodeToString(pinnedAccount, Base64.NO_WRAP), peerAccountB64)
                )).use { if (it.moveToFirst()) it.getBlob(0) else null } ?: return false
                val signedRoster = rosterStore.fetchSignedRoster(pinnedAccount) ?: return false
                if (!MessageDigest.isEqual(hash, pending) || !MessageDigest.isEqual(hash,
                        MessageDigest.getInstance("SHA-256").digest(signedRoster))) return false
                val peer = rosterStore.authorizedPeer(peerAccount, deviceId, 0x02) ?: return false
                if (!RustBridge.verifySignature(ACK_DOMAIN + wire.copyOfRange(0, 134),
                        signature, peer.signingKey)) return false
                val update = db.compileStatement("UPDATE device_roster_contact_bootstrap " +
                    "SET acked=1,ack_peer_device_id=? WHERE owner_account=? " +
                    "AND contact_account=? AND roster_hash=? AND acked=0")
                update.bindString(1, deviceId)
                update.bindString(2, Base64.encodeToString(pinnedAccount, Base64.NO_WRAP))
                update.bindString(3, peerAccountB64)
                update.bindBlob(4, hash)
                if (update.executeUpdateDelete() != 1) return false
                db.setTransactionSuccessful()
                return true
            } finally { db.endTransaction() }
        }
        db.beginTransaction()
        try {
            val pending = db.query(SimpleSQLiteQuery(
                "SELECT signing_key,roster_hash FROM device_roster_notifications " +
                    "WHERE account_ed=? AND peer_device_id=?",
                arrayOf(account, deviceId)
            )).use { if (it.moveToFirst()) it.getBlob(0) to it.getBlob(1) else null }
                ?: return false
            if (!MessageDigest.isEqual(hash, pending.second) || pending.first.size != 32) return false
            val current = rosterStore.authorizedPeer(pinnedAccount, deviceId, 0x02)
                ?: return false
            if (!MessageDigest.isEqual(pending.first, current.signingKey)) return false
            val signed = ACK_DOMAIN + wire.copyOfRange(0, 134)
            if (!RustBridge.verifySignature(signed, signature, pending.first)) return false
            db.execSQL("DELETE FROM device_roster_notifications WHERE account_ed=? " +
                "AND peer_device_id=? AND roster_hash=?",
                arrayOf(account, deviceId, hash))
            db.setTransactionSuccessful()
            return true
        } finally { db.endTransaction() }
    }

    private fun isAcceptedContact(accountEd: ByteArray): Boolean {
        if (accountEd.size != 32) return false
        val account = Base64.encodeToString(accountEd, Base64.NO_WRAP)
        val db = database.openHelper.readableDatabase
        if (db.query(SimpleSQLiteQuery("SELECT 1 FROM contacts WHERE publicKeyBase64=? " +
                "AND friendshipStatus='CONFIRMED' AND isBlocked=0 LIMIT 1", arrayOf(account)
            )).use { it.moveToFirst() }) return true
        return runCatching {
            db.query(SimpleSQLiteQuery("SELECT 1 FROM linked_chat_contacts WHERE account_ed=? " +
                "AND blocked=0 LIMIT 1", arrayOf(account)
            )).use { it.moveToFirst() }
        }.getOrDefault(false)
    }

    private fun ensureBootstrapTable() {
        database.openHelper.writableDatabase.execSQL(
            "CREATE TABLE IF NOT EXISTS device_roster_contact_bootstrap (" +
                "owner_account TEXT NOT NULL,contact_account TEXT NOT NULL,onion TEXT NOT NULL," +
                "roster_hash BLOB NOT NULL,next_try_at_ms INTEGER NOT NULL," +
                "attempts INTEGER NOT NULL DEFAULT 0,acked INTEGER NOT NULL DEFAULT 0," +
                "ack_peer_device_id TEXT,PRIMARY KEY(owner_account,contact_account))")
    }

    private fun wakeContactBootstrap(localAccount: ByteArray, contactAccount: ByteArray) {
        ensureBootstrapTable()
        database.openHelper.writableDatabase.execSQL(
            "UPDATE device_roster_contact_bootstrap SET next_try_at_ms=0,acked=0 " +
                "WHERE owner_account=? AND contact_account=?",
            arrayOf(Base64.encodeToString(localAccount, Base64.NO_WRAP),
                Base64.encodeToString(contactAccount, Base64.NO_WRAP)))
    }

    companion object {
        private const val A4 = 0xA4
        private const val A5 = 0xA5
        private val ACK_DOMAIN = "Secure-DEVICE-ROSTER-v1/committed\u0000"
            .toByteArray(Charsets.UTF_8)

        fun updateFrame(signedRoster: ByteArray): ByteArray {
            require(signedRoster.size in 38..32 * 1024 &&
                signedRoster.copyOfRange(0, 6).contentEquals("SLDR01".toByteArray(Charsets.US_ASCII)))
            return wrap(A4, signedRoster)
        }

        fun isStructurallyValid(wire: ByteArray): Boolean {
            if (wire.size !in 43..32_773) return false
            val type = wire[0].toInt() and 0xff
            if (type != A4 && type != A5) return false
            if (ByteBuffer.wrap(wire, 1, 4).int != wire.size - 5) return false
            return if (type == A5) wire.size == 198 && wire[5].toInt() == 1 else
                wire.copyOfRange(5, 11).contentEquals("SLDR01".toByteArray(Charsets.US_ASCII))
        }

        private val ONION = Regex("[a-z2-7]{56}\\.onion")

        fun acknowledgmentFrame(accountEd: ByteArray, acknowledgingAccount: ByteArray,
                                localDeviceId: String,
                                rosterHash: ByteArray, identity: LocalDeviceIdentity): ByteArray {
            require(accountEd.size == 32 && acknowledgingAccount.size == 32 &&
                rosterHash.size == 32 &&
                localDeviceId == identity.deviceId)
            val deviceBytes = Base64.decode(localDeviceId,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            require(deviceBytes.size == 32)
            val body = byteArrayOf(1) + accountEd + acknowledgingAccount +
                deviceBytes + rosterHash + ByteArray(64)
            val wire = wrap(A5, body)
            val signature = identity.sign(ACK_DOMAIN + wire.copyOfRange(0, 134))
            require(signature.size == 64)
            signature.copyInto(wire, 134)
            return wire
        }

        private fun wrap(type: Int, body: ByteArray): ByteArray =
            byteArrayOf(type.toByte()) + ByteBuffer.allocate(4).putInt(body.size).array() + body
    }
}
