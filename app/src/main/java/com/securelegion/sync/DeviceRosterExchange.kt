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

    fun acceptUpdate(wire: ByteArray, pinnedAccount: ByteArray,
                     identity: LocalDeviceIdentity,
                     nowMs: Long = System.currentTimeMillis()): Reply? {
        require(isStructurallyValid(wire) && wire[0].toInt() and 0xff == A4)
        require(pinnedAccount.size == 32 && wire.copyOfRange(11, 43).contentEquals(pinnedAccount))
        val signed = wire.copyOfRange(5, wire.size)
        val accepted = rosterStore.acceptSignedRoster(signed, pinnedAccount,
            identity.deviceId, nowMs)
        if (accepted.primaryDeviceId == identity.deviceId) return null
        val primary = rosterStore.authorizedPeer(pinnedAccount, accepted.primaryDeviceId, 0x07, nowMs)
            ?: throw IllegalArgumentException("Missing primary device")
        return Reply(acknowledgmentFrame(pinnedAccount, identity.deviceId,
            MessageDigest.getInstance("SHA-256").digest(signed), identity), primary.onion)
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
            pinnedAccount.size != 32 || !wire.copyOfRange(6, 38).contentEquals(pinnedAccount) ||
            !wire.copyOfRange(38, 70).contentEquals(pinnedAccount)) return false
        val deviceId = Base64.encodeToString(wire.copyOfRange(70, 102),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val hash = wire.copyOfRange(102, 134)
        val signature = wire.copyOfRange(134, 198)
        val account = Base64.encodeToString(pinnedAccount, Base64.NO_WRAP)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val pending = db.query(SimpleSQLiteQuery(
                "SELECT signing_key,roster_hash FROM device_roster_notifications " +
                    "WHERE account_ed=? AND peer_device_id=?",
                arrayOf(account, deviceId)
            )).use { if (it.moveToFirst()) it.getBlob(0) to it.getBlob(1) else null }
                ?: return false
            if (!MessageDigest.isEqual(hash, pending.second) || pending.first.size != 32) return false
            val signed = ACK_DOMAIN + wire.copyOfRange(0, 134)
            if (!RustBridge.verifySignature(signed, signature, pending.first)) return false
            db.execSQL("DELETE FROM device_roster_notifications WHERE account_ed=? " +
                "AND peer_device_id=? AND roster_hash=?",
                arrayOf(account, deviceId, hash))
            db.setTransactionSuccessful()
            return true
        } finally { db.endTransaction() }
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

        fun acknowledgmentFrame(accountEd: ByteArray, localDeviceId: String,
                                rosterHash: ByteArray, identity: LocalDeviceIdentity): ByteArray {
            require(accountEd.size == 32 && rosterHash.size == 32 &&
                localDeviceId == identity.deviceId)
            val deviceBytes = Base64.decode(localDeviceId,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            require(deviceBytes.size == 32)
            val body = byteArrayOf(1) + accountEd + accountEd + deviceBytes + rosterHash + ByteArray(64)
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
