package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceGroupFrame
import org.json.JSONObject

/** Group scoped Root roster pin. It does not establish contact or DM trust. */
internal class DelegatedGroupRosterTrust(private val database: SecureLegionDatabase) {
    data class Endpoint(val signingKey: ByteArray, val onion: String)

    fun observeOwn(account: ByteArray, encoded: ByteArray, nowMs: Long) {
        val current = DeviceRosterStore(database).fetchSignedRoster(account)
            ?: throw IllegalStateException("Local roster unavailable")
        val candidate = verify(encoded, account, null, nowMs)
        val pinned = verify(current, account, null, nowMs)
        require(candidate.getLong("epoch") <= pinned.getLong("epoch"))
        if (candidate.getLong("epoch") == pinned.getLong("epoch"))
            verify(encoded, account, current, nowMs)
    }

    /** Provisional until the native summary names this Root as a principal. */
    fun observeInTransaction(db: SupportSQLiteDatabase, account: ByteArray,
                             encoded: ByteArray, ownAccount: ByteArray,
                             nowMs: Long): Boolean {
        require(db.inTransaction() && account.size == 32 &&
            !account.contentEquals(ownAccount) && encoded.size in 1..32 * 1024)
        val accountB64 = b64(account)
        val global = DeviceRosterStore(database).fetchSignedRoster(account)
        val delegated = db.query(SimpleSQLiteQuery("SELECT roster,epoch FROM " +
            "delegated_group_trusted_rosters WHERE account_ed=?",
            arrayOf(accountB64))).use { cursor ->
            if (cursor.moveToFirst()) Pair(cursor.getBlob(0), cursor.getLong(1)) else null
        }
        val previous = global ?: delegated?.first
        val candidate = verify(encoded, account, null, nowMs)
        val prior = if (previous == null) null else verify(previous, account, null, nowMs)
        if (prior != null && candidate.getLong("epoch") >= prior.getLong("epoch"))
            verify(encoded, account, previous, nowMs)
        if (global != null) require(candidate.getLong("epoch") <= prior!!.getLong("epoch"))
        if (global == null && (delegated == null ||
                candidate.getLong("epoch") > delegated.second)) {
            purgeRemoved(db, accountB64, prior, candidate)
            db.execSQL("INSERT OR REPLACE INTO delegated_group_trusted_rosters " +
                "(account_ed,roster,epoch,roster_hash,accepted_at_ms) " +
                "VALUES (?,?,?,?,?)", arrayOf(accountB64, encoded,
                    candidate.getLong("epoch"), DeviceGroupFrame.hash(encoded), nowMs))
        }
        return previous == null
    }

    fun authorizeInTransaction(db: SupportSQLiteDatabase, frame: DeviceGroupFrame,
                               ownAccount: ByteArray, ownDeviceId: String,
                               nowMs: Long): Endpoint {
        require(db.inTransaction() && ownAccount.size == 32 &&
            frame.recipientAccount.contentEquals(ownAccount) &&
            frame.recipientDeviceId == ownDeviceId &&
            !frame.senderAccount.contentEquals(ownAccount))
        val rosters = DeviceRosterStore(database)
        require(rosters.isLocalAuthorized(ownAccount, ownDeviceId, 0x04, nowMs))
        val accountB64 = b64(frame.senderAccount)
        val global = rosters.fetchSignedRoster(frame.senderAccount)
        val delegated = db.query(SimpleSQLiteQuery("SELECT roster,epoch FROM " +
            "delegated_group_trusted_rosters WHERE account_ed=?",
            arrayOf(accountB64))).use { cursor ->
            if (cursor.moveToFirst()) Pair(cursor.getBlob(0), cursor.getLong(1)) else null
        }
        val previous = global ?: delegated?.first
        val candidate = verify(frame.senderRoster, frame.senderAccount, null, nowMs)
        val previousVerified = if (previous == null) null else
            verify(previous, frame.senderAccount, null, nowMs)
        if (previousVerified != null &&
            candidate.getLong("epoch") >= previousVerified.getLong("epoch"))
            verify(frame.senderRoster, frame.senderAccount, previous, nowMs)
        if (global != null) require(candidate.getLong("epoch") <=
            previousVerified!!.getLong("epoch"))
        val selected = if (previousVerified != null &&
            previousVerified.getLong("epoch") > candidate.getLong("epoch"))
            previousVerified else candidate
        if (global == null && (delegated == null ||
                candidate.getLong("epoch") > delegated.second)) {
            // The caller must check native group membership before committing.
            purgeRemoved(db, accountB64, previousVerified, candidate)
            db.execSQL("INSERT OR REPLACE INTO delegated_group_trusted_rosters " +
                "(account_ed,roster,epoch,roster_hash,accepted_at_ms) " +
                "VALUES (?,?,?,?,?)", arrayOf(accountB64, frame.senderRoster,
                    candidate.getLong("epoch"), DeviceGroupFrame.hash(frame.senderRoster), nowMs))
        }
        val entries = selected.getJSONArray("entries")
        for (index in 0 until entries.length()) {
            val certificate = entries.getJSONObject(index).getJSONObject("certificate")
            if (certificate.getString("device_id") != frame.senderDeviceId) continue
            require(certificate.getInt("capabilities") and 0x04 != 0 &&
                nowMs in certificate.getLong("issued_at_ms") until
                certificate.getLong("expires_at_ms"))
            val signing = Base64.decode(certificate.getString("device_ed"), Base64.DEFAULT)
            require(signing.size == 32 && frame.verify(signing,
                certificate.getInt("capabilities"), nowMs))
            return Endpoint(signing, certificate.getString("onion") + ".onion")
        }
        throw IllegalArgumentException("Untrusted group sender")
    }

    private fun verify(encoded: ByteArray, account: ByteArray,
                       previous: ByteArray?, nowMs: Long): JSONObject {
        val request = JSONObject().put("operation", "verify_roster")
            .put("roster", b64(encoded)).put("pinned_account", b64(account))
            .put("previous_roster", if (previous == null) JSONObject.NULL else b64(previous))
            .put("now_ms", nowMs).put("authorize", JSONObject.NULL)
        val verified = JSONObject(RustBridge.deviceAuthorization(
            request.toString().toByteArray(Charsets.UTF_8), null)
            .toString(Charsets.UTF_8))
        require(verified.getString("account_ed") == b64(account) &&
            Base64.decode(verified.getString("roster"), Base64.DEFAULT)
                .contentEquals(encoded) && verified.getLong("epoch") > 0)
        return verified
    }

    private fun purgeRemoved(db: SupportSQLiteDatabase, account: String,
                             previous: JSONObject?, current: JSONObject) {
        if (previous == null) return
        val old = previous.getJSONArray("entries")
        val next = current.getJSONArray("entries")
        val retained = HashSet<String>()
        for (index in 0 until next.length()) retained.add(next.getJSONObject(index)
            .getJSONObject("certificate").getString("device_id"))
        val accountHex = Base64.decode(account, Base64.DEFAULT).joinToString("") {
            "%02x".format(it.toInt() and 255)
        }
        for (index in 0 until old.length()) {
            val id = old.getJSONObject(index).getJSONObject("certificate")
                .getString("device_id")
            if (id in retained) continue
            db.execSQL("DELETE FROM delegated_group_inbox WHERE " +
                "sender_account=? AND sender_device=?", arrayOf(accountHex, id))
            db.execSQL("DELETE FROM delegated_group_inbound_receipts WHERE " +
                "sender_account=? AND sender_device=?", arrayOf(accountHex, id))
            db.execSQL("DELETE FROM delegated_group_delivery_batches WHERE " +
                "target_account=? AND target_device=?", arrayOf(account, id))
        }
    }

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
}
