package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceGroupBundle
import com.securelegion.sync.DeviceGroupFrame
import com.securelegion.sync.DeviceGroupProofRequest
import org.json.JSONObject
import java.security.SecureRandom

/** Returns only stored exact proofs for this account's accepted operations. */
internal class DelegatedGroupProofExchange(private val database: SecureLegionDatabase) {
    fun request(groupId: String, targetAccount: ByteArray,
                hashes: Collection<String>, account: ByteArray,
                identity: LocalDeviceIdentity,
                nowMs: Long = System.currentTimeMillis()
    ): List<Pair<String, ByteArray>> {
        require(groupId.matches(Regex("[0-9a-f]{64}")) &&
            account.size == 32 && targetAccount.size == 32 &&
            !account.contentEquals(targetAccount))
        val payload = DeviceGroupProofRequest.encode(hashes)
        val roster = DeviceRosterStore(database).fetchSignedRoster(targetAccount)
            ?: database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
                "SELECT roster FROM delegated_group_trusted_rosters WHERE account_ed=?",
                arrayOf(b64(targetAccount)))).use { cursor ->
                if (cursor.moveToFirst()) cursor.getBlob(0) else null
            } ?: return emptyList()
        val verified = JSONObject(RustBridge.deviceAuthorization(JSONObject()
            .put("operation", "verify_roster").put("roster", b64(roster))
            .put("pinned_account", b64(targetAccount))
            .put("previous_roster", JSONObject.NULL).put("now_ms", nowMs)
            .put("authorize", JSONObject.NULL).toString()
            .toByteArray(Charsets.UTF_8), null).toString(Charsets.UTF_8))
        require(verified.getString("account_ed") == b64(targetAccount))
        val ownRoster = DeviceRosterStore(database).fetchSignedRoster(account)
            ?: throw IllegalStateException("Local group roster unavailable")
        val group = groupId.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val entries = verified.getJSONArray("entries")
        val frames = ArrayList<Pair<String, ByteArray>>()
        for (index in 0 until entries.length()) {
            val entry = entries.getJSONObject(index)
            val cert = entry.getJSONObject("certificate")
            if (cert.getInt("capabilities") and 0x04 == 0 ||
                nowMs !in cert.getLong("issued_at_ms") until
                    cert.getLong("expires_at_ms")) continue
            val onion = cert.getString("onion") + ".onion"
            val wire = DeviceGroupFrame.sealChunk(DeviceGroupFrame.Kind.PROOF_REQUEST,
                account, targetAccount, cert.getString("device_id"),
                Base64.decode(cert.getString("device_x"), Base64.DEFAULT),
                Base64.decode(entry.getString("ml_kem_public"), Base64.DEFAULT),
                identity, ownRoster, group,
                ByteArray(32).also(SecureRandom()::nextBytes),
                DeviceGroupFrame.hash(payload), payload.size, 0, payload,
                nowMs).wire
            frames.add(Pair(onion, wire))
            if (frames.size == 2) break
        }
        payload.fill(0)
        return frames
    }

    fun respond(frame: DeviceGroupFrame, account: ByteArray,
                identity: LocalDeviceIdentity,
                nowMs: Long = System.currentTimeMillis()): Pair<String, ByteArray>? {
        require(frame.kind == DeviceGroupFrame.Kind.PROOF_REQUEST &&
            frame.chunkCount == 1 && frame.recipientAccount.contentEquals(account) &&
            frame.recipientDeviceId == identity.deviceId)
        val onion = DelegatedGroupReceiver(database).replyEndpoint(
            frame, account, identity, nowMs)
        val plain = frame.openChunk(identity)
        val hashes = try {
            require(DeviceGroupFrame.hash(plain).contentEquals(frame.bundleHash) &&
                plain.size == frame.bundleLength)
            DeviceGroupProofRequest.decode(plain)
        } finally { plain.fill(0) }
        val db = database.openHelper.readableDatabase
        val group = hex(frame.groupId)
        val proofs = ArrayList<ByteArray>()
        for (hash in hashes) {
            val row = db.query(SimpleSQLiteQuery("SELECT r.proof,l.opBytes FROM " +
                "delegated_group_ratifications r JOIN delegated_group_acceptance a " +
                "ON a.group_id=r.group_id AND a.operation_hash=r.operation_hash " +
                "JOIN crdt_op_log l ON l.opId=a.op_id AND l.groupId=a.group_id " +
                "WHERE r.group_id=? AND r.operation_hash=? LIMIT 1",
                arrayOf(group, hash))).use { cursor ->
                if (cursor.moveToFirst()) Pair(cursor.getBlob(0), cursor.getBlob(1))
                else null
            } ?: continue
            if (row.first.size != 134 ||
                hex(row.first.copyOfRange(6, 38)) != hash) continue
            val descriptor = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "inspect")
                .put("encoded", b64(row.second)))
            if (descriptor.getString("account_public") == b64(account) &&
                descriptor.getString("hash") == hash) proofs.add(row.first)
        }
        if (proofs.isEmpty()) return null
        val bundle = DeviceGroupBundle.create(DeviceGroupBundle.Mode.PROOFS_ONLY,
            ratifications = proofs)
        val body = try { bundle.encoded() } finally { bundle.clear() }
        try {
            require(body.size <= 2164)
            val requesterRoster = DeviceRosterStore(database)
                .fetchSignedRoster(frame.senderAccount) ?: db.query(SimpleSQLiteQuery(
                    "SELECT roster FROM delegated_group_trusted_rosters WHERE account_ed=?",
                    arrayOf(b64(frame.senderAccount)))).use { cursor ->
                    if (cursor.moveToFirst()) cursor.getBlob(0) else null
                } ?: throw IllegalArgumentException("Proof requester roster unavailable")
            val verified = JSONObject(RustBridge.deviceAuthorization(JSONObject()
                .put("operation", "verify_roster")
                .put("roster", b64(requesterRoster))
                .put("pinned_account", b64(frame.senderAccount))
                .put("previous_roster", JSONObject.NULL)
                .put("now_ms", nowMs).put("authorize", JSONObject.NULL)
                .toString().toByteArray(Charsets.UTF_8), null)
                .toString(Charsets.UTF_8))
            require(verified.getString("account_ed") == b64(frame.senderAccount))
            val entries = verified.getJSONArray("entries")
            var keys: Pair<ByteArray, ByteArray>? = null
            for (index in 0 until entries.length()) {
                val entry = entries.getJSONObject(index)
                val certificate = entry.getJSONObject("certificate")
                if (certificate.getString("device_id") != frame.senderDeviceId) continue
                require(certificate.getString("onion") + ".onion" == onion &&
                    certificate.getInt("capabilities") and 0x04 != 0 &&
                    nowMs in certificate.getLong("issued_at_ms") until
                        certificate.getLong("expires_at_ms"))
                keys = Pair(Base64.decode(certificate.getString("device_x"),
                    Base64.DEFAULT), Base64.decode(entry.getString("ml_kem_public"),
                    Base64.DEFAULT))
            }
            val recipientKeys = keys ?: throw IllegalArgumentException(
                "Proof requester is no longer authorized")
            val roster = DeviceRosterStore(database).fetchSignedRoster(account)
                ?: throw IllegalStateException("Local group roster unavailable")
            val id = ByteArray(32).also(SecureRandom()::nextBytes)
            val wire = DeviceGroupFrame.sealChunk(DeviceGroupFrame.Kind.PROOF_RESPONSE,
                account, frame.senderAccount, frame.senderDeviceId,
                recipientKeys.first, recipientKeys.second, identity, roster, frame.groupId,
                id, DeviceGroupFrame.hash(body), body.size, 0, body, nowMs).wire
            return Pair(onion, wire)
        } finally { body.fill(0); proofs.forEach { it.fill(0) } }
    }

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 255)
    }
}
