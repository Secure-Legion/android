package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.sync.DeviceGroupBundle
import com.securelegion.sync.DeviceGroupFrame
import org.json.JSONObject

/** C2 live acceptance. Incomplete or rejected bundles never produce an ACK. */
internal class DelegatedGroupReceiver(private val database: SecureLegionDatabase) {
    data class Result(val complete: Boolean, val ack: ByteArray? = null,
                      val duplicate: Boolean = false)

    private val trust = DelegatedGroupRosterTrust(database)
    private val chunks = DelegatedGroupChunkStore(database)
    private val states = DelegatedGroupStateStore(database)
    private val rosters = DeviceRosterStore(database)

    fun replyEndpoint(frame: DeviceGroupFrame, account: ByteArray,
                      identity: LocalDeviceIdentity,
                      nowMs: Long = System.currentTimeMillis()): String {
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val peer = trust.authorizeInTransaction(db, frame, account,
                identity.deviceId, nowMs)
            if (cached(db, chunks.transferId(frame, identity.deviceId), frame,
                    account, identity, nowMs) == null)
                requireCurrentMember(db, hex(frame.groupId), account,
                    frame.senderAccount, nowMs,
                    allowHistorical = frame.kind == DeviceGroupFrame.Kind.PROOF_RESPONSE)
            db.setTransactionSuccessful()
            return peer.onion
        } finally { db.endTransaction() }
    }

    fun receive(wire: ByteArray, account: ByteArray,
                    identity: LocalDeviceIdentity,
                    nowMs: Long = System.currentTimeMillis()): Result {
        val frame = DeviceGroupFrame.parse(wire)
        require(frame.kind in setOf(DeviceGroupFrame.Kind.DATA,
            DeviceGroupFrame.Kind.REINVITATION,
            DeviceGroupFrame.Kind.PROOF_RESPONSE) &&
            frame.recipientAccount.contentEquals(account) &&
            frame.recipientDeviceId == identity.deviceId &&
            nowMs in 1..9_007_199_254_740_991L)
        val db = database.openHelper.writableDatabase
        val groupId = hex(frame.groupId)
        val transferId = chunks.transferId(frame, identity.deviceId)
        db.beginTransaction()
        try {
            trust.authorizeInTransaction(db, frame, account, identity.deviceId, nowMs)
            val existing = groupExists(db, groupId)
            val duplicate = cached(db, transferId, frame, account, identity, nowMs)
            if (duplicate == null && existing && frame.kind == DeviceGroupFrame.Kind.DATA)
                requireCurrentMember(db, groupId, account,
                    frame.senderAccount, nowMs)
            if (existing && (frame.kind == DeviceGroupFrame.Kind.DATA ||
                    duplicate != null))
                db.setTransactionSuccessful()
            if (duplicate != null) return Result(true, duplicate, true)
        } finally { db.endTransaction() }

        val plain = frame.openChunk(identity)
        val complete = try { chunks.stage(frame, identity.deviceId, plain, nowMs) }
            finally { plain.fill(0) }
            ?: return Result(false)
        val bundle = try { DeviceGroupBundle.parse(complete.bundle) }
            catch (error: Exception) {
                complete.bundle.fill(0)
                throw error
            }
        try {
            require((frame.kind == DeviceGroupFrame.Kind.REINVITATION) ==
                (bundle.mode == DeviceGroupBundle.Mode.REINVITATION) &&
                (frame.kind == DeviceGroupFrame.Kind.PROOF_RESPONSE) ==
                    (bundle.mode == DeviceGroupBundle.Mode.PROOFS_ONLY))
            db.beginTransaction()
            try {
                trust.authorizeInTransaction(db, frame, account, identity.deviceId, nowMs)
                if (bundle.mode == DeviceGroupBundle.Mode.LIVE)
                    requireCurrentMember(db, groupId, account,
                        frame.senderAccount, nowMs)
                else require((bundle.mode == DeviceGroupBundle.Mode.REINVITATION &&
                    groupExists(db, groupId) ||
                    bundle.mode == DeviceGroupBundle.Mode.INVITATION &&
                    !groupExists(db, groupId) ||
                    bundle.mode == DeviceGroupBundle.Mode.PROOFS_ONLY &&
                    groupExists(db, groupId)))
                val duplicate = cached(db, transferId, frame, account, identity, nowMs)
                if (duplicate != null) {
                    db.setTransactionSuccessful()
                    return Result(true, duplicate, true)
                }
                val newlyPinned = HashSet<String>()
                for (observation in bundle.rosters) {
                    if (observation.account.contentEquals(account))
                        trust.observeOwn(account, observation.encoded, nowMs)
                    else if (trust.observeInTransaction(db, observation.account,
                            observation.encoded, account, nowMs))
                        newlyPinned.add(hex(observation.account))
                }
                val summary = when (bundle.mode) {
                    DeviceGroupBundle.Mode.LIVE -> states.applyLiveInTransaction(db,
                        groupId, account, bundle.packedOperations,
                        bundle.ratifications, bundle.rosters.map { it.account },
                        nowMs = nowMs)
                    DeviceGroupBundle.Mode.REINVITATION ->
                        states.applyLiveInTransaction(db, groupId, account,
                            bundle.packedOperations, bundle.ratifications,
                            bundle.rosters.map { it.account },
                            historyReceipt = bundle.historyReceipt,
                            incomingKey = bundle.groupKey,
                            foreignSource = frame.senderAccount, nowMs = nowMs)
                    DeviceGroupBundle.Mode.INVITATION ->
                        states.applyFirstInviteInTransaction(db, groupId, account,
                            frame.senderAccount, bundle.packedOperations, bundle.groupKey,
                            bundle.historyReceipt, bundle.ratifications,
                            bundle.rosters.map { it.account }, nowMs = nowMs)
                    DeviceGroupBundle.Mode.PROOFS_ONLY ->
                        states.applyRatificationsInTransaction(db, groupId, account,
                            bundle.ratifications, nowMs)
                    else -> throw IllegalArgumentException("Unsupported group bundle")
                }
                if (bundle.mode == DeviceGroupBundle.Mode.PROOFS_ONLY)
                    requireCurrentMember(db, groupId, account,
                        frame.senderAccount, nowMs, allowHistorical = true)
                val principals = HashSet<String>()
                val members = summary.getJSONArray("members")
                for (index in 0 until members.length())
                    principals.add(members.getJSONObject(index).getString("pubkey_hex"))
                val historical = HashSet<String>()
                val history = summary.getJSONArray("historical_principals")
                for (index in 0 until history.length()) historical.add(history.getString(index))
                for (observation in bundle.rosters) {
                    val principal = hex(observation.account)
                    require(principal in principals || principal in historical)
                    if (principal !in principals && principal in newlyPinned)
                        db.execSQL("DELETE FROM delegated_group_trusted_rosters " +
                            "WHERE account_ed=?", arrayOf(b64(observation.account)))
                }
                val ownRoster = rosters.fetchSignedRoster(account)
                    ?: throw IllegalStateException("Local group roster unavailable")
                val ack = DeviceGroupFrame.committedAck(
                    DeviceGroupFrame.parse(complete.firstWire), account, identity,
                    ownRoster, nowMs = nowMs).wire
                for ((limit, scoped) in listOf(1024 to true, 8192 to false)) {
                    val clause = if (scoped) " WHERE sender_account=?" else ""
                    val args = if (scoped) arrayOf<Any>(hex(frame.senderAccount))
                        else emptyArray()
                    val count = db.query(SimpleSQLiteQuery("SELECT count(*) FROM " +
                        "delegated_group_inbound_receipts$clause", args)).use { cursor ->
                        cursor.moveToFirst(); cursor.getInt(0)
                    }
                    if (count >= limit) db.execSQL("DELETE FROM " +
                        "delegated_group_inbound_receipts WHERE id IN " +
                        "(SELECT id FROM delegated_group_inbound_receipts$clause " +
                        "ORDER BY accepted_at_ms,id LIMIT ?)",
                        if (scoped) arrayOf(hex(frame.senderAccount), count - limit + 1)
                        else arrayOf(count - limit + 1))
                }
                db.execSQL("INSERT INTO delegated_group_inbound_receipts " +
                    "(id,local_device,group_id,sender_account,sender_device," +
                    "bundle_hash,bundle_length,chunk_count,ack,accepted_at_ms) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?)", arrayOf(transferId,
                        identity.deviceId, groupId, hex(frame.senderAccount),
                        frame.senderDeviceId, frame.bundleHash, frame.bundleLength,
                        frame.chunkCount, ack, nowMs))
                chunks.finishInTransaction(db, complete)
                db.setTransactionSuccessful()
                return Result(true, ack)
            } finally { db.endTransaction() }
        } finally {
            bundle.clear()
            complete.bundle.fill(0)
        }
    }

    private fun requireCurrentMember(db: SupportSQLiteDatabase, groupId: String,
                                     account: ByteArray, sender: ByteArray,
                                     nowMs: Long, allowHistorical: Boolean = false) {
        val state = states.loadInTransaction(db, groupId, account, nowMs)
        try {
            val summary = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "read_state").put("state", state.context),
                groupKey = state.groupKey)
            require(!summary.getBoolean("deleted") &&
                summary.getString("our_role") != "Removed")
            val members = summary.getJSONArray("members")
            var admitted = false
            for (index in 0 until members.length()) {
                val member = members.getJSONObject(index)
                if (member.getString("pubkey_hex") == hex(sender) &&
                    !member.getBoolean("removed") &&
                    !member.getBoolean("banned")) admitted = true
            }
            if (allowHistorical) {
                val historical = summary.getJSONArray("historical_principals")
                for (index in 0 until historical.length())
                    if (historical.getString(index) == hex(sender)) admitted = true
            }
            require(admitted) { "Sender is not a current group principal" }
        } finally { state.groupKey.fill(0) }
    }

    private fun groupExists(db: SupportSQLiteDatabase, groupId: String): Boolean =
        db.query(SimpleSQLiteQuery("SELECT 1 FROM groups WHERE groupId=?",
            arrayOf(groupId))).use { it.moveToFirst() }

    private fun cached(db: SupportSQLiteDatabase, id: String,
                       frame: DeviceGroupFrame, account: ByteArray,
                       identity: LocalDeviceIdentity, nowMs: Long): ByteArray? {
        val row = db.query(SimpleSQLiteQuery("SELECT local_device,group_id," +
            "sender_account,sender_device,bundle_hash,bundle_length,chunk_count,ack " +
            "FROM delegated_group_inbound_receipts WHERE id=?", arrayOf(id)))
            .use { cursor -> if (cursor.moveToFirst()) arrayOf<Any>(
                cursor.getString(0), cursor.getString(1), cursor.getString(2),
                cursor.getString(3), cursor.getBlob(4), cursor.getInt(5),
                cursor.getInt(6), cursor.getBlob(7)) else null } ?: return null
        require(row[0] == identity.deviceId && row[1] == hex(frame.groupId) &&
            row[2] == hex(frame.senderAccount) && row[3] == frame.senderDeviceId &&
            (row[4] as ByteArray).contentEquals(frame.bundleHash) &&
            row[5] == frame.bundleLength && row[6] == frame.chunkCount &&
            rosters.isLocalAuthorized(account, identity.deviceId, 0x04, nowMs))
        val ack = DeviceGroupFrame.parse(row[7] as ByteArray)
        require(ack.acknowledges(frame) && ack.senderAccount.contentEquals(account) &&
            ack.verify(identity.signingPublicKey, 0x04, ack.createdAtMs))
        return ack.wire
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
    private fun b64(bytes: ByteArray) =
        android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
}
