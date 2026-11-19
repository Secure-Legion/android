package com.securelegion.database

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.DeviceGroupProtocolBridge
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceGroupBundle
import com.securelegion.sync.DeviceGroupFrame
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/** Immutable C2 packet batches and exact device ACK settlement. */
internal class DelegatedGroupDeliveryStore(private val database: SecureLegionDatabase) {
    data class Due(val id: String, val account: ByteArray, val deviceId: String,
                   val onion: String, val wires: List<ByteArray>)
    private val rosters = DeviceRosterStore(database)
    private val trust = DelegatedGroupRosterTrust(database)
    private val states = DelegatedGroupStateStore(database)
    private var scanCursor: Triple<Long, String, String>? = null

    fun prepare(account: ByteArray, identity: LocalDeviceIdentity,
                nowMs: Long = System.currentTimeMillis()): Int {
        require(account.size == 32 && nowMs > 0)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            require(rosters.isLocalAuthorized(account, identity.deviceId, 0x04, nowMs))
            val ownRoster = rosters.fetchSignedRoster(account)
                ?: throw IllegalStateException("Local roster unavailable")
            val cert = localCertificate(db, account, identity.deviceId, nowMs)
            val targets = ArrayList<Array<String>>()
            val start = scanCursor
            db.query(SimpleSQLiteQuery("SELECT o.op_id,o.group_id,t.target_account,t.mode," +
                "o.created_at_ms " +
                "FROM delegated_group_origins o JOIN delegated_group_targets t " +
                "ON t.op_id=o.op_id WHERE o.local_device=? AND " +
                "(? IS NULL OR o.created_at_ms>? OR " +
                "(o.created_at_ms=? AND o.op_id>?) OR " +
                "(o.created_at_ms=? AND o.op_id=? AND t.target_account>?)) " +
                "ORDER BY o.created_at_ms,o.op_id,t.target_account LIMIT 128",
                arrayOf(identity.deviceId, start?.first, start?.first,
                    start?.first, start?.second, start?.first, start?.second,
                    start?.third)))
                .use { cursor -> while (cursor.moveToNext())
                    targets.add(arrayOf(cursor.getString(0), cursor.getString(1),
                        cursor.getString(2), cursor.getString(3),
                        cursor.getLong(4).toString())) }
            var made = 0
            var lastProcessed: Array<String>? = null
            for (target in targets) {
                if (made >= 8) break
                lastProcessed = target
                val targetAccount = Base64.decode(target[2], Base64.DEFAULT)
                if (targetAccount.size != 32 || targetAccount.contentEquals(account)) continue
                val rosterBytes = signedRoster(db, targetAccount) ?: continue
                val verified = verifyRoster(rosterBytes, targetAccount, nowMs)
                val entries = verified.getJSONArray("entries")
                for (index in 0 until entries.length()) {
                    if (made >= 8) break
                    val entry = entries.getJSONObject(index)
                    val certificate = entry.getJSONObject("certificate")
                    val deviceId = certificate.getString("device_id")
                    if (certificate.getInt("capabilities") and 0x04 == 0 ||
                        nowMs !in certificate.getLong("issued_at_ms") until
                            certificate.getLong("expires_at_ms")) continue
                    if (batchExists(db, target[0], target[2], deviceId) ||
                        completed(db, target[0], target[2], deviceId)) continue
                    val state = states.loadInTransaction(db, target[1], account, nowMs)
                    try {
                        val progress = db.query(SimpleSQLiteQuery("SELECT acknowledged FROM " +
                            "delegated_group_delivery_progress WHERE group_id=? AND " +
                            "local_device=? AND target_account=? AND target_device=?",
                            arrayOf(target[1], identity.deviceId, target[2], deviceId)))
                            .use { if (it.moveToFirst()) JSONArray(it.getString(0)) else JSONArray() }
                        val invitation = target[3] == "invite"
                        val terminal = target[3] == "terminal"
                        require(invitation || terminal || target[3] == "live")
                        val request = JSONObject()
                            .put("operation", if (invitation) "prepare_invitation"
                                else "select_delivery")
                            .put("state", state.context).put("certificate", b64(cert))
                            .put("origin_op_id", target[0])
                        val selected = if (invitation) identity.withSyncKeys { seed, _ ->
                            request.put("recipient_account", target[2])
                            DeviceGroupProtocolBridge.execute(request,
                                signingSeed = seed, groupKey = state.groupKey)
                        } else {
                            request.put("acknowledged", progress).put("limit", 128)
                            if (terminal) request.put("terminal_recipient", target[2])
                            DeviceGroupProtocolBridge.execute(request,
                                groupKey = state.groupKey)
                        }
                        val packed = Base64.decode(selected.getString("packed_ops"),
                            Base64.DEFAULT)
                        try {
                            if (!invitation && packed.isEmpty() &&
                                selected.getBoolean("complete")) {
                                db.execSQL("INSERT OR IGNORE INTO " +
                                    "delegated_group_delivery_completed " +
                                    "(op_id,target_account,target_device) VALUES (?,?,?)",
                                    arrayOf(target[0], target[2], deviceId))
                                continue
                            }
                            require(packed.isNotEmpty())
                            val hashes = selected.getJSONArray("operation_hashes")
                            validateSelectedHashes(packed, hashes)
                            val observations = if (invitation)
                                collectRosterAccounts(db,
                                    selected.getJSONArray("roster_accounts"), account)
                            else collectRosters(db, packed, account)
                            val proofs = ArrayList<ByteArray>()
                            for (hashIndex in 0 until hashes.length()) {
                                val operationHash = hashes.getString(hashIndex)
                                val proof = db.query(SimpleSQLiteQuery("SELECT proof FROM " +
                                    "delegated_group_ratifications WHERE group_id=? AND " +
                                    "operation_hash=?", arrayOf(target[1], operationHash)))
                                    .use { cursor -> if (cursor.moveToFirst())
                                        cursor.getBlob(0) else null }
                                if (proof != null) proofs.add(proof)
                            }
                            val bundleMode = if (!invitation) DeviceGroupBundle.Mode.LIVE
                                else if (selected.getBoolean("reinvitation"))
                                    DeviceGroupBundle.Mode.REINVITATION
                                else DeviceGroupBundle.Mode.INVITATION
                            val bundleKey = if (invitation) Base64.decode(
                                selected.getString("group_secret"), Base64.DEFAULT)
                                else ByteArray(0)
                            val historyReceipt = if (invitation) Base64.decode(
                                selected.getString("receipt"), Base64.DEFAULT)
                                else ByteArray(0)
                            val bundle = try {
                                DeviceGroupBundle.create(bundleMode,
                                    groupKey = bundleKey,
                                    historyReceipt = historyReceipt,
                                    packedOperations = packed,
                                    ratifications = proofs, rosters = observations)
                            } finally {
                                bundleKey.fill(0); historyReceipt.fill(0)
                                proofs.forEach { it.fill(0) }
                                observations.forEach {
                                    it.account.fill(0); it.encoded.fill(0)
                                }
                            }
                            try {
                                val body = bundle.encoded()
                                try {
                                    val group = hexBytes(target[1])
                                    val bundleId = ByteArray(32).also(SecureRandom()::nextBytes)
                                    val digest = DeviceGroupFrame.hash(body)
                                    val count = (body.size + DeviceGroupFrame.CHUNK_BYTES - 1) /
                                        DeviceGroupFrame.CHUNK_BYTES
                                    val x = Base64.decode(certificate.getString("device_x"),
                                        Base64.DEFAULT)
                                    val kem = Base64.decode(entry.getString("ml_kem_public"),
                                        Base64.DEFAULT)
                                    val wires = ArrayList<ByteArray>(count)
                                    for (chunk in 0 until count) {
                                        val start = chunk * DeviceGroupFrame.CHUNK_BYTES
                                        val end = minOf(body.size,
                                            start + DeviceGroupFrame.CHUNK_BYTES)
                                        wires.add(DeviceGroupFrame.sealChunk(
                                            if (bundleMode == DeviceGroupBundle.Mode.REINVITATION)
                                                DeviceGroupFrame.Kind.REINVITATION
                                            else DeviceGroupFrame.Kind.DATA,
                                            account, targetAccount,
                                            deviceId, x, kem, identity, ownRoster, group,
                                            bundleId, digest, body.size, chunk,
                                            body.copyOfRange(start, end), nowMs).wire)
                                    }
                                    val id = hex(DeviceGroupFrame.hash(
                                        (target[0] + target[2] + deviceId).toByteArray() +
                                            bundleId))
                                    val coverage = if (invitation)
                                        selected.getJSONArray("acknowledged_on_commit")
                                    else hashes
                                    val allowed = HashSet<String>()
                                    for (hashIndex in 0 until hashes.length())
                                        allowed.add(hashes.getString(hashIndex))
                                    require(coverage.length() in 1..4096)
                                    for (hashIndex in 0 until coverage.length())
                                        require(coverage.getString(hashIndex) in allowed)
                                    val plan = identity.sign(DeviceGroupFrame.hash(
                                        id.toByteArray() + digest +
                                            coverage.toString().toByteArray()))
                                    db.execSQL("INSERT INTO delegated_group_delivery_batches " +
                                        "(id,op_id,group_id,local_device,target_account," +
                                        "target_device,first_wire,operation_hashes,final_batch," +
                                        "plan_signature,created_at_ms,next_try_at_ms,attempts) " +
                                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,0,0)", arrayOf(id,
                                            target[0], target[1], identity.deviceId,
                                            target[2], deviceId, wires[0], coverage.toString(),
                                            if (invitation || selected.getBoolean("complete")) 1 else 0,
                                            plan, nowMs))
                                    for (chunk in wires.indices)
                                        db.execSQL("INSERT INTO " +
                                            "delegated_group_delivery_chunks " +
                                            "(batch_id,chunk_index,wire) VALUES (?,?,?)",
                                            arrayOf(id, chunk, wires[chunk]))
                                    made++
                                } finally { body.fill(0) }
                            } finally { bundle.clear() }
                        } finally { packed.fill(0) }
                    } finally { state.groupKey.fill(0) }
                }
            }
            db.setTransactionSuccessful()
            scanCursor = if (targets.size < 128 && made < 8) null
                else lastProcessed?.let {
                    Triple(it[4].toLong(), it[0], it[2])
                }
            return made
        } finally { db.endTransaction() }
    }

    fun due(account: ByteArray, identity: LocalDeviceIdentity,
            nowMs: Long = System.currentTimeMillis()): List<Due> {
        require(rosters.isLocalAuthorized(account, identity.deviceId, 0x04, nowMs))
        val db = database.openHelper.readableDatabase
        val rows = ArrayList<Array<String>>()
        db.query(SimpleSQLiteQuery("SELECT id,target_account,target_device FROM " +
            "delegated_group_delivery_batches WHERE local_device=? AND " +
            "next_try_at_ms<=? ORDER BY created_at_ms,id LIMIT 8",
            arrayOf(identity.deviceId, nowMs))).use { cursor ->
            while (cursor.moveToNext()) rows.add(arrayOf(cursor.getString(0),
                cursor.getString(1), cursor.getString(2)))
        }
        return rows.mapNotNull { row ->
            val target = Base64.decode(row[1], Base64.DEFAULT)
            val verified = signedRoster(db, target)?.let { verifyRoster(it, target, nowMs) }
                ?: return@mapNotNull null
            val entries = verified.getJSONArray("entries")
            var onion: String? = null
            for (index in 0 until entries.length()) {
                val certificate = entries.getJSONObject(index).getJSONObject("certificate")
                if (certificate.getString("device_id") == row[2] &&
                    certificate.getInt("capabilities") and 0x04 != 0 &&
                    nowMs in certificate.getLong("issued_at_ms") until
                        certificate.getLong("expires_at_ms"))
                    onion = certificate.getString("onion") + ".onion"
            }
            if (onion == null) return@mapNotNull null
            val wires = ArrayList<ByteArray>()
            db.query(SimpleSQLiteQuery("SELECT wire FROM " +
                "delegated_group_delivery_chunks WHERE batch_id=? " +
                "ORDER BY chunk_index", arrayOf(row[0]))).use { cursor ->
                while (cursor.moveToNext()) wires.add(cursor.getBlob(0))
            }
            if (wires.isEmpty() || wires.any { wire ->
                    val frame = DeviceGroupFrame.parse(wire)
                    !frame.senderAccount.contentEquals(account) ||
                        frame.senderDeviceId != identity.deviceId ||
                        !frame.recipientAccount.contentEquals(target) ||
                        frame.recipientDeviceId != row[2] ||
                        !frame.verify(identity.signingPublicKey, 0x04, nowMs)
                }) null else Due(row[0], target, row[2], onion!!, wires)
        }
    }

    fun defer(id: String, nowMs: Long = System.currentTimeMillis()) {
        val db = database.openHelper.writableDatabase
        db.execSQL("UPDATE delegated_group_delivery_batches SET attempts=attempts+1," +
            "next_try_at_ms=? WHERE id=?", arrayOf(nowMs + 10_000, id))
    }

    fun acknowledge(wire: ByteArray, account: ByteArray,
                    identity: LocalDeviceIdentity,
                    nowMs: Long = System.currentTimeMillis()): Boolean {
        val ack = DeviceGroupFrame.parse(wire)
        require(ack.isAcknowledgment && ack.recipientAccount.contentEquals(account) &&
            ack.recipientDeviceId == identity.deviceId)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            trust.authorizeInTransaction(db, ack, account, identity.deviceId, nowMs)
            val candidates = ArrayList<Array<Any>>()
            db.query(SimpleSQLiteQuery("SELECT id,op_id,group_id," +
                "target_account,target_device,first_wire,operation_hashes,final_batch " +
                "FROM delegated_group_delivery_batches WHERE local_device=? AND " +
                "target_account=? AND target_device=?", arrayOf(identity.deviceId,
                    b64(ack.senderAccount), ack.senderDeviceId))).use { cursor ->
                while (cursor.moveToNext()) candidates.add(arrayOf(cursor.getString(0),
                    cursor.getString(1), cursor.getString(2), cursor.getString(3),
                    cursor.getString(4), cursor.getBlob(5), cursor.getString(6),
                    cursor.getInt(7)))
            }
            val candidate = candidates.firstOrNull {
                ack.acknowledges(DeviceGroupFrame.parse(it[5] as ByteArray))
            } ?: return false
            val hashes = JSONArray(candidate[6] as String)
            val progress = db.query(SimpleSQLiteQuery("SELECT acknowledged FROM " +
                "delegated_group_delivery_progress WHERE group_id=? AND local_device=? " +
                "AND target_account=? AND target_device=?", arrayOf(candidate[2],
                    identity.deviceId, candidate[3], candidate[4])))
                .use { if (it.moveToFirst()) JSONArray(it.getString(0)) else JSONArray() }
            val known = HashSet<String>()
            for (index in 0 until progress.length()) known.add(progress.getString(index))
            for (index in 0 until hashes.length()) known.add(hashes.getString(index))
            val ordered = JSONArray()
            known.sorted().forEach(ordered::put)
            db.execSQL("INSERT OR REPLACE INTO delegated_group_delivery_progress " +
                "(group_id,local_device,target_account,target_device,acknowledged," +
                "updated_at_ms) VALUES (?,?,?,?,?,?)", arrayOf(candidate[2],
                    identity.deviceId, candidate[3], candidate[4], ordered.toString(), nowMs))
            if (ack.kind == DeviceGroupFrame.Kind.ACCOUNT_STORAGE_ACK)
                db.execSQL("INSERT OR REPLACE INTO delegated_group_account_progress " +
                    "(group_id,local_device,target_account,acknowledged,updated_at_ms) " +
                    "VALUES (?,?,?,?,?)", arrayOf(candidate[2], identity.deviceId,
                        candidate[3], ordered.toString(), nowMs))
            if (candidate[7] == 1) db.execSQL("INSERT OR IGNORE INTO " +
                "delegated_group_delivery_completed " +
                "(op_id,target_account,target_device) VALUES (?,?,?)",
                arrayOf(candidate[1], candidate[3], candidate[4]))
            db.execSQL("DELETE FROM delegated_group_delivery_batches WHERE id=?",
                arrayOf(candidate[0]))
            db.setTransactionSuccessful()
            return true
        } finally { db.endTransaction() }
    }

    private fun collectRosters(db: SupportSQLiteDatabase, packed: ByteArray,
                               own: ByteArray): List<DeviceGroupBundle.RosterObservation> {
        val accounts = HashSet<String>()
        var at = 0
        while (at < packed.size) {
            require(at + 4 <= packed.size)
            val length = ((packed[at].toInt() and 255) shl 24) or
                ((packed[at + 1].toInt() and 255) shl 16) or
                ((packed[at + 2].toInt() and 255) shl 8) or
                (packed[at + 3].toInt() and 255)
            at += 4
            require(length in 1..69_632 && at + length <= packed.size)
            val info = DeviceGroupProtocolBridge.execute(JSONObject()
                .put("operation", "inspect")
                .put("encoded", b64(packed.copyOfRange(at, at + length))))
            accounts.add(info.getString("account_public"))
            at += length
        }
        require(accounts.size <= 128)
        return accounts.mapNotNull { key ->
            val account = Base64.decode(key, Base64.DEFAULT)
            if (account.contentEquals(own)) null else {
                val roster = signedRoster(db, account)
                    ?: throw IllegalStateException("Group author roster unavailable")
                DeviceGroupBundle.RosterObservation(account, roster)
            }
        }
    }

    private fun collectRosterAccounts(db: SupportSQLiteDatabase,
                                      roots: JSONArray,
                                      own: ByteArray): List<DeviceGroupBundle.RosterObservation> {
        require(roots.length() <= 128)
        val unique = HashSet<String>()
        val result = ArrayList<DeviceGroupBundle.RosterObservation>()
        for (index in 0 until roots.length()) {
            val key = roots.getString(index)
            require(unique.add(key))
            val account = Base64.decode(key, Base64.DEFAULT)
            require(account.size == 32 && b64(account) == key)
            if (account.contentEquals(own)) continue
            val roster = signedRoster(db, account)
                ?: throw IllegalStateException("Invitation author roster unavailable")
            result.add(DeviceGroupBundle.RosterObservation(account, roster))
        }
        return result
    }

    private fun validateSelectedHashes(packed: ByteArray, hashes: JSONArray) {
        require(hashes.length() in 1..500_000)
        var at = 0
        var index = 0
        while (at < packed.size) {
            require(at + 4 <= packed.size && index < hashes.length())
            val length = ((packed[at].toInt() and 255) shl 24) or
                ((packed[at + 1].toInt() and 255) shl 16) or
                ((packed[at + 2].toInt() and 255) shl 8) or
                (packed[at + 3].toInt() and 255)
            at += 4
            require(length in 1..69_632 && at + length <= packed.size)
            require(hex(DeviceGroupFrame.hash(packed.copyOfRange(at, at + length))) ==
                hashes.getString(index++))
            at += length
        }
        require(index == hashes.length())
    }

    private fun localCertificate(db: SupportSQLiteDatabase, account: ByteArray,
                                 deviceId: String, nowMs: Long): ByteArray =
        db.query(SimpleSQLiteQuery("SELECT certificate FROM authorized_devices " +
            "WHERE accountEd=? AND deviceId=? AND isSelf=1 AND " +
            "(capabilities & 4)=4 AND issuedAtMs<=? AND expiresAtMs>?",
            arrayOf(b64(account), deviceId, nowMs, nowMs))).use { cursor ->
            if (cursor.moveToFirst()) cursor.getBlob(0)
            else throw IllegalStateException("Local group certificate unavailable")
        }

    private fun signedRoster(db: SupportSQLiteDatabase, account: ByteArray): ByteArray? {
        val key = b64(account)
        return db.query(SimpleSQLiteQuery("SELECT signedRoster FROM device_rosters " +
            "WHERE accountEd=?", arrayOf(key))).use { cursor ->
            if (cursor.moveToFirst()) cursor.getBlob(0) else null
        } ?: db.query(SimpleSQLiteQuery("SELECT roster FROM " +
            "delegated_group_trusted_rosters WHERE account_ed=?", arrayOf(key)))
            .use { cursor -> if (cursor.moveToFirst()) cursor.getBlob(0) else null }
    }

    private fun verifyRoster(encoded: ByteArray, account: ByteArray,
                             nowMs: Long): JSONObject {
        val request = JSONObject().put("operation", "verify_roster")
            .put("roster", b64(encoded)).put("pinned_account", b64(account))
            .put("previous_roster", JSONObject.NULL).put("now_ms", nowMs)
            .put("authorize", JSONObject.NULL)
        return JSONObject(RustBridge.deviceAuthorization(
            request.toString().toByteArray(Charsets.UTF_8), null)
            .toString(Charsets.UTF_8))
    }

    private fun batchExists(db: SupportSQLiteDatabase, op: String,
                            account: String, device: String) = db.query(SimpleSQLiteQuery(
        "SELECT 1 FROM delegated_group_delivery_batches WHERE op_id=? AND " +
            "target_account=? AND target_device=?", arrayOf(op, account, device)))
        .use { it.moveToFirst() }

    private fun completed(db: SupportSQLiteDatabase, op: String,
                          account: String, device: String) = db.query(SimpleSQLiteQuery(
        "SELECT 1 FROM delegated_group_delivery_completed WHERE op_id=? AND " +
            "target_account=? AND target_device=?", arrayOf(op, account, device)))
        .use { it.moveToFirst() }

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 255)
    }
    private fun hexBytes(value: String): ByteArray {
        require(value.matches(Regex("[0-9a-f]{64}")))
        return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
