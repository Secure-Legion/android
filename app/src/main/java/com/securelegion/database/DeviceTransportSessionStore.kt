package com.securelegion.database

import android.util.Log
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceTransportFrame
import java.security.MessageDigest
import java.util.Base64

/** C0v2 request/prekey handshake, persisted before any network reply. */
internal class DeviceTransportSessionStore(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore
) {
    private companion object {
        const val TAG = "DeviceTransportSession"
        const val RECEIVE_WINDOW = 16L
        const val SKIPPED_RETENTION = 64L
        const val MAX_RECEIPTS = 100_000L
    }
    data class Request(val sessionId: ByteArray, val wire: ByteArray)

    fun request(localAccount: ByteArray, recipientAccount: ByteArray,
                peerId: String, identity: LocalDeviceIdentity,
                nowMs: Long = System.currentTimeMillis()): Request {
        require(localAccount.size == 32 && recipientAccount.size == 32 &&
            identity.deviceId != peerId && peerId.length == 43)
        authorize(localAccount, identity.deviceId, recipientAccount, peerId, nowMs)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            authorize(localAccount, identity.deviceId, recipientAccount, peerId, nowMs)
            DeviceTransportEpochStore.reap(db, recipientAccount, peerId,
                identity.deviceId)
            val active = db.query(SimpleSQLiteQuery(
                "SELECT session_id,prekey_wire,state FROM device_transport_sessions " +
                    "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                    "AND direction='tx' AND state<>'retiring' " +
                    "ORDER BY generation DESC LIMIT 2",
                arrayOf(encoded(recipientAccount), peerId, identity.deviceId)
            )).use { c ->
                buildList {
                    while (c.moveToNext()) add(Triple(c.getBlob(0), c.getBlob(1), c.getString(2)))
                }
            }
            require(active.size <= 1) { "Ambiguous sending session" }
            if (active.isNotEmpty()) {
                val row = active.single()
                db.setTransactionSuccessful()
                return Request(row.first, if (row.third == "requested") row.second else ByteArray(0))
            }
            val count = db.query(SimpleSQLiteQuery(
                "SELECT COUNT(*) FROM device_transport_sessions WHERE account_ed=? " +
                    "AND peer_device_id=? AND local_device_id=? AND direction='tx'",
                arrayOf(encoded(recipientAccount), peerId, identity.deviceId)
            )).use { check(it.moveToFirst()); it.getInt(0) }
            require(count < 2) { "Sending session capacity reached" }
            val generation = DeviceTransportEpochStore.allocate(db, recipientAccount,
                peerId, identity.deviceId)
            val session = DeviceTransportFrame.sessionIdForGeneration(generation.generation)
            val retired = ByteArray(8)
            writeU64(retired, generation.retiredThrough)
            val frame = DeviceTransportFrame.sign(DeviceTransportFrame.Kind.SESSION_REQUEST,
                localAccount, recipientAccount, identity.deviceId, peerId,
                session, generation.generation, ByteArray(32), retired, identity)
            db.execSQL("INSERT INTO device_transport_sessions " +
                "(account_ed,peer_device_id,local_device_id,session_id,direction," +
                "state,generation,counter,prekey_wire,request_hash,created_at_ms) " +
                "VALUES (?,?,?,?,'tx','requested',?,0,?,?,?)",
                arrayOf(encoded(recipientAccount), peerId, identity.deviceId,
                    session, generation.generation, frame.wire, frame.exactWireHash, nowMs))
            db.setTransactionSuccessful()
            return Request(session, frame.wire)
        } finally { db.endTransaction() }
    }

    fun acceptRequest(frame: DeviceTransportFrame, identity: LocalDeviceIdentity,
                      nowMs: Long = System.currentTimeMillis()): ByteArray {
        require(frame.version == 2 && frame.kind == DeviceTransportFrame.Kind.SESSION_REQUEST &&
            frame.recipientDeviceId == identity.deviceId)
        authorize(frame.recipientAccount, identity.deviceId,
            frame.senderAccount, frame.senderDeviceId, nowMs)
        val peer = roster.authorizedPeer(frame.senderAccount, frame.senderDeviceId, 0x01, nowMs)
            ?: throw IllegalArgumentException("Unknown sender device")
        require(frame.verify(peer.signingKey))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            authorize(frame.recipientAccount, identity.deviceId,
                frame.senderAccount, frame.senderDeviceId, nowMs)
            val previous = db.query(SimpleSQLiteQuery(
                "SELECT prekey_wire,request_hash FROM device_transport_sessions " +
                    "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                    "AND direction='rx' AND generation=? LIMIT 1",
                arrayOf(encoded(frame.senderAccount), frame.senderDeviceId,
                    identity.deviceId, frame.counter)
            )).use { if (it.moveToFirst()) it.getBlob(0) to it.getBlob(1) else null }
            if (previous != null) {
                require(previous.second.contentEquals(frame.exactWireHash)) {
                    "Conflicting session request replay"
                }
                db.setTransactionSuccessful()
                return previous.first
            }
            val retired = readU64(frame.payload)
            DeviceTransportEpochStore.admit(db, frame.senderAccount,
                frame.senderDeviceId, identity.deviceId, frame.counter, retired)
            val count = db.query(SimpleSQLiteQuery(
                "SELECT COUNT(*) FROM device_transport_sessions WHERE account_ed=? " +
                    "AND peer_device_id=? AND local_device_id=? AND direction='rx'",
                arrayOf(encoded(frame.senderAccount), frame.senderDeviceId, identity.deviceId)
            )).use { check(it.moveToFirst()); it.getInt(0) }
            require(count < 2) { "Receiving session capacity reached" }
            val seed = DeviceTransportFrame.randomId()
            val pair = try { RustBridge.generateHybridKEMKeypairFromSeed(seed) }
                finally { seed.fill(0) }
            try {
                require(pair.size == 4800)
                val payload = pair.copyOfRange(0, 32) + pair.copyOfRange(64, 1632)
                val reply = DeviceTransportFrame.sign(DeviceTransportFrame.Kind.PREKEY,
                    frame.recipientAccount, frame.senderAccount, identity.deviceId,
                    frame.senderDeviceId, frame.sessionId, frame.counter,
                    ByteArray(32), payload, identity)
                db.execSQL("INSERT INTO device_transport_sessions " +
                    "(account_ed,peer_device_id,local_device_id,session_id,direction," +
                    "state,generation,counter,prekey_wire,prekey_x,prekey_kem," +
                    "request_hash,created_at_ms) " +
                    "VALUES (?,?,?,?,'rx','prekey',?,0,?,?,?,?,?)",
                    arrayOf(encoded(frame.senderAccount), frame.senderDeviceId,
                        identity.deviceId, frame.sessionId, frame.counter, reply.wire,
                        pair.copyOfRange(32, 64), pair.copyOfRange(1632, 4800),
                        frame.exactWireHash, nowMs))
                db.setTransactionSuccessful()
                return reply.wire
            } finally { pair.fill(0) }
        } finally { db.endTransaction() }
    }

    fun acceptPrekey(frame: DeviceTransportFrame, identity: LocalDeviceIdentity,
                     nowMs: Long = System.currentTimeMillis()) {
        require(frame.version == 2 && frame.kind == DeviceTransportFrame.Kind.PREKEY &&
            frame.recipientDeviceId == identity.deviceId)
        authorize(frame.recipientAccount, identity.deviceId,
            frame.senderAccount, frame.senderDeviceId, nowMs)
        val peer = roster.authorizedPeer(frame.senderAccount, frame.senderDeviceId, 0x01, nowMs)
            ?: throw IllegalArgumentException("Unknown prekey sender")
        require(frame.verify(peer.signingKey))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            authorize(frame.recipientAccount, identity.deviceId,
                frame.senderAccount, frame.senderDeviceId, nowMs)
            val row = db.query(SimpleSQLiteQuery(
                "SELECT state,generation,prekey_wire FROM device_transport_sessions " +
                    "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                    "AND session_id=? AND direction='tx' LIMIT 1",
                arrayOf(encoded(frame.senderAccount), frame.senderDeviceId,
                    identity.deviceId, frame.sessionId)
            )).use { if (it.moveToFirst()) Triple(it.getString(0), it.getLong(1),
                it.getBlob(2)) else null } ?: throw IllegalArgumentException("Unknown session")
            require(row.second == frame.counter)
            if (row.first == "ready") {
                require(row.third.contentEquals(frame.wire))
                db.setTransactionSuccessful()
                return
            }
            require(row.first == "requested")
            val encapsulated = RustBridge.hybridEncapsulate(
                frame.payload.copyOfRange(0, 32), frame.payload.copyOfRange(32, 1600))
            try {
                require(encapsulated.size == 1664)
                val chain = RustBridge.deriveRootKey(encapsulated.copyOfRange(0, 64),
                    frame.keyContext)
                try {
                    require(chain.size == 32)
                    db.execSQL("UPDATE device_transport_sessions SET state='ready'," +
                        "chain_key=?,initial_cipher=?,prekey_wire=?,counter=0 " +
                        "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                        "AND session_id=? AND direction='tx' AND state='requested'",
                        arrayOf(chain, encapsulated.copyOfRange(64, 1664), frame.wire,
                            encoded(frame.senderAccount), frame.senderDeviceId,
                            identity.deviceId, frame.sessionId))
                    db.setTransactionSuccessful()
                } finally { chain.fill(0) }
            } finally { encapsulated.fill(0) }
        } finally { db.endTransaction() }
    }

    /** Store plaintext before sending; the first send atomically seals the exact retry wire. */
    fun queuePayload(localAccount: ByteArray, recipientAccount: ByteArray,
                     peerId: String, plaintext: ByteArray, identity: LocalDeviceIdentity,
                     nowMs: Long = System.currentTimeMillis()): ByteArray {
        require(localAccount.size == 32 && recipientAccount.size == 32 &&
            plaintext.isNotEmpty() && plaintext.size <= 5 * 1024 * 1024)
        val sessionId = request(localAccount, recipientAccount, peerId, identity, nowMs).sessionId
        authorize(localAccount, identity.deviceId, recipientAccount, peerId, nowMs)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            authorize(localAccount, identity.deviceId, recipientAccount, peerId, nowMs)
            val session = db.query(SimpleSQLiteQuery(
                "SELECT session_id,prekey_wire,state FROM device_transport_sessions WHERE account_ed=? " +
                    "AND peer_device_id=? AND local_device_id=? AND session_id=? AND direction='tx' " +
                    "AND state IN ('requested','ready') LIMIT 1",
                arrayOf(encoded(recipientAccount), peerId, identity.deviceId, sessionId)
            )).use { if (it.moveToFirst()) it.getBlob(0) to it.getBlob(1) else null }
                ?: throw IllegalStateException("No active transport session")
            val sessionFrame = DeviceTransportFrame.parse(session.second)
            require((sessionFrame.kind == DeviceTransportFrame.Kind.SESSION_REQUEST &&
                sessionFrame.senderAccount.contentEquals(localAccount)) ||
                (sessionFrame.kind == DeviceTransportFrame.Kind.PREKEY &&
                    sessionFrame.recipientAccount.contentEquals(localAccount))) {
                "Account does not own transport session"
            }
            val jobId = DeviceTransportFrame.randomId()
            val logicalId = DeviceTransportFrame.logicalId(localAccount, identity.deviceId, jobId)
            db.execSQL("INSERT INTO device_transport_jobs " +
                "(account_ed,peer_device_id,local_device_id,job_id,logical_id," +
                "session_id,plaintext,created_at_ms) VALUES (?,?,?,?,?,?,?,?)",
                arrayOf(encoded(recipientAccount), peerId, identity.deviceId, jobId,
                logicalId, session.first, plaintext, nowMs))
            db.setTransactionSuccessful()
            return jobId
        } finally { db.endTransaction() }
    }

    /** Return the oldest exact wire for retry, sealing a queued draft when necessary. */
    fun nextDataWire(localAccount: ByteArray, identity: LocalDeviceIdentity,
                     draftOnly: Boolean = false): ByteArray? {
        rehomeDraft(localAccount, identity)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val pending = db.query(SimpleSQLiteQuery(
                "SELECT j.account_ed,j.peer_device_id,j.job_id,j.session_id,j.plaintext," +
                    "j.wire,s.counter,s.chain_key,s.initial_cipher,s.prekey_wire " +
                    "FROM device_transport_jobs j JOIN device_transport_sessions s ON " +
                    "s.account_ed=j.account_ed AND s.peer_device_id=j.peer_device_id AND " +
                    "s.local_device_id=j.local_device_id AND s.session_id=j.session_id " +
                    "AND s.direction='tx' WHERE j.local_device_id=? AND s.state='ready' " +
                    "AND (?=0 OR j.wire IS NULL) " +
                    "ORDER BY j.created_at_ms LIMIT 1",
                arrayOf(identity.deviceId, if (draftOnly) 1 else 0)
            )).use { c ->
                if (!c.moveToFirst()) null else DataDraft(c.getString(0), c.getString(1),
                    c.getBlob(2), c.getBlob(3), if (c.isNull(4)) null else c.getBlob(4),
                    if (c.isNull(5)) null else c.getBlob(5), c.getLong(6),
                    if (c.isNull(7)) null else c.getBlob(7),
                    if (c.isNull(8)) null else c.getBlob(8), c.getBlob(9))
            } ?: return null
            val recipient = Base64.getDecoder().decode(pending.account)
            require(DeviceTransportFrame.parse(pending.prekey).recipientAccount
                .contentEquals(localAccount)) { "Account does not own transport session" }
            authorize(localAccount, identity.deviceId, recipient, pending.peer, System.currentTimeMillis())
            if (pending.wire != null) {
                db.setTransactionSuccessful()
                return pending.wire
            }
            val plain = pending.plaintext ?: throw IllegalStateException("Missing transport draft")
            val chain = pending.chain ?: throw IllegalStateException("Missing send chain")
            require(pending.counter in 0 until DeviceTransportFrame.MAX_COUNTER)
            val encrypted = RustBridge.encryptMessageWithEvolution(
                String(plain, Charsets.ISO_8859_1), chain, pending.counter)
            try {
                val payload = byteArrayOf(if (pending.initial == null) 0 else 1) +
                    (pending.initial ?: ByteArray(0)) + encrypted.ciphertext
                val frame = DeviceTransportFrame.sign(DeviceTransportFrame.Kind.DATA,
                    localAccount, recipient, identity.deviceId, pending.peer,
                    pending.session, pending.counter, pending.job, payload, identity)
                db.execSQL("UPDATE device_transport_jobs SET wire=?,wire_hash=?," +
                    "plaintext=NULL,counter=?,next_try_at_ms=0 WHERE account_ed=? " +
                    "AND peer_device_id=? AND local_device_id=? AND job_id=? AND wire IS NULL",
                    arrayOf(frame.wire, frame.exactWireHash, pending.counter, pending.account,
                        pending.peer, identity.deviceId, pending.job))
                db.execSQL("UPDATE device_transport_sessions SET counter=?,chain_key=? " +
                    "WHERE account_ed=? AND peer_device_id=? " +
                    "AND local_device_id=? AND session_id=? AND direction='tx' AND counter=?",
                    arrayOf(pending.counter + 1, encrypted.evolvedChainKey,
                        pending.account, pending.peer, identity.deviceId, pending.session,
                        pending.counter))
                db.setTransactionSuccessful()
                return frame.wire
            } finally { encrypted.evolvedChainKey.fill(0) }
        } finally { db.endTransaction() }
    }

    data class PendingSend(val peerId: String, val onion: String, val wire: ByteArray)

    fun dueSends(identity: LocalDeviceIdentity, nowMs: Long = System.currentTimeMillis(),
                 limit: Int = 24): List<PendingSend> {
        require(limit in 1..64)
        val db = database.openHelper.readableDatabase
        val requests = db.query(SimpleSQLiteQuery(
            "SELECT s.account_ed,s.peer_device_id,a.syncOnion,s.prekey_wire " +
                "FROM device_transport_sessions s JOIN authorized_devices a " +
                "ON a.accountEd=s.account_ed AND a.deviceId=s.peer_device_id " +
                "WHERE s.local_device_id=? AND s.direction='tx' AND s.state='requested' " +
                "AND a.expiresAtMs>? AND (a.capabilities & 1)=1 " +
                "ORDER BY s.created_at_ms LIMIT ?",
            arrayOf(identity.deviceId, nowMs, limit)
        )).use { c -> buildList {
            while (c.moveToNext()) {
                val account = Base64.getDecoder().decode(c.getString(0))
                if (roster.isAuthorized(account, c.getString(1), 0x01, nowMs))
                    add(PendingSend(c.getString(1), c.getString(2), c.getBlob(3)))
            }
        } }
        if (requests.size >= limit) return requests
        val jobs = db.query(SimpleSQLiteQuery(
            "SELECT j.account_ed,j.peer_device_id,a.syncOnion,j.wire " +
                "FROM device_transport_jobs j JOIN authorized_devices a " +
                "ON a.accountEd=j.account_ed AND a.deviceId=j.peer_device_id " +
                "WHERE j.local_device_id=? AND j.wire IS NOT NULL " +
                "AND j.next_try_at_ms<=? AND a.expiresAtMs>? AND (a.capabilities & 1)=1 " +
                "ORDER BY j.next_try_at_ms,j.created_at_ms LIMIT ?",
            arrayOf(identity.deviceId, nowMs, nowMs, limit - requests.size)
        )).use { c -> buildList {
            while (c.moveToNext()) {
                val account = Base64.getDecoder().decode(c.getString(0))
                if (roster.isAuthorized(account, c.getString(1), 0x01, nowMs))
                    add(PendingSend(c.getString(1), c.getString(2), c.getBlob(3)))
            }
        } }
        return requests + jobs
    }

    fun recordSendAttempt(wire: ByteArray, nowMs: Long = System.currentTimeMillis()) {
        val frame = DeviceTransportFrame.parse(wire)
        if (frame.kind != DeviceTransportFrame.Kind.DATA) return
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val account = encoded(frame.recipientAccount)
            val attempts = db.query(SimpleSQLiteQuery(
                "SELECT attempts FROM device_transport_jobs WHERE account_ed=? " +
                    "AND peer_device_id=? AND job_id=? AND wire_hash=?",
                arrayOf(account, frame.recipientDeviceId, frame.jobId, frame.exactWireHash)
            )).use { if (it.moveToFirst()) it.getInt(0) else null } ?: return
            val delays = longArrayOf(2_000, 5_000, 10_000, 30_000, 60_000, 120_000)
            db.execSQL("UPDATE device_transport_jobs SET attempts=attempts+1," +
                "next_try_at_ms=? WHERE account_ed=? AND peer_device_id=? " +
                "AND job_id=? AND wire_hash=?",
                arrayOf(nowMs + delays[attempts.coerceIn(0, delays.lastIndex)], account,
                    frame.recipientDeviceId, frame.jobId, frame.exactWireHash))
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    /** Payload commit and exact-wire ACK share one database transaction. */
    fun acceptData(frame: DeviceTransportFrame, identity: LocalDeviceIdentity,
                   commitPayload: (SupportSQLiteDatabase, String, ByteArray) -> Boolean,
                   nowMs: Long = System.currentTimeMillis()): ByteArray {
        require(frame.version == 2 && frame.kind == DeviceTransportFrame.Kind.DATA &&
            frame.recipientDeviceId == identity.deviceId)
        authorize(frame.recipientAccount, identity.deviceId,
            frame.senderAccount, frame.senderDeviceId, nowMs)
        val peer = roster.authorizedPeer(frame.senderAccount, frame.senderDeviceId, 0x01, nowMs)
            ?: throw IllegalArgumentException("Unknown sender device")
        require(frame.verify(peer.signingKey))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            authorize(frame.recipientAccount, identity.deviceId,
                frame.senderAccount, frame.senderDeviceId, nowMs)
            val account = encoded(frame.senderAccount)
            val old = db.query(SimpleSQLiteQuery(
                "SELECT session_id,counter,wire_hash,ack_wire FROM device_transport_receipts " +
                    "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                    "AND (job_id=? OR (session_id=? AND counter=?)) LIMIT 2",
                arrayOf(account, frame.senderDeviceId, identity.deviceId, frame.jobId,
                    frame.sessionId, frame.counter)
            )).use { c -> buildList {
                while (c.moveToNext()) add(Receipt(c.getBlob(0), c.getLong(1),
                    c.getBlob(2), c.getBlob(3)))
            } }
            if (old.isNotEmpty()) {
                require(old.size == 1 && old[0].session.contentEquals(frame.sessionId) &&
                    old[0].counter == frame.counter &&
                    old[0].hash.contentEquals(frame.exactWireHash)) {
                    "Conflicting transport replay"
                }
                db.setTransactionSuccessful()
                return old[0].ack
            }
            val receiptCount = db.query(SimpleSQLiteQuery(
                "SELECT COUNT(*) FROM device_transport_receipts"
            )).use { check(it.moveToFirst()); it.getLong(0) }
            require(receiptCount < MAX_RECEIPTS) { "Transport receipt capacity reached" }
            val session = db.query(SimpleSQLiteQuery(
                "SELECT state,counter,chain_key,prekey_wire,prekey_x,prekey_kem " +
                    "FROM device_transport_sessions WHERE account_ed=? AND peer_device_id=? " +
                    "AND local_device_id=? AND session_id=? AND direction='rx'",
                arrayOf(account, frame.senderDeviceId, identity.deviceId, frame.sessionId)
            )).use { c -> if (!c.moveToFirst()) null else ReceiveSession(c.getString(0),
                c.getLong(1), if (c.isNull(2)) null else c.getBlob(2), c.getBlob(3),
                if (c.isNull(4)) null else c.getBlob(4),
                if (c.isNull(5)) null else c.getBlob(5)) }
                ?: throw IllegalArgumentException("Unknown transport session")
            if (frame.counter != session.counter) Log.i(TAG,
                "C0 receive ${if (frame.counter > session.counter) "gap" else "late"}: " +
                    "received=${frame.counter} expected=${session.counter} " +
                    "session=${sha256(frame.sessionId)} wire=${frame.exactWireHash.toHex()}")
            val decrypted = decryptData(db, frame, session, account, identity.deviceId)
            try {
                val logicalId = DeviceTransportFrame.logicalId(frame.senderAccount,
                    frame.senderDeviceId, frame.jobId)
                val ready = commitPayload(db, logicalId, decrypted.plain)
                val ack = DeviceTransportFrame.sign(
                    if (ready) DeviceTransportFrame.Kind.ACCOUNT_STORAGE_ACK
                        else DeviceTransportFrame.Kind.DEVICE_STORAGE_ACK,
                    frame.recipientAccount, frame.senderAccount, identity.deviceId,
                    frame.senderDeviceId, frame.sessionId, frame.counter, frame.jobId,
                    frame.exactWireHash, identity)
                if (decrypted.nextChain != null) {
                    db.execSQL("UPDATE device_transport_sessions SET state='ready',chain_key=?," +
                        "counter=?,prekey_x=NULL,prekey_kem=NULL WHERE account_ed=? " +
                        "AND peer_device_id=? AND local_device_id=? AND session_id=? AND direction='rx'",
                        arrayOf(decrypted.nextChain, frame.counter + 1, account,
                            frame.senderDeviceId, identity.deviceId, frame.sessionId))
                    val pruneBefore = maxOf(0L, frame.counter + 1 - SKIPPED_RETENTION)
                    db.execSQL("DELETE FROM device_transport_skipped_keys WHERE " +
                        "account_ed=? AND peer_device_id=? AND local_device_id=? " +
                        "AND session_id=? AND counter<?",
                        arrayOf(account, frame.senderDeviceId, identity.deviceId,
                            frame.sessionId, pruneBefore))
                }
                db.execSQL("INSERT INTO device_transport_receipts " +
                    "(account_ed,peer_device_id,local_device_id,session_id,counter," +
                    "job_id,wire_hash,ack_wire,committed_at_ms) VALUES (?,?,?,?,?,?,?,?,?)",
                    arrayOf(account, frame.senderDeviceId, identity.deviceId,
                        frame.sessionId, frame.counter, frame.jobId,
                        frame.exactWireHash, ack.wire, nowMs))
                db.setTransactionSuccessful()
                return ack.wire
            } finally { decrypted.plain.fill(0); decrypted.nextChain?.fill(0) }
        } finally { db.endTransaction() }
    }

    /** Ratchet movement and skipped-key consumption are enclosed by acceptData's transaction. */
    private fun decryptData(db: SupportSQLiteDatabase, frame: DeviceTransportFrame,
                            session: ReceiveSession, account: String,
                            localDeviceId: String): ReceivePlain {
        require(frame.counter < DeviceTransportFrame.MAX_COUNTER)
        val initial = frame.payload[0].toInt() == 1
        val encrypted = frame.payload.copyOfRange(1 + if (initial) 1600 else 0,
            frame.payload.size)
        require(encrypted.size >= 49 && encrypted[0] == 1.toByte() &&
            java.nio.ByteBuffer.wrap(encrypted, 1, 8).long == frame.counter) {
            "Invalid transport ciphertext sequence"
        }
        if (frame.counter < session.counter) {
            require(session.state == "ready") { "Old transport counter" }
            val key = db.query(SimpleSQLiteQuery(
                "SELECT message_key FROM device_transport_skipped_keys WHERE " +
                    "account_ed=? AND peer_device_id=? AND local_device_id=? " +
                    "AND session_id=? AND counter=? LIMIT 1",
                arrayOf(account, frame.senderDeviceId, localDeviceId,
                    frame.sessionId, frame.counter)
            )).use { if (it.moveToFirst()) it.getBlob(0) else null }
                ?: throw IllegalArgumentException("Old or replayed transport counter")
            try {
                require(key.size == 32)
                val text = RustBridge.decryptWithMessageKey(encrypted, key)
                    ?: throw IllegalArgumentException("Invalid skipped transport ciphertext")
                val plain = text.toByteArray(Charsets.ISO_8859_1)
                try {
                    db.execSQL("DELETE FROM device_transport_skipped_keys WHERE " +
                        "account_ed=? AND peer_device_id=? AND local_device_id=? " +
                        "AND session_id=? AND counter=?",
                        arrayOf(account, frame.senderDeviceId, localDeviceId,
                            frame.sessionId, frame.counter))
                    return ReceivePlain(plain, null)
                } catch (e: Exception) { plain.fill(0); throw e }
            } finally { key.fill(0); session.chain?.fill(0) }
        }
        require(frame.counter - session.counter < RECEIVE_WINDOW) {
            "Transport counter gap exceeds receive window"
        }
        var chain = if (session.state == "prekey") {
            require(initial && frame.counter < RECEIVE_WINDOW &&
                session.prekeyX != null && session.prekeyKem != null) {
                "Initial transport packet required"
            }
            val prekey = DeviceTransportFrame.parse(session.prekeyWire)
            val secret = RustBridge.hybridDecapsulate(session.prekeyX,
                session.prekeyKem, frame.payload.copyOfRange(1, 1601))
                ?: throw IllegalArgumentException("Invalid hybrid ciphertext")
            try { RustBridge.deriveRootKey(secret, prekey.keyContext) }
            finally { secret.fill(0) }
        } else {
            require(session.state == "ready")
            session.chain ?: throw IllegalArgumentException("Missing receive chain")
        }
        try {
            require(chain.size == 32)
            var missing = session.counter
            while (missing < frame.counter) {
                val key = RustBridge.deriveMessageKey(chain)
                var next: ByteArray? = null
                try {
                    require(key.size == 32)
                    next = RustBridge.evolveChainKey(chain)
                    require(next.size == 32)
                    db.execSQL("INSERT INTO device_transport_skipped_keys " +
                        "(account_ed,peer_device_id,local_device_id,session_id,counter," +
                        "message_key) VALUES (?,?,?,?,?,?)",
                        arrayOf(account, frame.senderDeviceId, localDeviceId,
                            frame.sessionId, missing, key))
                    chain.fill(0)
                    chain = next
                    next = null
                    missing++
                } finally { key.fill(0); next?.fill(0) }
            }
            val decrypted = RustBridge.decryptMessageWithEvolution(encrypted, chain,
                frame.counter) ?: throw IllegalArgumentException("Invalid transport ciphertext")
            require(decrypted.evolvedChainKey.size == 32)
            return ReceivePlain(decrypted.plaintext.toByteArray(Charsets.ISO_8859_1),
                decrypted.evolvedChainKey)
        } finally { chain.fill(0) }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 255)
    }

    fun acceptAcknowledgment(frame: DeviceTransportFrame, identity: LocalDeviceIdentity,
                             nowMs: Long = System.currentTimeMillis()) {
        require(frame.version == 2 && frame.kind in listOf(
            DeviceTransportFrame.Kind.DEVICE_STORAGE_ACK,
            DeviceTransportFrame.Kind.ACCOUNT_STORAGE_ACK) &&
            frame.recipientDeviceId == identity.deviceId)
        authorize(frame.recipientAccount, identity.deviceId,
            frame.senderAccount, frame.senderDeviceId, nowMs)
        val peer = roster.authorizedPeer(frame.senderAccount, frame.senderDeviceId, 0x01, nowMs)
            ?: throw IllegalArgumentException("Unknown ACK sender")
        require(frame.verify(peer.signingKey))
        if (frame.kind == DeviceTransportFrame.Kind.ACCOUNT_STORAGE_ACK)
            require(roster.isAuthorized(frame.senderAccount, frame.senderDeviceId,
                0x03, nowMs))
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            val account = encoded(frame.senderAccount)
            val logicalId = db.query(SimpleSQLiteQuery(
                "SELECT logical_id,session_id,counter,wire_hash FROM device_transport_jobs " +
                    "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? AND job_id=?",
                arrayOf(account, frame.senderDeviceId, identity.deviceId, frame.jobId)
            )).use { c -> if (c.moveToFirst() && c.getBlob(1).contentEquals(frame.sessionId) &&
                c.getLong(2) == frame.counter && c.getBlob(3).contentEquals(frame.payload))
                c.getString(0) else null }
                ?: throw IllegalArgumentException("Invalid transport acknowledgment")
            db.execSQL("UPDATE device_transport_sessions SET initial_cipher=NULL " +
                "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                "AND session_id=? AND direction='tx'",
                arrayOf(account, frame.senderDeviceId, identity.deviceId, frame.sessionId))
            db.execSQL("DELETE FROM device_transport_jobs WHERE account_ed=? AND " +
                "peer_device_id=? AND local_device_id=? AND job_id=?",
                arrayOf(account, frame.senderDeviceId, identity.deviceId, frame.jobId))
            db.execSQL("UPDATE messages SET status=MAX(status,2),messageDelivered=1 " +
                "WHERE messageId=? AND isSentByMe=1", arrayOf(logicalId))
            val linkedTable = db.query(SimpleSQLiteQuery(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND " +
                    "name='linked_chat_messages'"
            )).use { it.moveToFirst() }
            if (linkedTable) {
                db.execSQL("UPDATE linked_chat_messages SET status=MAX(status,2) " +
                    "WHERE message_id=? AND sent_by_me=1", arrayOf(logicalId))
                db.execSQL("INSERT INTO device_sync_source_changes " +
                    "(topic,object_id,kind,changed_at_ms) " +
                    "VALUES ('messages',?,'receipt',?)",
                    arrayOf(logicalId, nowMs))
            }
            if (frame.kind == DeviceTransportFrame.Kind.ACCOUNT_STORAGE_ACK) {
                val retired = db.query(SimpleSQLiteQuery(
                    "SELECT DISTINCT peer_device_id,session_id FROM device_transport_jobs " +
                        "WHERE account_ed=? AND local_device_id=? AND logical_id=? " +
                        "AND wire IS NOT NULL AND peer_device_id IN " +
                        "(SELECT deviceId FROM authorized_devices WHERE accountEd=? " +
                        "AND (capabilities & 3)=3)",
                    arrayOf(account, identity.deviceId, logicalId, account))).use { c ->
                    buildList { while (c.moveToNext()) add(c.getString(0) to c.getBlob(1)) }
                }
                for ((cancelledPeer, session) in retired)
                    DeviceTransportEpochStore.markRetiring(db, frame.senderAccount,
                        cancelledPeer, identity.deviceId, session)
                db.execSQL("DELETE FROM device_transport_jobs WHERE account_ed=? " +
                    "AND local_device_id=? AND logical_id=? AND peer_device_id IN " +
                    "(SELECT deviceId FROM authorized_devices WHERE accountEd=? " +
                    "AND (capabilities & 3)=3)",
                    arrayOf(account, identity.deviceId, logicalId, account))
                for (cancelledPeer in retired.map { it.first }.toSet())
                    DeviceTransportEpochStore.reap(db, frame.senderAccount,
                        cancelledPeer, identity.deviceId)
            }
            DeviceTransportEpochStore.reap(db, frame.senderAccount,
                frame.senderDeviceId, identity.deviceId)
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    private fun rehomeDraft(localAccount: ByteArray, identity: LocalDeviceIdentity) {
        val db = database.openHelper.writableDatabase
        val orphans = db.query(SimpleSQLiteQuery("SELECT account_ed,peer_device_id " +
            "FROM device_transport_jobs WHERE local_device_id=? AND " +
            "length(session_id)=0 AND wire IS NULL " +
            "GROUP BY account_ed,peer_device_id ORDER BY MIN(created_at_ms) LIMIT 8",
            arrayOf(identity.deviceId))).use { c -> buildList {
            while (c.moveToNext()) add(c.getString(0) to c.getString(1))
        } }
        for ((encodedAccount, peerId) in orphans) try {
            val account = Base64.getDecoder().decode(encodedAccount)
            val session = request(localAccount, account, peerId, identity).sessionId
            db.beginTransaction()
            try {
                authorize(localAccount, identity.deviceId, account, peerId,
                    System.currentTimeMillis())
                db.execSQL("UPDATE device_transport_jobs SET session_id=? " +
                    "WHERE account_ed=? AND peer_device_id=? AND local_device_id=? " +
                    "AND length(session_id)=0 AND wire IS NULL AND counter IS NULL " +
                    "AND wire_hash IS NULL AND plaintext IS NOT NULL",
                    arrayOf(session, encodedAccount, peerId, identity.deviceId))
                db.setTransactionSuccessful()
            } finally { db.endTransaction() }
        } catch (error: Exception) {
            Log.w(TAG, "Transport draft rehome deferred for $peerId: ${error.message}")
        }
    }

    private data class DataDraft(val account: String, val peer: String, val job: ByteArray,
        val session: ByteArray, val plaintext: ByteArray?, val wire: ByteArray?,
        val counter: Long, val chain: ByteArray?, val initial: ByteArray?,
        val prekey: ByteArray)
    private data class ReceiveSession(val state: String, val counter: Long,
        val chain: ByteArray?, val prekeyWire: ByteArray,
        val prekeyX: ByteArray?, val prekeyKem: ByteArray?)
    private data class ReceivePlain(val plain: ByteArray, val nextChain: ByteArray?)
    private data class Receipt(val session: ByteArray, val counter: Long,
        val hash: ByteArray, val ack: ByteArray)

    private fun authorize(localAccount: ByteArray, localId: String,
                          peerAccount: ByteArray, peerId: String, nowMs: Long) {
        require(roster.isLocalAuthorized(localAccount, localId, 0x01, nowMs) &&
            roster.isAuthorized(peerAccount, peerId, 0x01, nowMs)) {
            "C0 device is not authorized"
        }
    }

    private fun encoded(account: ByteArray) = Base64.getEncoder().encodeToString(account)
    private fun readU64(bytes: ByteArray): Long {
        require(bytes.size == 8)
        return bytes.fold(0L) { n, byte -> (n shl 8) or (byte.toLong() and 0xff) }
    }
    private fun writeU64(bytes: ByteArray, value: Long) {
        for (index in 0..7) bytes[index] = (value ushr ((7 - index) * 8)).toByte()
    }
}
