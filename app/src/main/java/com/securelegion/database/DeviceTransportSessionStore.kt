package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceTransportFrame
import java.util.Base64

/** C0v2 request/prekey handshake, persisted before any network reply. */
internal class DeviceTransportSessionStore(
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore
) {
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
