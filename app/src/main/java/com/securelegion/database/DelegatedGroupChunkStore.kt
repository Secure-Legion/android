package com.securelegion.database

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.sync.DeviceGroupFrame
import java.nio.charset.StandardCharsets

/** Restart safe encrypted staging. Completion is not group acceptance or an ACK. */
internal class DelegatedGroupChunkStore(private val database: SecureLegionDatabase) {
    data class Complete(val transferId: String, val firstWire: ByteArray,
                        val bundle: ByteArray, val staged: Boolean)

    /** Caller must authorize both devices and verify the C2 signature/decryption first. */
    fun stage(frame: DeviceGroupFrame, localDeviceId: String, plaintext: ByteArray,
              nowMs: Long = System.currentTimeMillis()): Complete? {
        require(frame.carriesData && localDeviceId == frame.recipientDeviceId &&
            plaintext.size == frame.expectedPlaintextLength && nowMs > 0)
        val id = transferId(frame, localDeviceId)
        val db = database.openHelper.writableDatabase
        db.beginTransaction()
        try {
            pruneExpired(db, nowMs)
            val current = readTransfer(db, id)
            if (current == null) {
                require(capacityAvailable(db, frame, plaintext.size)) {
                    "Group staging capacity exceeded"
                }
                db.execSQL("INSERT INTO delegated_group_inbox (id,local_device,group_id," +
                    "sender_account,sender_device,bundle_id,bundle_hash,bundle_length," +
                    "chunk_count,first_wire,first_received_at_ms,expires_at_ms) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", arrayOf(id, localDeviceId,
                        hex(frame.groupId), hex(frame.senderAccount), frame.senderDeviceId,
                        frame.bundleId, frame.bundleHash, frame.bundleLength, frame.chunkCount,
                        frame.wire, nowMs, nowMs + EXPIRY_MS))
            } else {
                require(current.localDevice == localDeviceId &&
                    current.groupId == hex(frame.groupId) &&
                    current.senderAccount == hex(frame.senderAccount) &&
                    current.senderDevice == frame.senderDeviceId &&
                    current.bundleId.contentEquals(frame.bundleId) &&
                    current.bundleHash.contentEquals(frame.bundleHash) &&
                    current.bundleLength == frame.bundleLength &&
                    current.chunkCount == frame.chunkCount &&
                    current.kind == frame.kind && current.expiresAtMs > nowMs) {
                    "Conflicting or expired group transfer"
                }
            }
            val digest = hex(DeviceGroupFrame.hash(plaintext))
            val wireDigest = hex(DeviceGroupFrame.hash(frame.wire))
            val prior = db.query(SimpleSQLiteQuery(
                "SELECT chunk_hash,plaintext,wire_hash FROM delegated_group_inbox_chunks " +
                    "WHERE transfer_id=? AND chunk_index=?", arrayOf(id, frame.chunkIndex)
            )).use { if (it.moveToFirst()) Triple(it.getString(0), it.getBlob(1),
                it.getString(2)) else null }
            if (prior != null) {
                val same = prior.first == digest && prior.second.contentEquals(plaintext) &&
                    prior.third == wireDigest
                prior.second.fill(0)
                require(same) {
                    "Conflicting group chunk replay"
                }
            } else {
                require(stagedBytes(db) + plaintext.size <= MAX_STAGED_BYTES) {
                    "Group staging capacity exceeded"
                }
                db.execSQL("INSERT INTO delegated_group_inbox_chunks " +
                    "(transfer_id,chunk_index,plaintext,chunk_hash,wire_hash) " +
                    "VALUES (?,?,?,?,?)",
                    arrayOf(id, frame.chunkIndex, plaintext, digest, wireDigest))
            }
            val complete = assemble(db, id, frame)
            db.setTransactionSuccessful()
            return complete
        } catch (error: Exception) {
            // Do not expose SQLite bound values or private bundle bytes in logs.
            throw IllegalStateException("Group chunk staging rejected")
        } finally { db.endTransaction() }
    }

    /** Call in the same transaction that publishes the native validated bundle and ACK. */
    fun finishInTransaction(db: SupportSQLiteDatabase, complete: Complete) {
        require(db.inTransaction())
        db.execSQL("DELETE FROM delegated_group_inbox WHERE id=?",
            arrayOf(complete.transferId))
    }

    private data class Transfer(val localDevice: String, val groupId: String,
                                val senderAccount: String, val senderDevice: String,
                                val bundleId: ByteArray, val bundleHash: ByteArray,
                                val bundleLength: Int, val chunkCount: Int,
                                val kind: DeviceGroupFrame.Kind, val expiresAtMs: Long,
                                val firstWire: ByteArray)

    private fun readTransfer(db: SupportSQLiteDatabase, id: String): Transfer? =
        db.query(SimpleSQLiteQuery("SELECT local_device,group_id,sender_account,sender_device," +
            "bundle_id,bundle_hash,bundle_length,chunk_count,first_wire,expires_at_ms " +
            "FROM delegated_group_inbox WHERE id=?", arrayOf(id))).use { cursor ->
            if (!cursor.moveToFirst()) null else {
                val first = cursor.getBlob(8)
                val kind = DeviceGroupFrame.parse(first).kind
                Transfer(cursor.getString(0), cursor.getString(1), cursor.getString(2),
                    cursor.getString(3), cursor.getBlob(4), cursor.getBlob(5),
                    cursor.getInt(6), cursor.getInt(7), kind, cursor.getLong(9), first)
            }
        }

    private fun assemble(db: SupportSQLiteDatabase, id: String,
                         frame: DeviceGroupFrame): Complete? {
        val transfer = readTransfer(db, id) ?: return null
        val chunks = ArrayList<ByteArray>(frame.chunkCount)
        db.query(SimpleSQLiteQuery("SELECT chunk_index,plaintext,chunk_hash " +
            "FROM delegated_group_inbox_chunks WHERE transfer_id=? ORDER BY chunk_index",
            arrayOf(id))).use { cursor ->
            while (cursor.moveToNext()) {
                val index = cursor.getInt(0)
                val bytes = cursor.getBlob(1)
                require(index == chunks.size && index < frame.chunkCount &&
                    bytes.size == minOf(DeviceGroupFrame.CHUNK_BYTES,
                        frame.bundleLength - index * DeviceGroupFrame.CHUNK_BYTES) &&
                    cursor.getString(2) == hex(DeviceGroupFrame.hash(bytes))) {
                    "Corrupt group chunk staging"
                }
                chunks.add(bytes)
            }
        }
        if (chunks.size != frame.chunkCount) return null
        val bundle = ByteArray(frame.bundleLength)
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(bundle, offset)
            offset += chunk.size
            chunk.fill(0)
        }
        if (!DeviceGroupFrame.hash(bundle).contentEquals(frame.bundleHash)) {
            bundle.fill(0)
            db.execSQL("DELETE FROM delegated_group_inbox WHERE id=?", arrayOf(id))
            return null
        }
        return Complete(id, transfer.firstWire, bundle, true)
    }

    private fun capacityAvailable(db: SupportSQLiteDatabase, frame: DeviceGroupFrame,
                                  nextChunkSize: Int): Boolean {
        val counts = db.query(SimpleSQLiteQuery("SELECT count(*), " +
            "sum(CASE WHEN sender_account=? THEN 1 ELSE 0 END) FROM delegated_group_inbox",
            arrayOf(hex(frame.senderAccount)))).use { cursor ->
            cursor.moveToFirst()
            Pair(cursor.getInt(0), cursor.getInt(1))
        }
        return counts.first < MAX_TRANSFERS && counts.second < MAX_PER_SENDER &&
            stagedBytes(db) + frame.wire.size + nextChunkSize <= MAX_STAGED_BYTES
    }

    private fun stagedBytes(db: SupportSQLiteDatabase): Long = db.query(
        "SELECT COALESCE((SELECT sum(length(first_wire)) FROM delegated_group_inbox),0) + " +
            "COALESCE((SELECT sum(length(plaintext)) FROM delegated_group_inbox_chunks),0)"
    ).use { it.moveToFirst(); it.getLong(0) }

    private fun pruneExpired(db: SupportSQLiteDatabase, nowMs: Long) {
        db.execSQL("DELETE FROM delegated_group_inbox WHERE expires_at_ms<=?",
            arrayOf(nowMs))
    }

    private fun transferId(frame: DeviceGroupFrame, localDeviceId: String): String =
        hex(DeviceGroupFrame.hash("Secure-GROUP-TRANSPORT-v1/transfer\u0000"
            .toByteArray(StandardCharsets.US_ASCII) + frame.recipientAccount +
            localDeviceId.toByteArray(StandardCharsets.US_ASCII) + frame.senderAccount +
            frame.senderDeviceId.toByteArray(StandardCharsets.US_ASCII) +
            frame.groupId + frame.bundleId))

    private fun hex(bytes: ByteArray) = bytes.joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }

    companion object {
        private const val MAX_TRANSFERS = 8
        private const val MAX_PER_SENDER = 2
        private const val MAX_STAGED_BYTES = 64L * 1024 * 1024
        private const val EXPIRY_MS = 60L * 60 * 1000
    }
}
