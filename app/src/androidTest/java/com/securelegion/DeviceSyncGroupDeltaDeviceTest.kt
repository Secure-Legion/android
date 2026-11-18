package com.securelegion

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.securelegion.sync.DeviceSyncGroupDelta
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceSyncGroupReceiver
import com.securelegion.sync.DeviceSyncGroupLinkPublisher
import androidx.test.platform.app.InstrumentationRegistry
import androidx.sqlite.db.SimpleSQLiteQuery
import android.util.Base64 as AndroidBase64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.util.Base64
import java.security.SecureRandom

@RunWith(AndroidJUnit4::class)
class DeviceSyncGroupDeltaDeviceTest {
    @Test fun signedGroupLinkImportsWithoutCreatingDirectContacts() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val pair = RustBridge.generateKeypair()
        val account = pair[0] as ByteArray
        val privateKey = pair[1] as ByteArray
        val account64 = AndroidBase64.encodeToString(account, AndroidBase64.NO_WRAP)
        val group = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val local = "J".repeat(43)
        val peer = "K".repeat(43)
        val relay = "L".repeat(43)
        val now = System.currentTimeMillis()
        try {
            for ((id, self) in listOf(local to 1, peer to 0, relay to 0)) {
                db.execSQL("INSERT OR REPLACE INTO authorized_devices " +
                    "(deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX,mlKemPublic," +
                    "certificate,capabilities,issuedAtMs,expiresAtMs,rosterEpoch,isSelf) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    arrayOf(id, account64, "test", "a".repeat(56) + ".onion",
                        ByteArray(32), ByteArray(32), ByteArray(1), ByteArray(1),
                        6, now - 1_000, now + 60_000, 1, self))
            }
            val secret64 = Base64.getEncoder().encodeToString(ByteArray(32) { 9 })
            val op = JSONObject(RustBridge.crdtCreateOp(group, "GroupCreate",
                JSONObject().put("group_name", "Sync test")
                    .put("encrypted_group_secret_b64", secret64).toString(),
                account, privateKey))
            val rawOp = Base64.getDecoder().decode(op.getString("op_bytes_b64"))
            val packed = byteArrayOf((rawOp.size ushr 24).toByte(),
                (rawOp.size ushr 16).toByte(), (rawOp.size ushr 8).toByte(),
                rawOp.size.toByte()) + rawOp
            val hash = MessageDigest.getInstance("SHA-256").digest(packed)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            val id = "$group:$hash"
            val delta = JSONObject().put("group_snapshot_id", id)
                .put("group_id", group)
                .put("packed_ops", Base64.getEncoder().encodeToString(packed))
                .put("group_secret", secret64)
            val identity = RustBridge.deviceHistoryIdentity(
                delta.toString().toByteArray(), "group_links", id, now)
            val digest = identity.copyOfRange(0, 32).joinToString("") {
                "%02x".format(it.toInt() and 255) }
            val event = identity.copyOfRange(32, 64).joinToString("") {
                "%02x".format(it.toInt() and 255) }
            val part = DeviceSyncChunkStore.Part(peer, "group_links", id, event,
                digest, now, 1, 0, 1, identity.copyOfRange(64, identity.size))
            val contactsBefore = db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM contacts"))
                .use { it.moveToFirst(); it.getInt(0) }
            val receiver = DeviceSyncGroupReceiver(database, DeviceRosterStore(database))
            assertEquals(DeviceSyncChunkStore.Result.COMMITTED,
                receiver.receive(account, local, part, now))
            assertEquals(DeviceSyncChunkStore.Result.COMMITTED,
                receiver.receive(account, local, part, now))
            db.query(SimpleSQLiteQuery("SELECT opType FROM crdt_op_log WHERE groupId=?",
                arrayOf(group))).use {
                assertTrue(it.moveToFirst())
                assertEquals("GroupLinkSync", it.getString(0))
            }
            val contactsAfter = db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM contacts"))
                .use { it.moveToFirst(); it.getInt(0) }
            assertEquals(contactsBefore, contactsAfter)
            val roster = DeviceRosterStore(database)
            val publisher = DeviceSyncGroupLinkPublisher(database, roster)
            publisher.prepare(account, local, peer, now)
            assertTrue(DeviceSyncOutboxStore(database, roster)
                .dueTor(account, local, peer, now).none { it.topic == "group_links" })
            publisher.prepare(account, local, relay, now)
            assertTrue(DeviceSyncOutboxStore(database, roster)
                .dueTor(account, local, relay, now).any { it.topic == "group_links" })
            val otherGroup = "e".repeat(64)
            val wrongId = "$otherGroup:$hash"
            val wrongDelta = JSONObject(delta.toString())
                .put("group_id", otherGroup).put("group_snapshot_id", wrongId)
            val wrongIdentity = RustBridge.deviceHistoryIdentity(
                wrongDelta.toString().toByteArray(), "group_links", wrongId, now)
            val wrongDigest = wrongIdentity.copyOfRange(0, 32).joinToString("") {
                "%02x".format(it.toInt() and 255) }
            val wrongEvent = wrongIdentity.copyOfRange(32, 64).joinToString("") {
                "%02x".format(it.toInt() and 255) }
            val wrongPart = DeviceSyncChunkStore.Part(peer, "group_links", wrongId,
                wrongEvent, wrongDigest, now, 1, 0, 1,
                wrongIdentity.copyOfRange(64, wrongIdentity.size))
            assertEquals(DeviceSyncChunkStore.Result.DEFERRED,
                receiver.receive(account, local, wrongPart, now))
            db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM groups WHERE groupId=?",
                arrayOf(otherGroup))).use { it.moveToFirst(); assertEquals(0, it.getInt(0)) }
        } finally {
            RustBridge.crdtUnloadGroup(group)
            db.execSQL("DELETE FROM crdt_op_log WHERE groupId=?", arrayOf(group))
            db.execSQL("DELETE FROM groups WHERE groupId=?", arrayOf(group))
            db.execSQL("DELETE FROM device_sync_versions WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_outbox WHERE peer_device_id=?", arrayOf(relay))
            db.execSQL("DELETE FROM device_sync_local_events WHERE topic='group_links' " +
                "AND object_id LIKE ?", arrayOf("$group:%"))
            db.execSQL("DELETE FROM device_sync_chunks WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_cursors WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?,?)",
                arrayOf(local, peer, relay))
            privateKey.fill(0)
            account.fill(0)
        }
    }

    @Test fun groupLinkQueueStopsImmediatelyWhenGroupAuthorityIsRemoved() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val account = ByteArray(32) { 0x6a }
        val account64 = AndroidBase64.encodeToString(account, AndroidBase64.NO_WRAP)
        val local = "G".repeat(43)
        val peer = "H".repeat(43)
        val now = System.currentTimeMillis()
        try {
            for ((id, self) in listOf(local to 1, peer to 0)) {
                db.execSQL("INSERT OR REPLACE INTO authorized_devices " +
                    "(deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX,mlKemPublic," +
                    "certificate,capabilities,issuedAtMs,expiresAtMs,rosterEpoch,isSelf) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    arrayOf(id, account64, "test", "a".repeat(56) + ".onion",
                        ByteArray(32), ByteArray(32), ByteArray(1), ByteArray(1),
                        6, now - 1_000, now + 60_000, 1, self))
            }
            db.execSQL("INSERT INTO device_sync_outbox " +
                "(peer_device_id,topic,object_id,event_id,event_time_ms,digest,sequence," +
                "delta_json,transport,next_try_at_ms,attempts,created_at_ms,is_live) " +
                "VALUES (?,'group_links',?,?,?,?,?,?,'TOR',0,0,?,0)",
                arrayOf(peer, "g:" + "a".repeat(64), "b".repeat(64), now,
                    ByteArray(32), 1, "{}".toByteArray(), now))
            val outbox = DeviceSyncOutboxStore(database, DeviceRosterStore(database))
            assertEquals(1, outbox.dueTor(account, local, peer, now).size)
            db.execSQL("UPDATE authorized_devices SET capabilities=2 WHERE deviceId=?",
                arrayOf(peer))
            assertTrue(outbox.dueTor(account, local, peer, now).isEmpty())
            db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM device_sync_outbox " +
                "WHERE peer_device_id=?", arrayOf(peer))).use {
                assertTrue(it.moveToFirst())
                assertEquals(1, it.getInt(0))
            }
        } finally {
            db.execSQL("DELETE FROM device_sync_outbox WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)",
                arrayOf(local, peer))
        }
    }

    @Test fun snapshotIdentityIsBoundToExactPackedOperations() {
        val group = "a".repeat(64)
        val packed = byteArrayOf(0, 0, 0, 1, 42)
        val digest = MessageDigest.getInstance("SHA-256").digest(packed)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val id = "$group:$digest"
        val delta = JSONObject().put("group_snapshot_id", id)
            .put("group_id", group)
            .put("packed_ops", Base64.getEncoder().encodeToString(packed))
            .put("group_secret", Base64.getEncoder().encodeToString(ByteArray(32) { 7 }))
        assertEquals(id, DeviceSyncGroupDelta.parse(delta, "groups", id)?.objectId)
        assertThrows(Exception::class.java) {
            DeviceSyncGroupDelta.parse(delta, "groups", "$group:${"b".repeat(64)}")
        }
        // A length-valid but unsigned operation cannot enter the Tor metadata lane.
        assertThrows(Exception::class.java) {
            DeviceSyncGroupDelta.parse(delta, "group_links", id)
        }
    }

    @Test fun packedGroupFramesRejectTruncationAndZeroLength() {
        assertTrue(DeviceSyncGroupDelta.validFraming(byteArrayOf(0, 0, 0, 1, 42)))
        assertFalse(DeviceSyncGroupDelta.validFraming(byteArrayOf(0, 0, 0, 2, 42)))
        assertFalse(DeviceSyncGroupDelta.validFraming(byteArrayOf(0, 0, 0, 0)))
    }
}
