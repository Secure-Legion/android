package com.securelegion

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceChatOutboundStore
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.LinkedChatStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.sync.DeviceSyncContactDelta
import com.securelegion.sync.DeviceSyncContactReceiver
import com.securelegion.sync.DeviceSyncLiveMessageReceiver
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.sync.DeviceSyncMediaFiles
import com.securelegion.sync.DeviceChatPayloadStore
import com.securelegion.sync.DeviceSyncMessageDelta
import com.securelegion.sync.DeviceTransportFrame
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LinkedChatStoreDeviceTest {
    @Test fun authenticatedContactAndLiveMessageImportWithoutWallet() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val roster = DeviceRosterStore(database)
        val store = LinkedChatStore(database, roster, { "ENC1:test-$it" },
            DeviceSyncMediaFiles(context, { it }, { it }))
        store.ensureSchema()
        val account = DeviceTransportFrame.randomId()
        val contactEd = DeviceTransportFrame.randomId()
        val contactX = DeviceTransportFrame.randomId()
        val accountB64 = Base64.encodeToString(account, Base64.NO_WRAP)
        val contactB64 = Base64.encodeToString(contactEd, Base64.NO_WRAP)
        val local = "L".repeat(43)
        val peer = "P".repeat(43)
        val now = System.currentTimeMillis()
        val messageId = "linked-import-$now"
        try {
            for ((device, self) in listOf(local to 1, peer to 0))
                db.execSQL("INSERT OR REPLACE INTO authorized_devices " +
                    "(deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX," +
                    "mlKemPublic,certificate,capabilities,issuedAtMs,expiresAtMs," +
                    "rosterEpoch,isSelf) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    arrayOf(device, accountB64, "test", "a".repeat(56) + ".onion",
                        ByteArray(32), ByteArray(32), ByteArray(1), ByteArray(1),
                        2, now - 1000, now + 60_000, 1, self))
            fun part(topic: String, objectId: String, sequence: Long,
                     body: ByteArray): DeviceSyncChunkStore.Part {
                val identity = RustBridge.deviceHistoryIdentity(body, topic, objectId, now)
                return DeviceSyncChunkStore.Part(peer, topic, objectId,
                    identity.copyOfRange(32, 64).joinToString("") {
                        "%02x".format(it.toInt() and 255) },
                    identity.copyOfRange(0, 32).joinToString("") {
                        "%02x".format(it.toInt() and 255) },
                    now, sequence, 0, 1, body)
            }
            val contact = JSONObject().put("public_key", contactB64)
                .put("x25519_pub", Base64.encodeToString(contactX, Base64.NO_WRAP))
                .put("display_name", "Synced person")
                .put("messaging_onion", JSONObject.NULL)
                .put("friend_request_onion", JSONObject.NULL)
                .put("friendship_status", 3)
                .put("created_at", now).toString().toByteArray()
            assertEquals(DeviceSyncChunkStore.Result.COMMITTED,
                DeviceSyncContactReceiver(database, roster, store).receive(account,
                    local, part("contacts", contactB64, 1, contact), now))
            val message = JSONObject().put("message_id", messageId)
                .put("contact_x25519", Base64.encodeToString(contactX,
                    Base64.NO_WRAP)).put("message_type", "TEXT")
                .put("is_sent_by_me", false).put("timestamp", now)
                .put("status", 2).put("content", "from another device")
                .toString().toByteArray()
            assertEquals(DeviceSyncChunkStore.Result.COMMITTED,
                DeviceSyncLiveMessageReceiver(database, roster,
                    { "ENC1:test-$it" }, linked = store).receive(account, local,
                        part("messages", messageId, 1, message), true, now))
            db.query(SimpleSQLiteQuery("SELECT encrypted_content FROM " +
                "linked_chat_messages WHERE message_id=?", arrayOf(messageId))).use {
                assertTrue(it.moveToFirst())
                assertEquals("ENC1:test-from another device", it.getString(0))
            }
            db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM contacts WHERE " +
                "publicKeyBase64=?", arrayOf(contactB64))).use {
                assertTrue(it.moveToFirst())
                assertEquals(0, it.getInt(0))
            }
        } finally {
            db.execSQL("DELETE FROM linked_chat_messages WHERE message_id=?",
                arrayOf(messageId))
            db.execSQL("DELETE FROM linked_chat_contacts WHERE account_ed=?",
                arrayOf(contactB64))
            for (table in listOf("device_sync_chunks", "device_sync_versions",
                    "device_sync_cursors", "device_sync_pending"))
                db.execSQL("DELETE FROM $table WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_local_events WHERE object_id IN (?,?)",
                arrayOf(contactB64, messageId))
            db.execSQL("DELETE FROM device_sync_source_changes WHERE object_id IN (?,?)",
                arrayOf(contactB64, messageId))
            db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)",
                arrayOf(local, peer))
        }
    }

    @Test fun walletFreeContactImportsAndQueuesDirectMessage() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val roster = DeviceRosterStore(database)
        val store = LinkedChatStore(database, roster, { "ENC1:test-$it" },
            DeviceSyncMediaFiles(context, { it }, { it }))
        store.ensureSchema()
        val localAccount = DeviceTransportFrame.randomId()
        val remoteAccount = DeviceTransportFrame.randomId()
        val remoteX = DeviceTransportFrame.randomId()
        val remote = Base64.encodeToString(remoteAccount, Base64.NO_WRAP)
        val now = System.currentTimeMillis()
        LocalDeviceIdentity.loadOrCreate(context).use { local ->
            LocalDeviceIdentity.createEphemeral().use { recipient ->
                try {
                    db.beginTransaction()
                    try {
                        assertTrue(store.applyContact(db, DeviceSyncContactDelta.Contact(
                            remoteAccount, remoteX, "Linked Test", null, null, now,
                            null, false, null, null, false), now))
                        val delta = DeviceSyncMessageDelta.parse(JSONObject()
                            .put("message_id", "linked-sync-$now")
                            .put("contact_x25519", Base64.encodeToString(remoteX,
                                Base64.NO_WRAP))
                            .put("message_type", "TEXT")
                            .put("is_sent_by_me", false)
                            .put("timestamp", now)
                            .put("status", 2)
                            .put("content", "synced"), now)
                        assertTrue(store.applyMessage(db, delta))
                        val direct = ByteArray(20)
                        direct[0] = 1
                        for (i in 0..7) direct[1 + i] =
                            (now ushr ((7 - i) * 8)).toByte()
                        "direct".toByteArray().copyInto(direct, 14)
                        val directId = DeviceTransportFrame.logicalId(remoteAccount,
                            recipient.deviceId, DeviceTransportFrame.randomId())
                        assertEquals(false, DeviceChatPayloadStore(
                            { "ENC1:test-$it" }, { _, _, _ -> error("No media") }, store)
                            .apply(db, remoteAccount, directId, direct, now))
                        db.setTransactionSuccessful()
                    } finally { db.endTransaction() }
                    db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM contacts " +
                        "WHERE publicKeyBase64=?", arrayOf(remote))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals(0, it.getInt(0))
                    }
                    for ((identity, account) in listOf(local to localAccount,
                            recipient to remoteAccount)) {
                        db.execSQL("INSERT OR REPLACE INTO authorized_devices " +
                            "(deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX," +
                            "mlKemPublic,certificate,capabilities,issuedAtMs,expiresAtMs," +
                            "rosterEpoch,isSelf) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            arrayOf(identity.deviceId,
                                Base64.encodeToString(account, Base64.NO_WRAP), "test",
                                identity.onionAddress, identity.signingPublicKey,
                                identity.encryptionPublicKey, ByteArray(1), ByteArray(1),
                                3, now - 1000, now + 60_000, 1, 1))
                    }
                    db.execSQL("INSERT OR REPLACE INTO device_rosters " +
                        "(accountEd,epoch,issuedAtMs,primaryDeviceId,signedRoster,acceptedAtMs) " +
                        "VALUES (?,?,?,?,?,?)", arrayOf(remote, 1, now,
                            recipient.deviceId, byteArrayOf(1), now))
                    val logical = DeviceChatOutboundStore(context, database, roster,
                        localAccount, { "ENC1:test-$it" })
                        .queueLinkedText(remoteAccount, "hello", now)
                    db.query(SimpleSQLiteQuery("SELECT encrypted_content FROM " +
                        "linked_chat_messages WHERE message_id=?", arrayOf(logical))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals("ENC1:test-hello", it.getString(0))
                    }
                    db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM device_transport_jobs " +
                        "WHERE logical_id=?", arrayOf(logical))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals(1, it.getInt(0))
                    }
                } finally {
                    db.execSQL("DELETE FROM linked_chat_messages WHERE account_ed=?",
                        arrayOf(remote))
                    db.execSQL("DELETE FROM linked_chat_contacts WHERE account_ed=?",
                        arrayOf(remote))
                    for (table in listOf("device_transport_jobs",
                            "device_transport_sessions", "device_transport_epochs"))
                        db.execSQL("DELETE FROM $table WHERE account_ed=?",
                            arrayOf(remote))
                    db.execSQL("DELETE FROM device_rosters WHERE accountEd=?",
                        arrayOf(remote))
                    db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)",
                        arrayOf(local.deviceId, recipient.deviceId))
                }
            }
        }
    }
}
