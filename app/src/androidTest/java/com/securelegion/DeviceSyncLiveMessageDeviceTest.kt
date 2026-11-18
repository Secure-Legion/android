package com.securelegion

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.sync.DeviceSyncLiveMessageReceiver
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceSyncLiveMessageDeviceTest {
    @Test fun missingContactSurvivesAndSettlesOnlyAfterImport() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val account = ByteArray(32) { 0x65 }
        val accountB64 = Base64.encodeToString(account, Base64.NO_WRAP)
        val local = "S".repeat(43)
        val peer = "T".repeat(43)
        val now = System.currentTimeMillis()
        val contactEd = Base64.encodeToString(ByteArray(32) { 0x45 }, Base64.NO_WRAP)
        val contactX = Base64.encodeToString(ByteArray(32) { 0x46 }, Base64.NO_WRAP)
        val messageId = "live-text-device-test"
        val delta = JSONObject().put("message_id", messageId)
            .put("contact_x25519", contactX).put("message_type", "TEXT")
            .put("is_sent_by_me", true).put("timestamp", now - 1_000)
            .put("status", 1).put("content", "sync text")
            .toString().toByteArray()
        val identity = RustBridge.deviceHistoryIdentity(delta, "messages", messageId, now)
        val part = DeviceSyncChunkStore.Part(peer, "messages", messageId,
            identity.copyOfRange(32, 64).toHex(),
            identity.copyOfRange(0, 32).toHex(), now, 1, 0, 1, delta)
        try {
            for ((id, self) in listOf(local to 1, peer to 0)) {
                db.execSQL("INSERT OR REPLACE INTO authorized_devices " +
                    "(deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX,mlKemPublic," +
                    "certificate,capabilities,issuedAtMs,expiresAtMs,rosterEpoch,isSelf) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    arrayOf(id, accountB64, "test", "a".repeat(56) + ".onion",
                        ByteArray(32), ByteArray(32), ByteArray(1), ByteArray(1),
                        2, now - 1_000, now + 60_000, 1, self))
            }
            val receiver = DeviceSyncLiveMessageReceiver(database,
                DeviceRosterStore(database), { "ENC1:$it" })
            assertEquals(DeviceSyncChunkStore.Result.DEFERRED,
                receiver.receive(account, local, part, true, now))
            db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM device_sync_pending " +
                "WHERE peer_device_id=? AND topic='messages'", arrayOf(peer))).use {
                assertTrue(it.moveToFirst())
                assertEquals(1, it.getInt(0))
            }
            runBlocking { database.contactDao().insertContact(Contact(
                displayName = "Sync Contact", solanaAddress = "live_text_wallet",
                publicKeyBase64 = contactEd, x25519PublicKeyBase64 = contactX,
                addedTimestamp = now - 2_000,
                friendshipStatus = Contact.FRIENDSHIP_CONFIRMED
            )) }
            assertEquals(1, receiver.drainPending(account, local, { true }, now).size)
            db.query(SimpleSQLiteQuery("SELECT isDeviceSyncImported,encryptedContent " +
                "FROM messages WHERE messageId=?", arrayOf(messageId))).use {
                assertTrue(it.moveToFirst())
                assertEquals(1, it.getInt(0))
                assertEquals("ENC1:sync text", it.getString(1))
            }
        } finally {
            db.execSQL("DELETE FROM messages WHERE messageId=?", arrayOf(messageId))
            db.execSQL("DELETE FROM device_sync_pending WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_chunks WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_versions WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_cursors WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("UPDATE device_sync_import_guard SET depth=depth+1 WHERE id=1")
            try { db.execSQL("DELETE FROM contacts WHERE publicKeyBase64=?", arrayOf(contactEd)) }
            finally { db.execSQL("UPDATE device_sync_import_guard SET depth=depth-1 WHERE id=1") }
            db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)",
                arrayOf(local, peer))
            identity.fill(0)
        }
    }

    private fun ByteArray.toHex() = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
