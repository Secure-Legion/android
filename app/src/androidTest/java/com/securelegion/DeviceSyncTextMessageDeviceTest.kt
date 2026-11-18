package com.securelegion

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.sync.DeviceSyncMessageDelta
import com.securelegion.sync.DeviceSyncDirectMessageStore
import com.securelegion.sync.DeviceSyncMediaFiles
import com.securelegion.crypto.KeyManager
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceSyncTextMessageDeviceTest {
    @Test fun importedTextWaitsForPinnedContactAndNeverOwnsDelivery() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val now = System.currentTimeMillis()
        val contactEd = Base64.encodeToString(ByteArray(32) { 0x41 }, Base64.NO_WRAP)
        val contactX = Base64.encodeToString(ByteArray(32) { 0x42 }, Base64.NO_WRAP)
        val id = "sync-text-device-test"
        val delta = DeviceSyncMessageDelta.parse(JSONObject()
            .put("message_id", id).put("contact_x25519", contactX)
            .put("message_type", "TEXT").put("is_sent_by_me", true)
            .put("timestamp", now - 1_000).put("status", 1)
            .put("content", "hello from another device"), now)
        try {
            db.beginTransaction()
            try {
                assertFalse(DeviceSyncDirectMessageStore.applyInTransaction(db, delta,
                    { "ENC1:$it" }))
                db.setTransactionSuccessful()
            } finally { db.endTransaction() }
            runBlocking { database.contactDao().insertContact(Contact(
                displayName = "Sync Sender", solanaAddress = "sync_text_wallet",
                publicKeyBase64 = contactEd, x25519PublicKeyBase64 = contactX,
                addedTimestamp = now - 2_000,
                friendshipStatus = Contact.FRIENDSHIP_CONFIRMED
            )) }
            db.beginTransaction()
            try {
                assertTrue(DeviceSyncDirectMessageStore.applyInTransaction(db, delta,
                    { "ENC1:$it" }))
                db.setTransactionSuccessful()
            } finally { db.endTransaction() }
            db.query(SimpleSQLiteQuery("SELECT encryptedContent,isDeviceSyncImported," +
                "retryCount,pingId FROM messages WHERE messageId=?", arrayOf(id))).use {
                assertTrue(it.moveToFirst())
                assertEquals("ENC1:hello from another device", it.getString(0))
                assertEquals(1, it.getInt(1))
                assertEquals(0, it.getInt(2))
                assertTrue(it.isNull(3))
            }
            for ((type, mediaId) in listOf("IMAGE" to "sync-image-device-test",
                    "VOICE" to "sync-voice-device-test")) {
                val payload = JSONObject().put("message_id", mediaId)
                    .put("contact_x25519", contactX).put("message_type", type)
                    .put("is_sent_by_me", false).put("timestamp", now - 500)
                    .put("status", 2)
                if (type == "IMAGE") payload.put("attachment_data",
                    Base64.encodeToString(byteArrayOf(1, 2, 3, 4), Base64.NO_WRAP))
                else payload.put("voice_data",
                    Base64.encodeToString(byteArrayOf(5, 6, 7, 8), Base64.NO_WRAP))
                    .put("voice_duration", 2)
                val media = DeviceSyncMessageDelta.parse(payload, now)
                if (type == "IMAGE") assertThrows(IllegalArgumentException::class.java) {
                    DeviceSyncMediaFiles(context, KeyManager.getInstance(context)).store(media)
                }
                db.beginTransaction()
                try {
                    assertTrue(DeviceSyncDirectMessageStore.applyInTransaction(db, media,
                        { "ENC1:$it" }, { "/private/$mediaId.enc" }))
                    db.setTransactionSuccessful()
                } finally { db.endTransaction() }
                db.query(SimpleSQLiteQuery("SELECT messageType,attachmentData,voiceFilePath," +
                    "isDeviceSyncImported FROM messages WHERE messageId=?",
                    arrayOf(mediaId))).use {
                    assertTrue(it.moveToFirst())
                    assertEquals(type, it.getString(0))
                    assertEquals(if (type == "IMAGE") "/private/$mediaId.enc" else null,
                        if (it.isNull(1)) null else it.getString(1))
                    assertEquals(if (type == "VOICE") "/private/$mediaId.enc" else null,
                        if (it.isNull(2)) null else it.getString(2))
                    assertEquals(1, it.getInt(3))
                }
            }
        } finally {
            db.execSQL("DELETE FROM messages WHERE messageId IN (?,?,?)",
                arrayOf(id, "sync-image-device-test", "sync-voice-device-test"))
            db.execSQL("UPDATE device_sync_import_guard SET depth=depth+1 WHERE id=1")
            try { db.execSQL("DELETE FROM contacts WHERE publicKeyBase64=?", arrayOf(contactEd)) }
            finally { db.execSQL("UPDATE device_sync_import_guard SET depth=depth-1 WHERE id=1") }
            db.execSQL("DELETE FROM device_sync_source_changes WHERE object_id=?", arrayOf(id))
        }
    }
}
