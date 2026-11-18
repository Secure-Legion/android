package com.securelegion

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncContactWorkStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.entities.Contact
import com.securelegion.sync.DeviceSyncContactPublisher
import com.securelegion.sync.DeviceSyncOutboundWire
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Verifies fresh-first and old-turn selection in a real SQLCipher profile. */
@RunWith(AndroidJUnit4::class)
class DeviceSyncContactWorkDeviceTest {
    @Test fun torBatchGivesFreshContactsAndOldWorkATurn() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val account = ByteArray(32) { 0x64 }
        val accountB64 = Base64.encodeToString(account, Base64.NO_WRAP)
        val local = "N".repeat(43)
        val peer = "R".repeat(43)
        val now = System.currentTimeMillis()
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
            for ((ordinal, topic) in listOf("settings", "contacts", "contacts", "contacts")
                    .withIndex()) {
                db.execSQL("INSERT INTO device_sync_outbox " +
                    "(peer_device_id,topic,object_id,event_id,event_time_ms,digest,sequence," +
                    "delta_json,transport,next_try_at_ms,attempts,created_at_ms,is_live) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,0,0,?,0)",
                    arrayOf(peer, topic, "batch_$ordinal", "%064x".format(ordinal + 1),
                        now, ByteArray(32) { ordinal.toByte() }, 1,
                        "{}".toByteArray(), "TOR", now - 4_000 + ordinal))
            }
            val selected = DeviceSyncOutboxStore(database, DeviceRosterStore(database))
                .dueTor(account, local, peer, now)
            assertEquals(listOf("batch_0", "batch_3", "batch_2"),
                selected.map { it.objectId })
            db.execSQL("INSERT INTO device_sync_outbox " +
                "(peer_device_id,topic,object_id,event_id,event_time_ms,digest,sequence," +
                "delta_json,transport,next_try_at_ms,attempts,created_at_ms,is_live) " +
                "VALUES (?,'messages',?,?,?,?,?,?,'TOR',0,0,?,1)",
                arrayOf(peer, "live_batch", "f".repeat(64), now,
                    ByteArray(32) { 0x44 }, 1, "{}".toByteArray(), now + 1))
            db.execSQL("DELETE FROM device_sync_outbox WHERE peer_device_id=? " +
                "AND topic='contacts'", arrayOf(peer))
            val outbox = DeviceSyncOutboxStore(database, DeviceRosterStore(database))
            assertEquals(listOf("batch_0"), outbox.dueTor(account, local, peer, now)
                .map { it.objectId })
            assertEquals(listOf("batch_0", "live_batch"),
                outbox.dueTor(account, local, peer, now, liveNegotiated = true)
                    .map { it.objectId })
        } finally {
            db.execSQL("DELETE FROM device_sync_outbox WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)",
                arrayOf(local, peer))
        }
    }

    @Test fun confirmedContactSeedsAnExactDurableOutboxEvent() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val account = ByteArray(32) { 0x62 }
        val accountB64 = Base64.encodeToString(account, Base64.NO_WRAP)
        val local = "M".repeat(43)
        val peer = "Q".repeat(43)
        val contactEd = Base64.encodeToString(ByteArray(32) { 0x31 }, Base64.NO_WRAP)
        val contactX = Base64.encodeToString(ByteArray(32) { 0x32 }, Base64.NO_WRAP)
        val now = System.currentTimeMillis()
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
            runBlocking { database.contactDao().insertContact(Contact(
                displayName = "Sync Test", solanaAddress = "sync_test_wallet",
                publicKeyBase64 = contactEd, x25519PublicKeyBase64 = contactX,
                addedTimestamp = now - 1_000,
                friendshipStatus = Contact.FRIENDSHIP_CONFIRMED
            )) }
            val roster = DeviceRosterStore(database)
            DeviceSyncContactPublisher(database, roster).prepareBatch(account, local, peer, now)
            val events = DeviceSyncOutboxStore(database, roster).dueTor(account, local, peer, now)
            val event = events.first { it.topic == "contacts" && it.objectId == contactEd }
            assertEquals(1, DeviceSyncOutboundWire.payloads(event).size)
            assertTrue(event.canonicalDelta.isNotEmpty())
        } finally {
            db.execSQL("UPDATE device_sync_import_guard SET depth=depth+1 WHERE id=1")
            try { db.execSQL("DELETE FROM contacts WHERE publicKeyBase64=?", arrayOf(contactEd)) }
            finally { db.execSQL("UPDATE device_sync_import_guard SET depth=depth-1 WHERE id=1") }
            db.execSQL("DELETE FROM device_sync_contact_work WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_contact_peers WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_outbox WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_local_events WHERE topic='contacts' AND object_id=?",
                arrayOf(contactEd))
            db.execSQL("DELETE FROM device_sync_source_changes WHERE object_id=?", arrayOf(contactEd))
            db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)", arrayOf(local, peer))
        }
    }

    @Test fun freshChangesAndOldestDueBothProgress() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val account = ByteArray(32) { 0x61 }
        val accountB64 = Base64.encodeToString(account, Base64.NO_WRAP)
        val local = "L".repeat(43)
        val peer = "P".repeat(43)
        val now = System.currentTimeMillis()
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
            val store = DeviceSyncContactWorkStore(database, DeviceRosterStore(database))
            store.initialize(account, local, peer, now)
            for (number in 1..3) db.execSQL(
                "INSERT INTO device_sync_source_changes(topic,object_id,kind,changed_at_ms) " +
                    "VALUES ('contacts',?,'upsert',?)",
                arrayOf("test_contact_$number", now + number))
            assertEquals(3, store.discover(account, local, peer, now))
            assertEquals(listOf("test_contact_3", "test_contact_1"),
                store.due(peer, now).map { it.objectId })
        } finally {
            db.execSQL("DELETE FROM device_sync_contact_work WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_contact_peers WHERE peer_device_id=?", arrayOf(peer))
            db.execSQL("DELETE FROM device_sync_source_changes WHERE object_id IN " +
                "('test_contact_1','test_contact_2','test_contact_3')")
            db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)",
                arrayOf(local, peer))
        }
    }
}
