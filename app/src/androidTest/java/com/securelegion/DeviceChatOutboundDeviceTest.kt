package com.securelegion

import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.DeviceChatOutboundStore
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.sync.DeviceTransportFrame
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceChatOutboundDeviceTest {
    @Test fun visibleMessageAndRecipientJobsCommitTogether() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val localAccount = DeviceTransportFrame.randomId()
        val remoteAccount = DeviceTransportFrame.randomId()
        val localEncoded = Base64.encodeToString(localAccount, Base64.NO_WRAP)
        val remoteEncoded = Base64.encodeToString(remoteAccount, Base64.NO_WRAP)
        val now = System.currentTimeMillis()
        val contactId = runBlocking { database.contactDao().insertContact(Contact(
            displayName = "Outbound Test", solanaAddress = "outbound_test_$now",
            publicKeyBase64 = remoteEncoded,
            x25519PublicKeyBase64 = Base64.encodeToString(ByteArray(32) { 7 },
                Base64.NO_WRAP), addedTimestamp = now,
            friendshipStatus = Contact.FRIENDSHIP_CONFIRMED)) }
        val contact = runBlocking { database.contactDao().getContactById(contactId)!! }
        LocalDeviceIdentity.loadOrCreate(context).use { local ->
            LocalDeviceIdentity.createEphemeral().use { remote ->
                try {
                    for ((identity, account) in listOf(local to localEncoded,
                            remote to remoteEncoded)) {
                        db.execSQL("INSERT OR REPLACE INTO authorized_devices " +
                            "(deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX," +
                            "mlKemPublic,certificate,capabilities,issuedAtMs,expiresAtMs," +
                            "rosterEpoch,isSelf) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            arrayOf(identity.deviceId, account, "test", identity.onionAddress,
                                identity.signingPublicKey, identity.encryptionPublicKey,
                                ByteArray(1), ByteArray(1), 3, now - 1000,
                                now + 60_000, 1, 1))
                    }
                    db.execSQL("INSERT OR REPLACE INTO device_rosters " +
                        "(accountEd,epoch,issuedAtMs,primaryDeviceId,signedRoster,acceptedAtMs) " +
                        "VALUES (?,?,?,?,?,?)", arrayOf(remoteEncoded, 1, now,
                            remote.deviceId, byteArrayOf(1), now))
                    val logical = DeviceChatOutboundStore(context, database,
                        DeviceRosterStore(database), localAccount, { "ENC1:test-$it" })
                        .queueApplication(contact, "hello", "hello".toByteArray(),
                            0x00, null, false, nowMs = now)
                    db.query(SimpleSQLiteQuery("SELECT encryptedContent,status FROM messages " +
                        "WHERE messageId=?", arrayOf(logical))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals("ENC1:test-hello", it.getString(0))
                        assertEquals(0, it.getInt(1))
                    }
                    db.query(SimpleSQLiteQuery("SELECT COUNT(*),length(plaintext) " +
                        "FROM device_transport_jobs WHERE logical_id=?", arrayOf(logical)))
                        .use {
                            assertTrue(it.moveToFirst())
                            assertEquals(1, it.getInt(0))
                            assertEquals(19, it.getInt(1))
                        }
                } finally {
                    db.execSQL("DELETE FROM messages WHERE contactId=?", arrayOf(contactId))
                    db.execSQL("DELETE FROM device_transport_jobs WHERE account_ed=?",
                        arrayOf(remoteEncoded))
                    db.execSQL("DELETE FROM device_transport_sessions WHERE account_ed=?",
                        arrayOf(remoteEncoded))
                    db.execSQL("DELETE FROM device_transport_epochs WHERE account_ed=?",
                        arrayOf(remoteEncoded))
                    db.execSQL("DELETE FROM device_rosters WHERE accountEd=?",
                        arrayOf(remoteEncoded))
                    db.execSQL("DELETE FROM authorized_devices WHERE deviceId IN (?,?)",
                        arrayOf(local.deviceId, remote.deviceId))
                    db.execSQL("DELETE FROM contacts WHERE id=?", arrayOf(contactId))
                }
            }
        }
    }
}
