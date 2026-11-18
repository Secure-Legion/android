package com.securelegion

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceTransportSessionStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.sync.DeviceChatPayloadStore
import com.securelegion.sync.DeviceTransportFrame
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import kotlinx.coroutines.runBlocking

@RunWith(AndroidJUnit4::class)
class DeviceTransportHandshakeDeviceTest {
    @Test fun independentIdentitiesPersistRequestPrekeyAndReadyChain() {
        val instrument = InstrumentationRegistry.getInstrumentation()
        val database = SecureLegionDatabase.getInstance(instrument.targetContext,
            ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val accountA = DeviceTransportFrame.randomId()
        val accountB = DeviceTransportFrame.randomId()
        val now = System.currentTimeMillis()
        val contactId = runBlocking { database.contactDao().insertContact(Contact(
            displayName = "C0 Test", solanaAddress = "test_" +
                Base64.getUrlEncoder().withoutPadding().encodeToString(accountA),
            publicKeyBase64 = Base64.getEncoder().encodeToString(accountA),
            x25519PublicKeyBase64 = Base64.getEncoder().encodeToString(ByteArray(32) { 4 }),
            addedTimestamp = now, friendshipStatus = "CONFIRMED")) }
        try { LocalDeviceIdentity.loadOrCreate(instrument.targetContext).use { sender ->
            LocalDeviceIdentity.createEphemeral().use { receiver ->
                require(sender.deviceId != receiver.deviceId)
                try {
                    for ((identity, account) in listOf(sender to accountA,
                            receiver to accountB)) {
                        db.execSQL("INSERT OR REPLACE INTO authorized_devices " +
                            "(deviceId,accountEd,displayName,syncOnion,deviceEd,deviceX," +
                            "mlKemPublic,certificate,capabilities,issuedAtMs,expiresAtMs," +
                            "rosterEpoch,isSelf) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            arrayOf(identity.deviceId,
                                Base64.getEncoder().encodeToString(account), "test",
                                identity.onionAddress, identity.signingPublicKey,
                                identity.encryptionPublicKey, ByteArray(1), ByteArray(1),
                                1, now - 1_000, now + 60_000, 1, 1))
                    }
                    val sessions = DeviceTransportSessionStore(database,
                        DeviceRosterStore(database))
                    val request = sessions.request(accountA, accountB,
                        receiver.deviceId, sender, now)
                    val requestFrame = DeviceTransportFrame.parse(request.wire)
                    assertTrue(requestFrame.verify(sender.signingPublicKey))
                    val prekeyWire = sessions.acceptRequest(requestFrame, receiver, now)
                    assertTrue(sessions.acceptRequest(requestFrame, receiver, now)
                        .contentEquals(prekeyWire))
                    val prekey = DeviceTransportFrame.parse(prekeyWire)
                    assertTrue(prekey.verify(receiver.signingPublicKey))
                    val payload = ByteArray(19)
                    payload[0] = 1
                    for (i in 0..7) payload[1 + i] = (now ushr ((7 - i) * 8)).toByte()
                    "hello".toByteArray().copyInto(payload, 14)
                    val job = sessions.queuePayload(accountA, accountB,
                        receiver.deviceId, payload, sender, now)
                    assertEquals(null, sessions.nextDataWire(accountA, sender))
                    sessions.acceptPrekey(prekey, sender, now)
                    sessions.acceptPrekey(prekey, sender, now)
                    val dataWire = sessions.nextDataWire(accountA, sender)!!
                    assertArrayEquals(dataWire, sessions.nextDataWire(accountA, sender))
                    val data = DeviceTransportFrame.parse(dataWire)
                    assertArrayEquals(job, data.jobId)
                    var commits = 0
                    val ackWire = sessions.acceptData(data, receiver, { _, _, plain ->
                        assertArrayEquals(payload, plain)
                        commits++
                        DeviceChatPayloadStore({ "ENC1:test-$it" }).apply(db,
                            accountA, DeviceTransportFrame.logicalId(accountA,
                                sender.deviceId, job), plain, now)
                    }, now)
                    assertArrayEquals(ackWire, sessions.acceptData(data, receiver,
                        { _, _, _ -> error("Duplicate commit") }, now))
                    assertEquals(1, commits)
                    db.query(SimpleSQLiteQuery("SELECT encryptedContent FROM messages " +
                        "WHERE messageId=?", arrayOf(DeviceTransportFrame.logicalId(
                            accountA, sender.deviceId, job)))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals("ENC1:test-hello", it.getString(0))
                    }
                    val ack = DeviceTransportFrame.parse(ackWire)
                    assertEquals(DeviceTransportFrame.Kind.DEVICE_STORAGE_ACK, ack.kind)
                    sessions.acceptAcknowledgment(ack, sender, now)
                    val imagePayload = ByteArray(17)
                    imagePayload[0] = 1
                    for (i in 0..7) imagePayload[1 + i] =
                        (now ushr ((7 - i) * 8)).toByte()
                    imagePayload[13] = 0x02
                    byteArrayOf(7, 8, 9).copyInto(imagePayload, 14)
                    val secondJob = sessions.queuePayload(accountA, accountB,
                        receiver.deviceId, imagePayload, sender, now + 1)
                    val second = DeviceTransportFrame.parse(sessions.nextDataWire(accountA,
                        sender)!!)
                    assertEquals(1L, second.counter)
                    assertEquals(0, second.payload[0].toInt())
                    assertArrayEquals(secondJob, second.jobId)
                    val secondAck = sessions.acceptData(second, receiver,
                        { dbTransaction, logicalId, plain ->
                            DeviceChatPayloadStore({ "ENC1:test-$it" }, { type, _, media ->
                                assertEquals("IMAGE", type)
                                assertArrayEquals(byteArrayOf(7, 8, 9), media)
                                "/test/image"
                            }).apply(dbTransaction, accountA, logicalId, plain, now)
                        }, now)
                    db.query(SimpleSQLiteQuery("SELECT messageType,attachmentData FROM messages " +
                        "WHERE messageId=?", arrayOf(DeviceTransportFrame.logicalId(
                            accountA, sender.deviceId, secondJob)))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals("IMAGE", it.getString(0))
                        assertEquals("/test/image", it.getString(1))
                    }
                    sessions.acceptAcknowledgment(DeviceTransportFrame.parse(secondAck), sender, now)
                    val voicePayload = ByteArray(21)
                    voicePayload[0] = 1
                    for (i in 0..7) voicePayload[1 + i] =
                        (now ushr ((7 - i) * 8)).toByte()
                    voicePayload[13] = 0x01
                    voicePayload[17] = 3
                    byteArrayOf(5, 6, 7).copyInto(voicePayload, 18)
                    val thirdJob = sessions.queuePayload(accountA, accountB,
                        receiver.deviceId, voicePayload, sender, now + 2)
                    val third = DeviceTransportFrame.parse(sessions.nextDataWire(accountA,
                        sender)!!)
                    assertEquals(2L, third.counter)
                    val thirdAck = sessions.acceptData(third, receiver,
                        { dbTransaction, logicalId, plain ->
                            DeviceChatPayloadStore({ "ENC1:test-$it" }, { type, _, media ->
                                assertEquals("VOICE", type)
                                assertArrayEquals(byteArrayOf(5, 6, 7), media)
                                "/test/voice"
                            }).apply(dbTransaction, accountA, logicalId, plain, now)
                        }, now)
                    db.query(SimpleSQLiteQuery("SELECT messageType,voiceFilePath,voiceDuration " +
                        "FROM messages WHERE messageId=?", arrayOf(
                            DeviceTransportFrame.logicalId(accountA, sender.deviceId,
                                thirdJob)))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals("VOICE", it.getString(0))
                        assertEquals("/test/voice", it.getString(1))
                        assertEquals(3, it.getInt(2))
                    }
                    sessions.acceptAcknowledgment(DeviceTransportFrame.parse(thirdAck), sender, now)
                    db.query(SimpleSQLiteQuery("SELECT state,length(chain_key)," +
                        "initial_cipher IS NULL FROM device_transport_sessions " +
                        "WHERE account_ed=? AND peer_device_id=? AND direction='tx'",
                        arrayOf(Base64.getEncoder().encodeToString(accountB),
                            receiver.deviceId))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals("ready", it.getString(0))
                        assertEquals(32, it.getInt(1))
                        assertEquals(1, it.getInt(2))
                    }
                    db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM device_transport_jobs " +
                        "WHERE job_id=?", arrayOf(job))).use {
                        assertTrue(it.moveToFirst())
                        assertEquals(0, it.getInt(0))
                    }
                } finally {
                    for ((account, peerId) in listOf(accountA to sender.deviceId,
                            accountB to receiver.deviceId)) {
                        val encoded = Base64.getEncoder().encodeToString(account)
                        for (table in listOf("device_transport_sessions",
                                "device_transport_epochs"))
                            db.execSQL("DELETE FROM $table WHERE account_ed=?",
                                arrayOf(encoded))
                        db.execSQL("DELETE FROM authorized_devices WHERE deviceId=?",
                            arrayOf(peerId))
                    }
                }
            }
        }
        } finally { db.execSQL("DELETE FROM contacts WHERE id=?", arrayOf(contactId)) }
    }
}
