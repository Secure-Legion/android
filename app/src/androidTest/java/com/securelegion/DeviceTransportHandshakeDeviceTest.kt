package com.securelegion

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceTransportSessionStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.sync.DeviceTransportFrame
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class DeviceTransportHandshakeDeviceTest {
    @Test fun independentIdentitiesPersistRequestPrekeyAndReadyChain() {
        val instrument = InstrumentationRegistry.getInstrumentation()
        val database = SecureLegionDatabase.getInstance(instrument.targetContext,
            ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val accountA = ByteArray(32) { 0x21 }
        val accountB = ByteArray(32) { 0x22 }
        val now = System.currentTimeMillis()
        LocalDeviceIdentity.loadOrCreate(instrument.targetContext).use { sender ->
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
                    sessions.acceptPrekey(prekey, sender, now)
                    sessions.acceptPrekey(prekey, sender, now)
                    val payload = byteArrayOf(0, 1, 2, -1, 0, 9)
                    val job = sessions.queuePayload(accountA, accountB,
                        receiver.deviceId, payload, sender, now)
                    val dataWire = sessions.nextDataWire(accountA, sender)!!
                    assertArrayEquals(dataWire, sessions.nextDataWire(accountA, sender))
                    val data = DeviceTransportFrame.parse(dataWire)
                    assertArrayEquals(job, data.jobId)
                    var commits = 0
                    val ackWire = sessions.acceptData(data, receiver, { _, _, plain ->
                        assertArrayEquals(payload, plain)
                        commits++
                        true
                    }, now)
                    assertArrayEquals(ackWire, sessions.acceptData(data, receiver,
                        { _, _, _ -> error("Duplicate commit") }, now))
                    assertEquals(1, commits)
                    val ack = DeviceTransportFrame.parse(ackWire)
                    assertEquals(DeviceTransportFrame.Kind.ACCOUNT_STORAGE_ACK, ack.kind)
                    sessions.acceptAcknowledgment(ack, sender, now)
                    val secondJob = sessions.queuePayload(accountA, accountB,
                        receiver.deviceId, byteArrayOf(7, 8), sender, now + 1)
                    val second = DeviceTransportFrame.parse(sessions.nextDataWire(accountA,
                        sender)!!)
                    assertEquals(1L, second.counter)
                    assertEquals(0, second.payload[0].toInt())
                    assertArrayEquals(secondJob, second.jobId)
                    val secondAck = sessions.acceptData(second, receiver,
                        { _, _, plain -> assertArrayEquals(byteArrayOf(7, 8), plain); true }, now)
                    sessions.acceptAcknowledgment(DeviceTransportFrame.parse(secondAck), sender, now)
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
    }
}
