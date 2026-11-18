package com.securelegion

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.sync.DeviceSyncFrameV2
import com.securelegion.sync.NearbyHistoryFrame
import com.securelegion.sync.NearbyHistoryTlsConnection
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NearbyHistoryFrameDeviceTest {
    @Test fun nearbyRecordsUseBoundedBigEndianLength() {
        val output = ByteArrayOutputStream()
        NearbyHistoryTlsConnection.writeRecord(output,
            JSONObject().put("type", "challenge"))
        val encoded = output.toByteArray()
        assertEquals(0, encoded[0].toInt())
        assertEquals(0, encoded[1].toInt())
        assertEquals("challenge", NearbyHistoryTlsConnection
            .readRecord(ByteArrayInputStream(encoded)).getString("type"))
        assertThrows(Exception::class.java) {
            NearbyHistoryTlsConnection.readRecord(ByteArrayInputStream(
                byteArrayOf(0x7f, 0x7f, 0x7f, 0x7f)))
        }
    }

    @Test fun tlsOnlyLegacyEnvelopeVerifiesSenderRecipientAndCiphertext() {
        LocalDeviceIdentity.createEphemeral().use { sender ->
            LocalDeviceIdentity.createEphemeral().use { recipient ->
                val now = System.currentTimeMillis()
                val wire = NearbyHistoryFrame.encode(DeviceSyncFrameV2.Kind.HELLO,
                    sender, recipient.deviceId, recipient.encryptionPublicKey,
                    JSONObject().put("nearby_v", 1).put("session", "s".repeat(43))
                        .put("challenge", "c".repeat(43)), now)
                val decoded = NearbyHistoryFrame.decode(wire, sender.deviceId,
                    recipient, sender.signingPublicKey, sender.encryptionPublicKey, now)
                assertEquals(DeviceSyncFrameV2.Kind.HELLO, decoded.kind)
                assertEquals("s".repeat(43), decoded.payload.getString("session"))
                val tampered = wire.copyOf().also { it[it.lastIndex] =
                    (it.last().toInt() xor 1).toByte() }
                assertThrows(Exception::class.java) {
                    NearbyHistoryFrame.decode(tampered, sender.deviceId,
                        recipient, sender.signingPublicKey,
                        sender.encryptionPublicKey, now)
                }
                LocalDeviceIdentity.createEphemeral().use { stranger ->
                    assertThrows(Exception::class.java) {
                        NearbyHistoryFrame.decode(wire, sender.deviceId,
                            stranger, sender.signingPublicKey,
                            sender.encryptionPublicKey, now)
                    }
                }
            }
        }
    }
}
