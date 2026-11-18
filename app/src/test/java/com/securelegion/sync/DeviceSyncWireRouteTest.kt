package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class DeviceSyncWireRouteTest {
    private val local = "L".repeat(43)
    private val peer = "P".repeat(43)
    private val account = ByteArray(32) { it.toByte() }

    @Test fun handshakeRouteIsOnlyAHintForExpectedAccountAndRecipient() {
        val header = JSONObject().put("v", 2).put("from", peer).put("to", local)
            .put("account", Base64.getEncoder().encodeToString(account))
            .put("session", "S").put("step", 1).put("ts", 1)
            .put("noise", "N")
        val wire = frame(0xB6, JSONObject().put("header", header)
            .put("signature", "S").toString().toByteArray())
        assertEquals(peer, DeviceSyncWireRoute.peerId(wire, local, account))
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncWireRoute.peerId(wire, "X".repeat(43), account)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncWireRoute.peerId(wire, local, ByteArray(32))
        }
    }

    @Test fun dataRouteRejectsLengthAndRecipientSpoofingBeforeNoise() {
        val body = byteArrayOf(2) + ByteArray(32) + peer.toByteArray() +
            local.toByteArray() + ByteArray(8) + byteArrayOf(1) + ByteArray(18)
        val wire = frame(0xB7, body)
        assertEquals(peer, DeviceSyncWireRoute.peerId(wire, local, account))
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncWireRoute.peerId(wire.copyOf().also { it[4]++ }, local, account)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceSyncWireRoute.peerId(wire.copyOf().also { it[81] = 'X'.code.toByte() },
                local, account)
        }
    }

    private fun frame(kind: Int, body: ByteArray): ByteArray = byteArrayOf(kind.toByte(),
        (body.size ushr 24).toByte(), (body.size ushr 16).toByte(),
        (body.size ushr 8).toByte(), body.size.toByte()) + body
}
