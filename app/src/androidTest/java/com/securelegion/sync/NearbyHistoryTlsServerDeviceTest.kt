package com.securelegion.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class NearbyHistoryTlsServerDeviceTest {
    @Test fun pinnedTls13AndRecordsRoundTrip() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        NearbyHistoryTlsServer.open(context).use { server ->
            assertTrue(server.fingerprint.matches(Regex("[0-9a-f]{64}")))
            val offer = NearbyHistoryOfferWire.Offer(server.host, server.port,
                "A".repeat(43), System.currentTimeMillis() + 60_000,
                "B".repeat(43), "C".repeat(43), ByteArray(32),
                server.fingerprint, ByteArray(64), ByteArray(0))
            val worker = Executors.newSingleThreadExecutor()
            try {
                val accepted = worker.submit<String> {
                    server.accept().use { socket ->
                        val request = NearbyHistoryTlsConnection.readRecord(socket.inputStream)
                        assertEquals("ping", request.getString("type"))
                        NearbyHistoryTlsConnection.writeRecord(socket.outputStream,
                            JSONObject().put("type", "pong"))
                        socket.session.protocol
                    }
                }
                NearbyHistoryTlsConnection.open(context, offer).use { client ->
                    client.write(JSONObject().put("type", "ping"))
                    assertEquals("pong", client.read().getString("type"))
                }
                assertEquals("TLSv1.3", accepted.get(15, TimeUnit.SECONDS))
            } finally { worker.shutdownNow() }
        }
    }
}
