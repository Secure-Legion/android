package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

class NearbyHistoryOfferWireTest {
    private val now = 1_794_596_100_000L
    private val fixture = JSONObject(javaClass.getResourceAsStream("/nearby-history-vector.json")!!
        .bufferedReader().use { it.readText() })
    private val offer get() = JSONObject(fixture.getJSONObject("offer").toString())

    @Test fun exactIosTranscriptVector() {
        val parsed = NearbyHistoryOfferWire.parse(offer.toString(), now)
        val expected = Base64.getDecoder().decode(fixture.getString("transcript_base64"))
        assertArrayEquals(expected, parsed.transcript)
        assertEquals("192.168.8.152", parsed.host)
    }

    @Test fun malformedOffersFailClosed() {
        for (host in listOf("127.0.0.1", "172.32.0.1", "192.168.01.1", "example.com")) {
            assertThrows(IllegalArgumentException::class.java) {
                NearbyHistoryOfferWire.parse(offer.put("host", host).toString(), now)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            NearbyHistoryOfferWire.parse(offer.put("extra", 1).toString(), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            NearbyHistoryOfferWire.parse(offer.toString().replace("\"v\":1", "\"v\":1.0"), now)
        }
    }
}
