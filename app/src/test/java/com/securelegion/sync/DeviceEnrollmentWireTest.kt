package com.securelegion.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class DeviceEnrollmentWireTest {
    private val now = 1_792_400_000_000L

    private fun qr(): JSONObject {
        val ed = ByteArray(32) { (it + 1).toByte() }
        val x = ByteArray(32) { (it + 33).toByte() }
        val id = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(
                "secure-legion-device-v1".toByteArray() + ed + x
            )
        )
        val b64 = Base64.getEncoder()
        val endpoint = JSONObject()
            .put("role", "candidate").put("device_id", id)
            .put("device_name", "Android").put("platform", "Android 15")
            .put("onion", "a".repeat(56) + ".onion")
            .put("device_ed", b64.encodeToString(ed))
            .put("device_x", b64.encodeToString(x))
            .put("kem_hash", b64.encodeToString(ByteArray(32) { 3 }))
            .put("e_pub", b64.encodeToString(ByteArray(32) { 4 }))
            .put("nonce", b64.encodeToString(ByteArray(32) { 5 }))
        return JSONObject().put("v", 1).put("t", "SL_ENROLL")
            .put("expires", now + 120_000).put("candidate", endpoint)
    }

    @Test fun candidateQrIsBoundedAndParsingDoesNotGrantTrust() {
        val parsed = DeviceEnrollmentWire.parseCandidateQr(qr().toString(), now)
        assertEquals(1, parsed.version)
        assertEquals("Android", parsed.candidate.name)
        assertEquals(43, parsed.candidate.deviceId.length)
        assertEquals(null, parsed.pinnedAccount)
    }

    @Test fun malformedAndAmbiguousQrsAreRejected() {
        val floatVersion = qr().toString().replace("\"v\":1", "\"v\":1.0")
        assertThrows(IllegalArgumentException::class.java) {
            DeviceEnrollmentWire.parseCandidateQr(floatVersion, now)
        }
        val changedId = qr()
        changedId.getJSONObject("candidate").put("device_id", "a".repeat(43))
        assertThrows(IllegalArgumentException::class.java) {
            DeviceEnrollmentWire.parseCandidateQr(changedId.toString(), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceEnrollmentWire.parseCandidateQr(qr().put("extra", true).toString(), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceEnrollmentWire.parseCandidateQr(qr().toString(), now + 300_000)
        }
    }

    @Test fun a3FrameRequiresExactLengthAndSupportedHeader() {
        val body = JSONObject().put("v", 1).put("id", "b".repeat(64))
            .put("type", "offer")
        val wire = DeviceEnrollmentWire.encodeFrame(body)
        assertEquals("offer", DeviceEnrollmentWire.decodeFrame(wire).type)
        wire[4] = (wire[4].toInt() - 1).toByte()
        assertThrows(IllegalArgumentException::class.java) {
            DeviceEnrollmentWire.decodeFrame(wire)
        }
    }
}
