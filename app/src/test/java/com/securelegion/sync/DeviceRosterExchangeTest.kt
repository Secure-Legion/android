package com.securelegion.sync

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceRosterExchangeTest {
    @Test fun a4AndA5LengthsAreExact() {
        val signed = ByteArray(38)
        "SLDR01".toByteArray(Charsets.US_ASCII).copyInto(signed)
        val a4 = DeviceRosterExchange.updateFrame(signed)
        assertTrue(DeviceRosterExchange.isStructurallyValid(a4))
        a4[4] = (a4[4].toInt() + 1).toByte()
        assertFalse(DeviceRosterExchange.isStructurallyValid(a4))
        val a5 = byteArrayOf(0xA5.toByte(), 0, 0, 0, 193.toByte(), 1) + ByteArray(192)
        assertTrue(DeviceRosterExchange.isStructurallyValid(a5))
        assertFalse(DeviceRosterExchange.isStructurallyValid(a5.copyOfRange(0, 197)))
    }
}
