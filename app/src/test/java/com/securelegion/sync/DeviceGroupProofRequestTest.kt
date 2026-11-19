package com.securelegion.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceGroupProofRequestTest {
    @Test fun canonicalRoundTrip() {
        val first = "01".repeat(32)
        val second = "fe".repeat(32)
        val encoded = DeviceGroupProofRequest.encode(listOf(second, first, first))
        assertEquals(71, encoded.size)
        assertEquals(listOf(first, second), DeviceGroupProofRequest.decode(encoded))
    }

    @Test fun rejectsUnsortedDuplicateAndMalformedFrames() {
        val first = "01".repeat(32)
        val second = "fe".repeat(32)
        val valid = DeviceGroupProofRequest.encode(listOf(first, second))
        val unsorted = valid.copyOf().also {
            val a = it.copyOfRange(7, 39)
            it.copyOfRange(39, 71).copyInto(it, 7)
            a.copyInto(it, 39)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupProofRequest.decode(unsorted)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupProofRequest.decode(valid + byteArrayOf(0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupProofRequest.encode(listOf("FF".repeat(32)))
        }
    }
}
