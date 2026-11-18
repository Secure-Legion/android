package com.securelegion.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceTransportFrameTest {
    @Test fun acceptsOnlyExactC0FrameLengthsAndKinds() {
        val wire = responsibilityRequest()
        val frame = DeviceTransportFrame.parse(wire)
        assertEquals(2, frame.version)
        assertEquals(DeviceTransportFrame.Kind.RESPONSIBILITY_REQUEST, frame.kind)
        assertEquals(0L, frame.counter)
        assertEquals(0, frame.payload.size)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceTransportFrame.parse(wire.copyOf(wire.size + 1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceTransportFrame.parse(wire.copyOf().apply { this[6] = 8 })
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceTransportFrame.parse(wire.copyOf().apply { this[174] = 1 })
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceTransportFrame.parse(wire.copyOf().apply { this[207] = 1 })
        }
    }

    private fun responsibilityRequest() =
        ByteArray(DeviceTransportFrame.HEADER_SIZE + DeviceTransportFrame.SIGNATURE_SIZE)
            .apply {
                this[0] = DeviceTransportFrame.TYPE.toByte()
                val size = this.size - 5
                this[1] = (size ushr 24).toByte()
                this[2] = (size ushr 16).toByte()
                this[3] = (size ushr 8).toByte()
                this[4] = size.toByte()
                this[5] = 2
                this[6] = DeviceTransportFrame.Kind.RESPONSIBILITY_REQUEST.code.toByte()
            }
}
