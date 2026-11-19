package com.securelegion.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceGroupFrameTest {
    @Test fun acceptsExactAckHeaderAndRejectsAmbiguousBounds() {
        val wire = ack()
        val frame = DeviceGroupFrame.parse(wire)
        assertEquals(DeviceGroupFrame.Kind.DEVICE_STORAGE_ACK, frame.kind)
        assertEquals(1, frame.chunkCount)
        assertEquals(0, frame.payload.size)
        listOf(
            wire.copyOf(wire.size + 1),
            wire.copyOf().apply { this[6] = 7 },
            wire.copyOf().apply { this[167] = 0 },
            wire.copyOf().apply { this[239] = 1 },
            wire.copyOf().apply { this[241] = 2 },
            wire.copyOf().apply { this[249] = 1 },
            wire.copyOf().apply { this[248] = 0 },
            wire.copyOf().apply { this[246] = 0 }
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                DeviceGroupFrame.parse(invalid)
            }
        }
    }

    @Test fun proofRequestCannotClaimLargeOrMultipleChunks() {
        val wire = ack().apply {
            this[6] = DeviceGroupFrame.Kind.PROOF_REQUEST.code.toByte()
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupFrame.parse(wire)
        }
    }

    @Test fun dataChunkRequiresExactHybridAndAeadLength() {
        val payloadSize = DeviceGroupFrame.HYBRID_BYTES + 1 +
            DeviceGroupFrame.AEAD_OVERHEAD
        val wire = ByteArray(DeviceGroupFrame.HEADER_BYTES + 1 + payloadSize +
            DeviceGroupFrame.SIGNATURE_BYTES).apply {
            val base = ack()
            base.copyInto(this, 0, 0, DeviceGroupFrame.HEADER_BYTES + 1)
            this[6] = DeviceGroupFrame.Kind.DATA.code.toByte()
            val length = size - 5
            this[1] = (length ushr 24).toByte()
            this[2] = (length ushr 16).toByte()
            this[3] = (length ushr 8).toByte()
            this[4] = length.toByte()
            this[249] = (payloadSize ushr 24).toByte()
            this[250] = (payloadSize ushr 16).toByte()
            this[251] = (payloadSize ushr 8).toByte()
            this[252] = payloadSize.toByte()
        }
        assertEquals(1, DeviceGroupFrame.parse(wire).expectedPlaintextLength)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupFrame.parse(wire.copyOf().apply { this[252] =
                (payloadSize - 1).toByte() })
        }
    }

    private fun ack() = ByteArray(DeviceGroupFrame.HEADER_BYTES + 1 +
        DeviceGroupFrame.SIGNATURE_BYTES).apply {
        this[0] = DeviceGroupFrame.TYPE.toByte()
        val length = size - 5
        this[1] = (length ushr 24).toByte()
        this[2] = (length ushr 16).toByte()
        this[3] = (length ushr 8).toByte()
        this[4] = length.toByte()
        this[5] = 1
        this[6] = DeviceGroupFrame.Kind.DEVICE_STORAGE_ACK.code.toByte()
        this[167] = 1
        this[238] = 1 // creation time
        this[241] = 0
        this[242] = 1 // one chunk
        this[246] = 1 // one plaintext byte
        this[248] = 1 // one roster byte
        this[253] = 1
    }
}
