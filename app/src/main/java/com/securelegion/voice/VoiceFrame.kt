package com.securelegion.voice

import java.nio.ByteBuffer

/**
 * VoiceFrame represents a single encrypted audio packet in the MCP-TV protocol.
 *
 * Structure:
 * - Call ID (16 bytes): Unique identifier for this call
 * - Sequence Number (8 bytes): Monotonic counter for ordering
 * - Direction (1 byte): 0 = A→B, 1 = B→A
 * - Circuit Index (1 byte): Which Tor circuit this frame traveled on (0-4)
 * - Payload Length (4 bytes): Size of encrypted payload
 * - Encrypted Payload (variable): XChaCha20-Poly1305 encrypted Opus frame
 *
 * Total header: 30 bytes + variable payload
 */
data class VoiceFrame(
    val callId: ByteArray, // 16 bytes (UUID)
    val sequenceNumber: Long, // 8 bytes
    val direction: Byte, // 1 byte (0 or 1)
    val circuitIndex: Int, // 1 byte (0-4)
    val encryptedPayload: ByteArray // Variable (typically 20-120 bytes for 20ms Opus frames)
) {
    companion object {
        const val HEADER_SIZE = 30
        const val CALL_ID_SIZE = 16

        /**
         * Deserialize a VoiceFrame from raw bytes received over Tor circuit
         */
        fun fromBytes(data: ByteArray): VoiceFrame {
            require(data.size >= HEADER_SIZE) { "Frame too small: ${data.size} bytes" }

            val buffer = ByteBuffer.wrap(data)

            // Read call ID (16 bytes)
            val callId = ByteArray(CALL_ID_SIZE)
            buffer.get(callId)

            // Read sequence number (8 bytes)
            val sequenceNumber = buffer.long

            // Read direction (1 byte)
            val direction = buffer.get()

            // Read circuit index (1 byte)
            val circuitIndex = buffer.get().toInt()

            // Read payload length (4 bytes)
            val payloadLength = buffer.int
            require(payloadLength >= 0 && payloadLength <= 10000) {
                "Invalid payload length: $payloadLength"
            }

            // Read encrypted payload
            val encryptedPayload = ByteArray(payloadLength)
            buffer.get(encryptedPayload)

            return VoiceFrame(callId, sequenceNumber, direction, circuitIndex, encryptedPayload)
        }
    }

    /**
     * Serialize this VoiceFrame to bytes for transmission over Tor circuit
     */
    fun toBytes(): ByteArray {
        val totalSize = HEADER_SIZE + encryptedPayload.size
        val buffer = ByteBuffer.allocate(totalSize)

        // Write call ID (16 bytes)
        buffer.put(callId)

        // Write sequence number (8 bytes)
        buffer.putLong(sequenceNumber)

        // Write direction (1 byte)
        buffer.put(direction)

        // Write circuit index (1 byte)
        buffer.put(circuitIndex.toByte())

        // Write payload length (4 bytes)
        buffer.putInt(encryptedPayload.size)

        // Write encrypted payload
        buffer.put(encryptedPayload)

        return buffer.array()
    }

    /**
     * Encode Additional Authenticated Data (AAD) for AEAD encryption
     * Format: callId || seqNum || direction || circuitIndex
     */
    fun encodeAAD(): ByteArray {
        val buffer = ByteBuffer.allocate(26)
        buffer.put(callId) // 16 bytes
        buffer.putLong(sequenceNumber) // 8 bytes
        buffer.put(direction) // 1 byte
        buffer.put(circuitIndex.toByte()) // 1 byte
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as VoiceFrame

        if (!callId.contentEquals(other.callId)) return false
        if (sequenceNumber != other.sequenceNumber) return false
        if (direction != other.direction) return false
        if (circuitIndex != other.circuitIndex) return false
        if (!encryptedPayload.contentEquals(other.encryptedPayload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = callId.contentHashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + direction
        result = 31 * result + circuitIndex
        result = 31 * result + encryptedPayload.contentHashCode()
        return result
    }
}
