package com.securelegion.voice

import com.securelegion.crypto.RustBridge
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * OpusCodec wraps the native Rust Opus encoder/decoder for voice calls.
 *
 * Optimized configuration for voice over Tor (40ms frames):
 * - Sample rate: 48 kHz (Opus native rate)
 * - Channels: 1 (mono)
 * - Frame size: 40ms (1920 samples at 48kHz)
 * - Bitrate: 32 kbps (high quality for voice)
 * - Application: VOIP (optimized for speech)
 * - Signal: VOICE (optimized for speech characteristics)
 * - FEC: Enabled with 25% expected packet loss
 * - DTX: Disabled (continuous transmission for smoother streaming over Tor)
 *
 * Expected bandwidth: ~5 KB/s per circuit with 40ms frames
 * With 3 circuits: ~15 KB/s total upstream/downstream
 */
class OpusCodec {
    companion object {
        // Opus configuration constants (40ms frames for Tor)
        const val SAMPLE_RATE = 48000 // 48 kHz (Opus native)
        const val CHANNELS = 1 // Mono
        const val FRAME_SIZE_MS = 40 // 40ms frames (better for Tor latency)
        const val FRAME_SIZE_SAMPLES = 1920 // 40ms at 48kHz = 1920 samples
        const val BITRATE = 32000 // 32 kbps (high quality)
        const val MAX_PACKET_SIZE = 4000 // Maximum Opus packet size

        // PCM format
        const val PCM_BIT_DEPTH = 16 // 16-bit signed PCM
        const val PCM_FRAME_SIZE_BYTES = FRAME_SIZE_SAMPLES * CHANNELS * (PCM_BIT_DEPTH / 8) // 3840 bytes

        // FEC (Forward Error Correction) configuration for Tor voice calls
        // Aggressive settings for high packet loss tolerance
        const val ENABLE_FEC = true // Enable in-band FEC
        const val PACKET_LOSS_PERC = 25 // Expected packet loss % (25% for Tor)
        const val DTX_ENABLED = false // DTX disabled (continuous transmission)
    }

    private var encoderHandle: Long = 0
    private var decoderHandle: Long = 0

    /**
     * Initialize Opus encoder for capturing and encoding microphone audio
     */
    fun initEncoder() {
        if (encoderHandle != 0L) {
            RustBridge.opusEncoderDestroy(encoderHandle)
        }

        encoderHandle = RustBridge.opusEncoderCreate(BITRATE)

        if (encoderHandle == -1L) {
            encoderHandle = 0
            throw RuntimeException("Failed to initialize Opus encoder")
        }
    }

    /**
     * Initialize Opus decoder for decoding and playing received audio
     */
    fun initDecoder() {
        if (decoderHandle != 0L) {
            RustBridge.opusDecoderDestroy(decoderHandle)
        }

        decoderHandle = RustBridge.opusDecoderCreate()

        if (decoderHandle == -1L) {
            decoderHandle = 0
            throw RuntimeException("Failed to initialize Opus decoder")
        }
    }

    /**
     * Encode PCM audio frame to Opus
     * @param pcmData 16-bit signed PCM samples (little-endian)
     * Must be exactly FRAME_SIZE_SAMPLES (960 samples for 20ms)
     * @return Compressed Opus packet (typically 20-120 bytes for voice)
     */
    fun encode(pcmData: ShortArray): ByteArray {
        if (encoderHandle == 0L) {
            throw IllegalStateException("Encoder not initialized - call initEncoder() first")
        }

        require(pcmData.size == FRAME_SIZE_SAMPLES) {
            "Invalid PCM frame size: ${pcmData.size}, expected $FRAME_SIZE_SAMPLES"
        }

        // Convert ShortArray to ByteArray (little-endian i16)
        val pcmBytes = ByteArray(pcmData.size * 2)
        val buffer = ByteBuffer.wrap(pcmBytes).order(ByteOrder.LITTLE_ENDIAN)
        for (sample in pcmData) {
            buffer.putShort(sample)
        }

        val opusPacket = RustBridge.opusEncode(encoderHandle, pcmBytes)
            ?: throw RuntimeException("Opus encoding failed")

        return opusPacket
    }

    /**
     * Decode Opus packet to PCM audio
     * @param opusPacket Compressed Opus packet
     * @return 16-bit signed PCM samples (FRAME_SIZE_SAMPLES = 960 samples)
     */
    fun decode(opusPacket: ByteArray): ShortArray {
        if (decoderHandle == 0L) {
            throw IllegalStateException("Decoder not initialized - call initDecoder() first")
        }

        val pcmBytes = RustBridge.opusDecode(decoderHandle, opusPacket)
            ?: throw RuntimeException("Opus decoding failed")

        // Convert ByteArray (little-endian i16) to ShortArray
        val buffer = ByteBuffer.wrap(pcmBytes).order(ByteOrder.LITTLE_ENDIAN)
        val pcmData = ShortArray(pcmBytes.size / 2)
        for (i in pcmData.indices) {
            pcmData[i] = buffer.getShort()
        }

        if (pcmData.size != FRAME_SIZE_SAMPLES) {
            throw RuntimeException("Decoded unexpected number of samples: ${pcmData.size}")
        }

        return pcmData
    }

    /**
     * Decode Opus packet using FEC to recover missing frame
     * Uses in-band Forward Error Correction data from packet N+1 to recover frame N
     * @param nextPacket Compressed Opus packet (N+1) containing FEC data for missing frame N
     * @return 16-bit signed PCM samples for the PREVIOUS frame (N), or null if FEC failed
     */
    fun decodeFEC(nextPacket: ByteArray): ShortArray? {
        if (decoderHandle == 0L) {
            throw IllegalStateException("Decoder not initialized - call initDecoder() first")
        }

        val pcmBytes = RustBridge.opusDecodeFEC(decoderHandle, nextPacket)
            ?: return null // FEC failed - encoder might not have FEC enabled or no redundancy available

        // Convert ByteArray (little-endian i16) to ShortArray
        val buffer = ByteBuffer.wrap(pcmBytes).order(ByteOrder.LITTLE_ENDIAN)
        val pcmData = ShortArray(pcmBytes.size / 2)
        for (i in pcmData.indices) {
            pcmData[i] = buffer.getShort()
        }

        if (pcmData.size != FRAME_SIZE_SAMPLES) {
            // FEC recovered partial frame or wrong size - treat as failure
            return null
        }

        return pcmData
    }

    /**
     * Decode packet loss concealment (PLC) frame
     * When a packet is lost, generate a synthetic frame to smooth the gap
     * @return 16-bit signed PCM samples (FRAME_SIZE_SAMPLES = 960 samples)
     *
     * Note: Native Opus decoder handles PLC internally when decoding with FEC.
     * This method is kept for API compatibility but decodes an empty packet.
     */
    fun decodePLC(): ShortArray {
        if (decoderHandle == 0L) {
            throw IllegalStateException("Decoder not initialized - call initDecoder() first")
        }

        // Decode empty packet for PLC
        val pcmBytes = RustBridge.opusDecode(decoderHandle, ByteArray(0))
            ?: throw RuntimeException("Opus PLC failed")

        // Convert ByteArray to ShortArray
        val buffer = ByteBuffer.wrap(pcmBytes).order(ByteOrder.LITTLE_ENDIAN)
        val pcmData = ShortArray(pcmBytes.size / 2)
        for (i in pcmData.indices) {
            pcmData[i] = buffer.getShort()
        }

        if (pcmData.size != FRAME_SIZE_SAMPLES) {
            throw RuntimeException("PLC decoded unexpected number of samples: ${pcmData.size}")
        }

        return pcmData
    }

    /**
     * Reset encoder state (use when starting new call)
     */
    fun resetEncoder() {
        if (encoderHandle != 0L) {
            RustBridge.opusEncoderDestroy(encoderHandle)
            encoderHandle = 0
        }
        initEncoder()
    }

    /**
     * Reset decoder state (use when starting new call)
     */
    fun resetDecoder() {
        if (decoderHandle != 0L) {
            RustBridge.opusDecoderDestroy(decoderHandle)
            decoderHandle = 0
        }
        initDecoder()
    }

    /**
     * Clean up resources
     */
    fun release() {
        if (encoderHandle != 0L) {
            RustBridge.opusEncoderDestroy(encoderHandle)
            encoderHandle = 0
        }
        if (decoderHandle != 0L) {
            RustBridge.opusDecoderDestroy(decoderHandle)
            decoderHandle = 0
        }
    }

    /**
     * Get current encoder bitrate
     * Note: Native Opus encoder doesn't expose bitrate getter, returns configured value
     */
    fun getEncoderBitrate(): Int {
        return if (encoderHandle != 0L) BITRATE else 0
    }

    /**
     * Set encoder bitrate dynamically (for adaptive quality)
     * Note: Requires recreating encoder with new bitrate in current implementation
     * @param bitrate Target bitrate in bps (8000-510000)
     */
    fun setEncoderBitrate(bitrate: Int) {
        if (encoderHandle != 0L) {
            RustBridge.opusEncoderDestroy(encoderHandle)
            encoderHandle = RustBridge.opusEncoderCreate(bitrate)
            if (encoderHandle == -1L) {
                encoderHandle = 0
            }
        }
    }

    /**
     * Calculate expected bandwidth usage
     * @return Approximate bytes per second
     */
    fun getExpectedBandwidth(): Int {
        // 40ms frames = 25 frames/second
        // Audio payload avg ~160 bytes/frame at ~32 kbps (VBR varies; FEC can increase)
        // Plus VoiceFrame overhead (~30 bytes header)
        // ≈ ~190 bytes/frame * 25 = ~4750 bytes/sec ≈ ~4.75 KB/s per circuit (typical)
        // Note: Actual bandwidth may spike to ~6 KB/s with high FEC overhead during loss bursts
        return 4750
    }
}
