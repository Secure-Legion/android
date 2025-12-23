package com.securelegion.voice

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import android.util.Log
import kotlinx.coroutines.*
import kotlin.coroutines.coroutineContext
import java.util.concurrent.PriorityBlockingQueue
import kotlin.math.max

/**
 * AudioPlaybackManager handles audio playback with adaptive jitter buffer.
 *
 * Flow:
 * 1. Receive encrypted VoiceFrames from all circuits (out-of-order)
 * 2. Decrypt and decode Opus frames
 * 3. Buffer in priority queue sorted by sequence number
 * 4. Wait for jitter buffer delay (200-500ms adaptive)
 * 5. Play frames in order, use PLC for missing frames
 * 6. Adapt buffer size based on observed jitter
 *
 * Threading: Playback runs on background thread
 */
class AudioPlaybackManager(
    private val context: Context,
    private val opusCodec: OpusCodec
) {
    companion object {
        private const val TAG = "AudioPlaybackManager"

        // Audio configuration (matches OpusCodec)
        private const val SAMPLE_RATE = OpusCodec.SAMPLE_RATE
        private const val CHANNEL_CONFIG = AudioFormat.CHANNEL_OUT_MONO
        private const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
        private const val FRAME_SIZE_SAMPLES = OpusCodec.FRAME_SIZE_SAMPLES

        // Jitter buffer configuration
        private const val MIN_BUFFER_MS = 200        // Minimum 200ms delay
        private const val MAX_BUFFER_MS = 500        // Maximum 500ms delay
        private const val INITIAL_BUFFER_MS = 300    // Start with 300ms
        private const val FRAME_DURATION_MS = 20     // 20ms per frame
        private const val MAX_OUT_OF_ORDER = 10      // Max frames to buffer before considering lost

        // Adaptive buffer tuning
        private const val LATE_FRAME_THRESHOLD = 0.05f  // If >5% frames late, increase buffer
        private const val EARLY_FRAME_THRESHOLD = 0.90f // If >90% frames early, decrease buffer
    }

    private var audioTrack: AudioTrack? = null
    private var playbackJob: Job? = null
    private var isSpeakerEnabled = false

    @Volatile
    private var isPlaying = false

    // Jitter buffer: priority queue sorted by sequence number
    private val jitterBuffer = PriorityBlockingQueue<BufferedFrame>(
        100,
        compareBy { it.sequenceNumber }
    )

    // Current state
    private var nextExpectedSeq: Long = 0
    private var jitterBufferMs: Int = INITIAL_BUFFER_MS
    private var framesReceived: Long = 0
    private var framesLate: Long = 0
    private var framesLost: Long = 0

    /**
     * Buffered frame with timestamp for jitter adaptation
     */
    private data class BufferedFrame(
        val sequenceNumber: Long,
        val opusFrame: ByteArray,
        val receivedAtMs: Long = System.currentTimeMillis()
    )

    /**
     * Initialize AudioTrack for speaker playback
     */
    fun initialize() {
        try {
            // Calculate buffer size
            val minBufferSize = AudioTrack.getMinBufferSize(
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT
            )

            if (minBufferSize == AudioTrack.ERROR || minBufferSize == AudioTrack.ERROR_BAD_VALUE) {
                throw RuntimeException("Invalid AudioTrack buffer size: $minBufferSize")
            }

            // Use larger buffer to accommodate jitter buffer delay
            val bufferSize = maxOf(minBufferSize, FRAME_SIZE_SAMPLES * 2 * 10) // 10 frames

            audioTrack = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build()
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setSampleRate(SAMPLE_RATE)
                        .setChannelMask(CHANNEL_CONFIG)
                        .setEncoding(AUDIO_FORMAT)
                        .build()
                )
                .setBufferSizeInBytes(bufferSize)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()

            if (audioTrack?.state != AudioTrack.STATE_INITIALIZED) {
                throw RuntimeException("AudioTrack failed to initialize")
            }

            Log.d(TAG, "AudioTrack initialized: $SAMPLE_RATE Hz, buffer=$bufferSize bytes")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize AudioTrack", e)
            throw e
        }
    }

    /**
     * Start playback loop
     */
    fun startPlayback(scope: CoroutineScope) {
        val audioTrack = this.audioTrack
            ?: throw IllegalStateException("AudioTrack not initialized")

        if (isPlaying) {
            Log.w(TAG, "Already playing")
            return
        }

        try {
            audioTrack.play()
            isPlaying = true

            // Reset sequence tracking
            nextExpectedSeq = 0
            jitterBuffer.clear()

            // Launch playback loop
            playbackJob = scope.launch(Dispatchers.IO) {
                playbackLoop()
            }

            Log.d(TAG, "Audio playback started")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start playback", e)
            isPlaying = false
            throw e
        }
    }

    /**
     * Add received Opus frame to jitter buffer
     * Called from network receiver (potentially from multiple circuits)
     */
    fun addFrame(sequenceNumber: Long, opusFrame: ByteArray) {
        if (!isPlaying) {
            return
        }

        framesReceived++

        // Check if frame is late (already played)
        if (sequenceNumber < nextExpectedSeq) {
            framesLate++
            Log.d(TAG, "Late frame: seq=$sequenceNumber, expected=$nextExpectedSeq")
            return
        }

        // Add to jitter buffer
        jitterBuffer.offer(BufferedFrame(sequenceNumber, opusFrame))

        // Adapt jitter buffer based on arrival patterns
        if (framesReceived % 100 == 0L) {
            adaptJitterBuffer()
        }
    }

    /**
     * Main playback loop - reads from jitter buffer and plays audio
     */
    private suspend fun playbackLoop() {
        val audioTrack = this.audioTrack ?: return

        Log.d(TAG, "Playback loop started, jitter buffer: ${jitterBufferMs}ms")

        // Wait for initial jitter buffer to fill
        delay(jitterBufferMs.toLong())

        try {
            while (isPlaying && coroutineContext.isActive) {
                val frame = getNextFrame()

                if (frame != null) {
                    // Decode Opus to PCM
                    try {
                        val pcmSamples = opusCodec.decode(frame.opusFrame)

                        // Write PCM to speaker
                        val samplesWritten = audioTrack.write(
                            pcmSamples,
                            0,
                            FRAME_SIZE_SAMPLES,
                            AudioTrack.WRITE_BLOCKING
                        )

                        if (samplesWritten < 0) {
                            Log.e(TAG, "AudioTrack write error: $samplesWritten")
                        }

                    } catch (e: Exception) {
                        Log.e(TAG, "Opus decode error, using PLC", e)
                        playPLC(audioTrack)
                    }

                    nextExpectedSeq = frame.sequenceNumber + 1

                } else {
                    // No frame available - packet lost, use PLC
                    framesLost++
                    Log.d(TAG, "Packet loss at seq=$nextExpectedSeq, using PLC")
                    playPLC(audioTrack)
                    nextExpectedSeq++
                }

                // Frame duration is 20ms, sleep to maintain real-time playback
                // (AudioTrack blocks automatically, but this ensures timing)
                delay(FRAME_DURATION_MS.toLong())
            }

        } catch (e: Exception) {
            Log.e(TAG, "Playback loop error", e)
        } finally {
            Log.d(TAG, "Playback loop ended")
        }
    }

    /**
     * Get next frame from jitter buffer
     * @return Frame if available, null if lost/missing
     */
    private fun getNextFrame(): BufferedFrame? {
        // Look for next expected sequence number in buffer
        val iterator = jitterBuffer.iterator()
        while (iterator.hasNext()) {
            val frame = iterator.next()
            if (frame.sequenceNumber == nextExpectedSeq) {
                iterator.remove()
                return frame
            } else if (frame.sequenceNumber > nextExpectedSeq + MAX_OUT_OF_ORDER) {
                // Frame is too far ahead, consider earlier frames lost
                return null
            }
        }

        // Frame not in buffer yet
        return null
    }

    /**
     * Play packet loss concealment (PLC) frame
     */
    private fun playPLC(audioTrack: AudioTrack) {
        try {
            val plcSamples = opusCodec.decodePLC()

            audioTrack.write(
                plcSamples,
                0,
                FRAME_SIZE_SAMPLES,
                AudioTrack.WRITE_BLOCKING
            )

        } catch (e: Exception) {
            Log.e(TAG, "PLC error, playing silence", e)
            // Fallback: play silence
            val silence = ShortArray(FRAME_SIZE_SAMPLES) { 0 }
            audioTrack.write(silence, 0, FRAME_SIZE_SAMPLES, AudioTrack.WRITE_BLOCKING)
        }
    }

    /**
     * Adapt jitter buffer size based on frame arrival patterns
     */
    private fun adaptJitterBuffer() {
        if (framesReceived < 50) {
            return // Not enough data
        }

        val lateRate = framesLate.toFloat() / framesReceived

        if (lateRate > LATE_FRAME_THRESHOLD) {
            // Too many late frames, increase buffer
            jitterBufferMs = (jitterBufferMs + 50).coerceIn(MIN_BUFFER_MS, MAX_BUFFER_MS)
            Log.d(TAG, "Increased jitter buffer to ${jitterBufferMs}ms (late rate: $lateRate)")

        } else if (lateRate < EARLY_FRAME_THRESHOLD * 0.1f && jitterBufferMs > MIN_BUFFER_MS) {
            // Very few late frames, decrease buffer
            jitterBufferMs = max(MIN_BUFFER_MS, jitterBufferMs - 25)
            Log.d(TAG, "Decreased jitter buffer to ${jitterBufferMs}ms (late rate: $lateRate)")
        }

        // Reset stats periodically
        if (framesReceived % 500 == 0L) {
            framesLate = 0
            framesReceived = 0
        }
    }

    /**
     * Stop playback
     */
    fun stopPlayback() {
        if (!isPlaying) {
            return
        }

        isPlaying = false

        // Cancel playback coroutine
        playbackJob?.cancel()
        playbackJob = null

        // Stop AudioTrack
        try {
            audioTrack?.stop()
            audioTrack?.flush()
            jitterBuffer.clear()
            Log.d(TAG, "Audio playback stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping AudioTrack", e)
        }
    }

    /**
     * Enable/disable speaker
     */
    fun setSpeakerEnabled(enabled: Boolean) {
        isSpeakerEnabled = enabled

        val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
        audioManager?.isSpeakerphoneOn = enabled

        Log.d(TAG, "Speaker enabled: $enabled")
    }

    /**
     * Check if speaker is enabled
     */
    fun isSpeakerEnabled(): Boolean = isSpeakerEnabled

    /**
     * Get call quality stats
     */
    fun getStats(): CallQualityStats {
        val lossRate = if (framesReceived > 0) {
            (framesLost.toFloat() / framesReceived * 100)
        } else {
            0f
        }

        return CallQualityStats(
            jitterBufferMs = jitterBufferMs,
            framesReceived = framesReceived,
            framesLost = framesLost,
            packetLossRate = lossRate
        )
    }

    /**
     * Release resources
     */
    fun release() {
        stopPlayback()

        try {
            audioTrack?.release()
            audioTrack = null
            Log.d(TAG, "AudioTrack released")
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing AudioTrack", e)
        }
    }

    /**
     * Call quality statistics
     */
    data class CallQualityStats(
        val jitterBufferMs: Int,
        val framesReceived: Long,
        val framesLost: Long,
        val packetLossRate: Float
    )
}
