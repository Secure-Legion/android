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

        // Jitter buffer configuration (optimized for Tor network conditions)
        // Tor circuits typically have 250-600ms latency with occasional spikes
        // Larger buffers prevent dropouts at the cost of ~100-200ms additional latency
        private const val MIN_BUFFER_MS = 300        // Minimum 300ms delay (was 200ms)
        private const val MAX_BUFFER_MS = 800        // Maximum 800ms delay (was 500ms)
        private const val INITIAL_BUFFER_MS = 400    // Start with 400ms (was 300ms)
        private const val FRAME_DURATION_MS = 20     // 20ms per frame
        private const val MAX_OUT_OF_ORDER = 10      // Max frames to buffer before considering lost

        // Adaptive buffer tuning (more tolerant for Tor jitter)
        private const val LATE_FRAME_THRESHOLD = 0.10f  // If >10% frames late, increase buffer (was 5%)
        private const val EARLY_FRAME_THRESHOLD = 0.95f // If >95% frames early, decrease buffer (was 90%)
    }

    private var audioTrack: AudioTrack? = null
    private var playbackJob: Job? = null
    private var isSpeakerEnabled = false
    private var audioManager: AudioManager? = null
    private var previousAudioMode: Int = AudioManager.MODE_NORMAL

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

    // FEC statistics
    private var fecAttempts: Long = 0
    private var fecSuccess: Long = 0
    private var plcFrames: Long = 0

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
            // Set up AudioManager for voice communication mode
            audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            audioManager?.let { am ->
                previousAudioMode = am.mode
                am.mode = AudioManager.MODE_IN_COMMUNICATION
                Log.d(TAG, "AudioManager mode set to MODE_IN_COMMUNICATION (previous: $previousAudioMode)")
            }

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
                    // Case A: Perfect in-order packet
                    try {
                        val pcmSamples = opusCodec.decode(frame.opusFrame)

                        audioTrack.write(
                            pcmSamples,
                            0,
                            FRAME_SIZE_SAMPLES,
                            AudioTrack.WRITE_BLOCKING
                        )

                    } catch (e: Exception) {
                        Log.e(TAG, "Opus decode error, using PLC", e)
                        playPLC(audioTrack)
                        plcFrames++
                    }

                    nextExpectedSeq = frame.sequenceNumber + 1

                } else {
                    // Missing frame - check if next frame is available for FEC recovery
                    val nextFrame = findFrame(nextExpectedSeq + 1)

                    if (nextFrame != null) {
                        // Case B: Exactly 1 frame missing and next frame available - try FEC
                        fecAttempts++
                        Log.d(TAG, "Attempting FEC recovery for seq=$nextExpectedSeq using seq=${nextFrame.sequenceNumber}")

                        try {
                            val fecSamples = opusCodec.decodeFEC(nextFrame.opusFrame)

                            if (fecSamples != null && fecSamples.size == FRAME_SIZE_SAMPLES) {
                                // FEC success! Play recovered frame
                                fecSuccess++
                                audioTrack.write(
                                    fecSamples,
                                    0,
                                    FRAME_SIZE_SAMPLES,
                                    AudioTrack.WRITE_BLOCKING
                                )
                                Log.d(TAG, "✓ FEC recovered seq=$nextExpectedSeq (success rate: ${(fecSuccess*100/fecAttempts)}%)")
                            } else {
                                // FEC failed - fallback to PLC
                                Log.d(TAG, "✗ FEC failed for seq=$nextExpectedSeq, using PLC")
                                playPLC(audioTrack)
                                plcFrames++
                                framesLost++
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "FEC decode error, using PLC", e)
                            playPLC(audioTrack)
                            plcFrames++
                            framesLost++
                        }

                        nextExpectedSeq++

                        // Now play the next frame (N+1) normally
                        try {
                            val pcmSamples = opusCodec.decode(nextFrame.opusFrame)
                            audioTrack.write(
                                pcmSamples,
                                0,
                                FRAME_SIZE_SAMPLES,
                                AudioTrack.WRITE_BLOCKING
                            )
                        } catch (e: Exception) {
                            Log.e(TAG, "Opus decode error on seq=${nextFrame.sequenceNumber}, using PLC", e)
                            playPLC(audioTrack)
                            plcFrames++
                        }

                        nextExpectedSeq++
                        removeFrame(nextFrame.sequenceNumber) // Remove from jitter buffer

                        // We played 2 frames - delay for 2x frame duration
                        delay((FRAME_DURATION_MS * 2).toLong())
                        continue  // Skip the regular delay at bottom
                    } else {
                        // Case C: No next frame available - use PLC
                        framesLost++
                        plcFrames++
                        Log.d(TAG, "Packet loss at seq=$nextExpectedSeq, using PLC (next frame not available)")
                        playPLC(audioTrack)
                        nextExpectedSeq++
                    }
                }

                // Frame duration is 20ms, sleep to maintain real-time playback
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
     * Find a specific frame in jitter buffer without removing it
     * Used for FEC: check if next frame is available before attempting recovery
     */
    private fun findFrame(sequenceNumber: Long): BufferedFrame? {
        jitterBuffer.forEach { frame ->
            if (frame.sequenceNumber == sequenceNumber) {
                return frame
            }
        }
        return null
    }

    /**
     * Remove a specific frame from jitter buffer
     * Used after FEC: remove the next frame after we've decoded it
     */
    private fun removeFrame(sequenceNumber: Long) {
        val iterator = jitterBuffer.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().sequenceNumber == sequenceNumber) {
                iterator.remove()
                return
            }
        }
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
            // Too many late frames, increase buffer (bigger steps for Tor)
            jitterBufferMs = (jitterBufferMs + 100).coerceIn(MIN_BUFFER_MS, MAX_BUFFER_MS)
            Log.d(TAG, "Increased jitter buffer to ${jitterBufferMs}ms (late rate: ${String.format("%.1f", lateRate * 100)}%)")

        } else if (lateRate < EARLY_FRAME_THRESHOLD * 0.1f && jitterBufferMs > MIN_BUFFER_MS) {
            // Very few late frames, decrease buffer (slower steps to avoid oscillation)
            jitterBufferMs = max(MIN_BUFFER_MS, jitterBufferMs - 50)
            Log.d(TAG, "Decreased jitter buffer to ${jitterBufferMs}ms (late rate: ${String.format("%.1f", lateRate * 100)}%)")
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
        audioManager?.isSpeakerphoneOn = enabled
        Log.d(TAG, "Speaker enabled: $enabled (AudioManager mode: ${audioManager?.mode})")
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

        val fecSuccessRate = if (fecAttempts > 0) {
            (fecSuccess.toFloat() / fecAttempts * 100)
        } else {
            0f
        }

        return CallQualityStats(
            jitterBufferMs = jitterBufferMs,
            framesReceived = framesReceived,
            framesLost = framesLost,
            packetLossRate = lossRate,
            fecAttempts = fecAttempts,
            fecSuccess = fecSuccess,
            fecSuccessRate = fecSuccessRate,
            plcFrames = plcFrames
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

        // Restore previous audio mode
        audioManager?.let { am ->
            am.mode = previousAudioMode
            am.isSpeakerphoneOn = false
            Log.d(TAG, "AudioManager mode restored to $previousAudioMode, speakerphone disabled")
        }
        audioManager = null
    }

    /**
     * Call quality statistics
     */
    data class CallQualityStats(
        val jitterBufferMs: Int,
        val framesReceived: Long,
        val framesLost: Long,
        val packetLossRate: Float,
        val fecAttempts: Long,
        val fecSuccess: Long,
        val fecSuccessRate: Float,
        val plcFrames: Long
    )
}
