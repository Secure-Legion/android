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

        // Jitter buffer configuration (optimized for Tor)
        // Tor has high variance - we prioritize smoothness over low latency
        // Start big, grow immediately on underrun, shrink slowly after long stability
        private const val MIN_BUFFER_MS = 500        // Minimum target buffer (was 150ms - TOO SMALL for Tor)
        private const val MAX_BUFFER_MS = 1400       // Maximum target buffer (was 450ms - increased for Tor variance)
        private const val INITIAL_BUFFER_MS = 700    // Start with 700ms for Tor stability
        private const val HARD_CAP_MS = 1600         // Hard cap at 1600ms (drop frames beyond)
        private const val FRAME_DURATION_MS = 20     // CRITICAL FIX: 20ms per frame (matches OpusCodec.FRAME_SIZE_MS)
        private const val MAX_OUT_OF_ORDER = 10      // Max frames to buffer before considering lost

        // FEC grace window (v2 - wait for next packet before PLCing)
        private const val FEC_GRACE_WINDOW_MS = 60L  // Wait 60ms for next packet (3 frames @ 20ms)
        private const val FEC_MAX_RETRIES = 2        // Check for next frame 2 times during grace window

        // Reorder grace window (v3 - wait for out-of-order frames before missing)
        private const val REORDER_GRACE_MS = 80L     // Wait 80ms for out-of-order frames (4 frames @ 20ms)

        // Adaptive buffer tuning (more tolerant for Tor jitter)
        private const val LATE_FRAME_THRESHOLD = 0.10f  // If >10% frames late, increase buffer (was 5%)
        private const val EARLY_FRAME_THRESHOLD = 0.95f // If >95% frames early, decrease buffer (was 90%)

        // Resynchronization (recover from dead circuits by skipping forward)
        // This is the ONLY delay control mechanism - latency clamp removed (incompatible with Tor)
        private const val RESYNC_PLC_THRESHOLD = 15  // Skip forward after 15 consecutive PLC frames (300ms dead)

        // Buffer adaptation tuning (immediate growth, slow shrinking)
        private const val UNDERRUN_GROWTH_MS = 150    // Immediate +150ms on underrun (not gradual)
        private const val SHRINK_STEP_MS = 20         // Tiny -20ms shrink steps (slow)
        private const val SHRINK_STABILITY_MS = 20_000L  // Wait 20 seconds stable before shrinking
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
    @Volatile
    private var nextExpectedSeq: Long = 0
    @Volatile
    private var maxSeqSeen: Long = 0          // Track highest sequence number received (for buffer depth)
    private var jitterBufferMs: Int = INITIAL_BUFFER_MS
    private var framesReceived: Long = 0
    private var framesLate: Long = 0
    private var framesLost: Long = 0
    private var framesLateToBuffer: Long = 0  // Arrived after playout deadline (v3)
    private var framesPanicTrimmed: Long = 0  // Dropped due to exceeding HARD_CAP_MS

    // Buffer adaptation tracking
    private var lastUnderrunTime: Long = 0   // Last time we had an underrun (for stability tracking)
    private var underrunCount: Long = 0      // Total underruns during call
    private var playbackFrameCount: Long = 0 // Frame counter for periodic buffer adaptation

    // FEC statistics
    private var fecAttempts: Long = 0
    private var fecSuccess: Long = 0
    private var plcFrames: Long = 0

    // Resynchronization statistics
    private var consecutivePLCFrames: Int = 0   // Track consecutive PLC for resync detection
    private var resyncCount: Long = 0           // Number of times we've resynchronized

    // Seq → Circuit mapping for PLC attribution (v3)
    // Thread-safe map of sequence numbers to their circuit index (ConcurrentHashMap prevents ConcurrentModificationException)
    private val seqToCircuit = java.util.concurrent.ConcurrentHashMap<Long, Int>()
    // Track insertion order for trimming oldest entries (preserves FIFO semantics)
    private val seqOrder = java.util.concurrent.ConcurrentLinkedQueue<Long>()

    // Per-circuit statistics (v2) for adaptive routing feedback
    private data class CircuitStats(
        var framesReceived: Long = 0,
        var framesLate: Long = 0
    )
    private val circuitStats = mutableMapOf<Int, CircuitStats>()

    // Telemetry integration (v2)
    private var telemetry: CallQualityTelemetry? = null

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
     * @param audioSessionId Optional session ID from AudioRecord for AEC (0 = generate new)
     */
    fun initialize(audioSessionId: Int = 0) {
        try {
            // Set up AudioManager for voice communication mode
            audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            audioManager?.let { am ->
                // IMPORTANT: Do NOT change the audio mode if it's already MODE_IN_COMMUNICATION
                // VoiceCallActivity may have already set it up, and we don't want to override its settings
                if (am.mode != AudioManager.MODE_IN_COMMUNICATION) {
                    previousAudioMode = am.mode
                    am.mode = AudioManager.MODE_IN_COMMUNICATION
                    Log.d(TAG, "Set AudioManager mode to MODE_IN_COMMUNICATION (prev: $previousAudioMode)")
                } else {
                    // Mode already set by VoiceCallActivity - don't change it
                    previousAudioMode = AudioManager.MODE_NORMAL  // Will restore to NORMAL on release
                    Log.d(TAG, "AudioManager already in MODE_IN_COMMUNICATION - preserving existing settings")
                }

                // CRITICAL FIX: Respect current speaker state instead of forcing it OFF
                // VoiceCallActivity may have already set speaker ON during "Calling..." phase
                @Suppress("DEPRECATION")
                val currentSpeakerState = am.isSpeakerphoneOn
                isSpeakerEnabled = currentSpeakerState

                Log.d(TAG, "AudioPlaybackManager initialized: mode=${am.mode}, speaker=${if (currentSpeakerState) "ON" else "OFF"} (preserved from VoiceCallActivity)")
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

            val builder = AudioTrack.Builder()
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

            // CRITICAL: Use same session ID as AudioRecord for AEC to work
            if (audioSessionId != 0) {
                builder.setSessionId(audioSessionId)
                Log.d(TAG, "Using shared audio session ID: $audioSessionId (enables AEC)")
            }

            audioTrack = builder.build()

            if (audioTrack?.state != AudioTrack.STATE_INITIALIZED) {
                throw RuntimeException("AudioTrack failed to initialize")
            }

            Log.d(TAG, "AudioTrack initialized: $SAMPLE_RATE Hz, buffer=$bufferSize bytes, sessionId=${audioTrack?.audioSessionId}")

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

            // Reset sequence tracking (synchronized for thread safety with addFrame)
            synchronized(this) {
                nextExpectedSeq = 0
                maxSeqSeen = 0
                jitterBuffer.clear()
                seqToCircuit.clear()
                seqOrder.clear()
                playbackFrameCount = 0  // Reset frame counter for buffer adaptation
                lastUnderrunTime = System.currentTimeMillis()  // Initialize stability timer
            }

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
     * Set telemetry for quality monitoring
     */
    fun setTelemetry(telemetry: CallQualityTelemetry) {
        this.telemetry = telemetry
    }

    /**
     * Add received Opus frame to jitter buffer
     * Called from network receiver (potentially from multiple circuits)
     * @param sequenceNumber Packet sequence number
     * @param opusFrame Decoded Opus frame bytes
     * @param circuitIndex Which circuit this frame arrived on (for per-circuit stats)
     *
     * CRITICAL: Synchronized to handle DOUBLE-SEND - same packet arriving on 2 circuits simultaneously
     */
    @Synchronized
    fun addFrame(sequenceNumber: Long, opusFrame: ByteArray, circuitIndex: Int = 0) {
        if (!isPlaying) {
            return
        }

        framesReceived++

        // Track per-circuit stats
        val stats = circuitStats.getOrPut(circuitIndex) { CircuitStats() }
        stats.framesReceived++

        // Track which circuit this sequence came from (v3 - for PLC attribution)
        seqToCircuit[sequenceNumber] = circuitIndex
        seqOrder.add(sequenceNumber)

        // Trim old entries (keep last 500 seqs) - use ConcurrentLinkedQueue for FIFO ordering
        while (seqToCircuit.size > 500) {
            val oldestSeq = seqOrder.poll() ?: break
            seqToCircuit.remove(oldestSeq)
        }

        // Update max sequence seen for buffer depth tracking
        if (sequenceNumber > maxSeqSeen) {
            maxSeqSeen = sequenceNumber
        }

        // PANIC TRIM: Check if buffer depth exceeds hard cap (prevent delay creep)
        // bufferDepthMs = (maxSeqSeen - nextExpectedSeq) * frameMs
        val bufferDepthMs = (maxSeqSeen - nextExpectedSeq) * FRAME_DURATION_MS
        if (bufferDepthMs > HARD_CAP_MS) {
            // Buffer depth exceeded hard cap - advance nextExpectedSeq to bring it back to targetBufferMs
            val trimToSeq = maxSeqSeen - (jitterBufferMs / FRAME_DURATION_MS)
            val framesTrimmed = trimToSeq - nextExpectedSeq
            if (framesTrimmed > 0) {
                framesPanicTrimmed += framesTrimmed
                framesLost += framesTrimmed
                nextExpectedSeq = trimToSeq
                Log.w(TAG, "PANIC TRIM: buffer depth ${bufferDepthMs}ms exceeded HARD_CAP ${HARD_CAP_MS}ms, " +
                        "trimmed $framesTrimmed frames, advanced seq to $nextExpectedSeq (target buffer ${jitterBufferMs}ms)")
            }
        }

        // Check if frame is late (already played)
        if (sequenceNumber < nextExpectedSeq) {
            framesLate++
            stats.framesLate++

            // Check if this frame arrived after its playout deadline (v3 - deadline miss detection)
            // This distinguishes between network delay vs CPU/processing delay
            val framePlayoutTimeMs = (sequenceNumber - nextExpectedSeq) * FRAME_DURATION_MS
            if (framePlayoutTimeMs < -REORDER_GRACE_MS) {
                // Frame missed its deadline by more than reorder grace window
                framesLateToBuffer++
                Log.d(TAG, "Frame missed playout deadline: seq=$sequenceNumber, expected=$nextExpectedSeq, late by ${-framePlayoutTimeMs}ms, circuit=$circuitIndex")
            } else {
                Log.d(TAG, "Late frame (within grace): seq=$sequenceNumber, expected=$nextExpectedSeq, circuit=$circuitIndex")
            }

            telemetry?.reportLateFrame(circuitIndex)
            return
        }

        // Add to jitter buffer
        jitterBuffer.offer(BufferedFrame(sequenceNumber, opusFrame))
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
                var frame = getNextFrame()

                if (frame != null) {
                    // Case A: Perfect in-order packet (latency clamp removed - incompatible with Tor's variable latency)
                    consecutivePLCFrames = 0  // Reset PLC counter on successful frame
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
                        consecutivePLCFrames++

                        // Attribution: decode failed for a frame we had (v3)
                        val expectedCircuit = seqToCircuit[frame.sequenceNumber] ?: 0
                        telemetry?.reportPLCForCircuit(expectedCircuit)
                    }

                    nextExpectedSeq = frame.sequenceNumber + 1

                } else {
                    // Frame not in buffer - check if we're stuck on dead circuit (resynchronization)
                    if (consecutivePLCFrames >= RESYNC_PLC_THRESHOLD && !jitterBuffer.isEmpty()) {
                        // We've been using PLC for too long AND we have frames available
                        // This means playout is stuck on a dead circuit while new circuits have frames
                        val earliestFrame = jitterBuffer.peek()
                        if (earliestFrame != null && earliestFrame.sequenceNumber > nextExpectedSeq) {
                            val gap = earliestFrame.sequenceNumber - nextExpectedSeq
                            Log.w(TAG, "⚡ RESYNC: Skipping forward from seq=$nextExpectedSeq to ${earliestFrame.sequenceNumber} (gap=$gap frames, ${gap * FRAME_DURATION_MS}ms) after $consecutivePLCFrames consecutive PLC")

                            // JUMP FORWARD to recover from dead circuit
                            nextExpectedSeq = earliestFrame.sequenceNumber
                            consecutivePLCFrames = 0
                            resyncCount++

                            // Don't delay - immediately process the frame on next iteration
                            continue
                        }
                    }

                    // Frame not in buffer - apply reorder grace window (v3)
                    delay(REORDER_GRACE_MS)
                    frame = getNextFrame()

                    if (frame != null) {
                        Log.d(TAG, "Frame arrived during reorder grace: seq=${frame.sequenceNumber} (expected=$nextExpectedSeq)")

                        consecutivePLCFrames = 0  // Reset on success

                        // Decode and play the reordered frame
                        try {
                            val pcmSamples = opusCodec.decode(frame.opusFrame)

                            audioTrack.write(
                                pcmSamples,
                                0,
                                FRAME_SIZE_SAMPLES,
                                AudioTrack.WRITE_BLOCKING
                            )

                        } catch (e: Exception) {
                            Log.e(TAG, "Opus decode error on reordered frame, using PLC", e)
                            playPLC(audioTrack)
                            plcFrames++
                            consecutivePLCFrames++

                            val expectedCircuit = seqToCircuit[frame.sequenceNumber] ?: 0
                            telemetry?.reportPLCForCircuit(expectedCircuit)
                        }

                        nextExpectedSeq = frame.sequenceNumber + 1

                    } else {
                        // Still missing after reorder grace - try FEC recovery (v2)
                        val recovered = attemptFECRecovery(audioTrack, nextExpectedSeq)

                        if (!recovered) {
                            // FEC failed after grace window - fallback to PLC
                            // THIS IS AN UNDERRUN - buffer was too small
                            onUnderrun()  // Immediate buffer growth

                            framesLost++
                            plcFrames++
                            consecutivePLCFrames++

                            // Attribution: which circuit should have delivered this seq? (v3)
                            val expectedCircuit = seqToCircuit[nextExpectedSeq] ?: 0
                            telemetry?.reportPLCForCircuit(expectedCircuit)

                            Log.d(TAG, "Packet loss at seq=$nextExpectedSeq (circuit=$expectedCircuit), using PLC")
                            playPLC(audioTrack)
                            nextExpectedSeq++
                        } else {
                            // FEC recovered and played frame(s)
                            consecutivePLCFrames = 0  // Reset on FEC success
                            // nextExpectedSeq already advanced in attemptFECRecovery
                            // Skip regular delay since we handled timing in attemptFECRecovery
                            continue
                        }
                    }
                }

                // Periodically check if we can shrink buffer (slow shrinking)
                playbackFrameCount++
                if (playbackFrameCount % 250 == 0L) {  // Every 5 seconds (250 frames * 20ms)
                    adaptJitterBuffer()
                    telemetry?.updateJitterBuffer(jitterBufferMs)
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
     * Attempt FEC recovery with grace window (v2)
     *
     * CRITICAL BEHAVIOR (per spec § 6.1-6.2):
     * - If frame N is missing and frame N+1 is available:
     *   1. Decode N using FEC data from packet N+1
     *   2. Then decode N+1 normally
     * - If N+1 is NOT available:
     *   1. Wait up to FEC_GRACE_WINDOW_MS (30ms) for it to arrive
     *   2. If it arrives → use FEC recovery
     *   3. If timeout → return false (caller will use PLC)
     *
     * GUARANTEES:
     * - Only attempts FEC for EXACTLY one-frame gaps (N missing, N+1 present)
     * - Capped total wait time (30ms) - won't block forever on reordering
     * - Won't attempt FEC for multi-frame loss (requires consecutive packets)
     *
     * @param audioTrack AudioTrack for playback
     * @param missingSeq Sequence number of missing frame (N)
     * @return True if FEC recovered and played frames, false if should use PLC
     */
    private suspend fun attemptFECRecovery(audioTrack: AudioTrack, missingSeq: Long): Boolean {
        // Check if next frame (N+1) is immediately available
        var nextFrame = findFrame(missingSeq + 1)

        if (nextFrame == null) {
            // Next frame not available - implement grace window
            // Wait up to FEC_GRACE_WINDOW_MS, checking FEC_MAX_RETRIES times
            val delayPerRetry = FEC_GRACE_WINDOW_MS / FEC_MAX_RETRIES

            for (retry in 1..FEC_MAX_RETRIES) {
                delay(delayPerRetry)
                nextFrame = findFrame(missingSeq + 1)
                if (nextFrame != null) {
                    Log.d(TAG, "Next frame arrived during grace window (retry $retry/$FEC_MAX_RETRIES)")
                    break
                }
            }
        }

        if (nextFrame == null) {
            // Next frame still not available after grace window - FEC not possible
            Log.d(TAG, "Next frame not available after ${FEC_GRACE_WINDOW_MS}ms grace window")
            return false
        }

        // Next frame available - attempt FEC recovery
        fecAttempts++
        Log.d(TAG, "Attempting FEC recovery for seq=$missingSeq using seq=${nextFrame.sequenceNumber}")

        try {
            val fecSamples = opusCodec.decodeFEC(nextFrame.opusFrame)

            if (fecSamples != null && fecSamples.size == FRAME_SIZE_SAMPLES) {
                // FEC success! Play recovered frame
                fecSuccess++
                telemetry?.reportFECAttempt(success = true)
                audioTrack.write(
                    fecSamples,
                    0,
                    FRAME_SIZE_SAMPLES,
                    AudioTrack.WRITE_BLOCKING
                )
                Log.d(TAG, "✓ FEC recovered seq=$missingSeq (success rate: ${(fecSuccess*100/fecAttempts)}%)")

                nextExpectedSeq = missingSeq + 1

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

                    // Attribution: decode failed for frame N+1 during FEC recovery (v3)
                    val expectedCircuit = seqToCircuit[nextFrame.sequenceNumber] ?: 0
                    telemetry?.reportPLCForCircuit(expectedCircuit)
                }

                nextExpectedSeq++
                removeFrame(nextFrame.sequenceNumber) // Remove from jitter buffer

                // We played 2 frames - delay for 2x frame duration
                delay((FRAME_DURATION_MS * 2).toLong())
                return true

            } else {
                // FEC decode returned null or wrong size - not enough redundancy in packet
                telemetry?.reportFECAttempt(success = false)
                Log.d(TAG, "✗ FEC failed for seq=$missingSeq (no redundancy data)")
                return false
            }

        } catch (e: Exception) {
            telemetry?.reportFECAttempt(success = false)
            Log.e(TAG, "FEC decode error for seq=$missingSeq", e)
            return false
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
     * Handle buffer underrun (immediate growth)
     * Called when frame == null in playback loop (missing frame)
     */
    private fun onUnderrun() {
        val now = System.currentTimeMillis()
        val oldBuffer = jitterBufferMs

        // IMMEDIATE GROWTH: +150ms on underrun (don't wait for gradual increase)
        jitterBufferMs = (jitterBufferMs + UNDERRUN_GROWTH_MS).coerceAtMost(MAX_BUFFER_MS)
        lastUnderrunTime = now
        underrunCount++

        Log.w(TAG, "⚡ UNDERRUN #$underrunCount! Grew buffer ${oldBuffer}ms → ${jitterBufferMs}ms")
    }

    /**
     * Adapt jitter buffer size (slow shrinking after stability)
     * Call this periodically (e.g., every ~5 seconds) during playback
     */
    private fun adaptJitterBuffer() {
        val now = System.currentTimeMillis()
        val stableDuration = now - lastUnderrunTime

        // Only shrink if:
        // 1. No underruns for 20+ seconds (SHRINK_STABILITY_MS)
        // 2. Buffer is above minimum
        if (stableDuration > SHRINK_STABILITY_MS && jitterBufferMs > MIN_BUFFER_MS) {
            val oldBuffer = jitterBufferMs
            jitterBufferMs = max(MIN_BUFFER_MS, jitterBufferMs - SHRINK_STEP_MS)
            lastUnderrunTime = now  // Reset stability timer after shrink

            Log.d(TAG, "📉 Stable for ${stableDuration/1000}s, shrunk buffer ${oldBuffer}ms → ${jitterBufferMs}ms")
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

            // Clear buffers (synchronized for thread safety with addFrame)
            synchronized(this) {
                jitterBuffer.clear()
                seqToCircuit.clear()
                seqOrder.clear()
            }

            // Log final stats (v3 - latency clamp removed)
            if (framesReceived > 0) {
                val lateToBufferRate = (framesLateToBuffer.toFloat() / framesReceived * 100)
                Log.d(TAG, "Final stats: framesLateToBuffer=$framesLateToBuffer (${String.format("%.1f", lateToBufferRate)}%)")
                Log.d(TAG, "Resynchronization: resyncs=$resyncCount")
            }

            Log.d(TAG, "Audio playback stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping AudioTrack", e)
        }
    }

    /**
     * Enable/disable speakerphone
     *
     * Routes audio output to either:
     * - Earpiece (small speaker at top for holding phone to ear) when OFF
     * - Loudspeaker (external loud speaker) when ON
     */
    fun setSpeakerEnabled(enabled: Boolean) {
        isSpeakerEnabled = enabled

        audioManager?.let { am ->
            try {
                // CRITICAL: For MODE_IN_COMMUNICATION, we must:
                // 1. Set speakerphone mode (routes audio to loudspeaker vs earpiece)
                // 2. DO NOT restart AudioTrack (causes audio gaps and issues)

                @Suppress("DEPRECATION")
                am.isSpeakerphoneOn = enabled

                if (enabled) {
                    Log.i(TAG, "✓ Speaker ON - audio routed to LOUDSPEAKER")
                } else {
                    Log.i(TAG, "✓ Speaker OFF - audio routed to EARPIECE")
                }

                Log.d(TAG, "AudioManager state: mode=${am.mode}, speakerphone=${am.isSpeakerphoneOn}")
            } catch (e: Exception) {
                Log.e(TAG, "Error setting speaker mode", e)
            }
        }
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

        val lateToBufferRate = if (framesReceived > 0) {
            (framesLateToBuffer.toFloat() / framesReceived * 100)
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
            plcFrames = plcFrames,
            framesLateToBuffer = framesLateToBuffer,
            lateToBufferRate = lateToBufferRate
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
     * Get per-circuit late frame percentages for scheduler feedback
     * Returns map of circuit index → late frame percentage
     */
    @Synchronized
    fun getPerCircuitLatePercent(): Map<Int, Double> {
        return circuitStats.mapValues { (_, stats) ->
            if (stats.framesReceived > 0) {
                (stats.framesLate.toDouble() / stats.framesReceived * 100.0)
            } else {
                0.0
            }
        }
    }

    /**
     * Reset per-circuit statistics (call periodically after feedback sent)
     */
    @Synchronized
    fun resetCircuitStats() {
        circuitStats.clear()
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
        val plcFrames: Long,
        val framesLateToBuffer: Long = 0,      // v3: Frames that missed playout deadline
        val lateToBufferRate: Float = 0f       // v3: Percentage of deadline misses
    )
}
