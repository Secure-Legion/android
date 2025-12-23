package com.securelegion.voice

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlin.coroutines.coroutineContext
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * AudioCaptureManager handles microphone capture for voice calls.
 *
 * Flow:
 * 1. Check RECORD_AUDIO permission
 * 2. Initialize AudioRecord with 48kHz mono PCM
 * 3. Read 20ms chunks (960 samples) from microphone
 * 4. Convert byte buffer to short array
 * 5. Pass to Opus encoder
 * 6. Emit encoded Opus frames via callback
 *
 * Threading: Runs on background thread to avoid blocking UI
 */
class AudioCaptureManager(
    private val context: Context,
    private val opusCodec: OpusCodec
) {
    companion object {
        private const val TAG = "AudioCaptureManager"

        // Audio configuration (matches OpusCodec settings)
        private const val SAMPLE_RATE = OpusCodec.SAMPLE_RATE
        private const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
        private const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
        private const val FRAME_SIZE_SAMPLES = OpusCodec.FRAME_SIZE_SAMPLES
        private const val FRAME_SIZE_BYTES = FRAME_SIZE_SAMPLES * 2 // 16-bit = 2 bytes per sample
    }

    private var audioRecord: AudioRecord? = null
    private var captureJob: Job? = null
    private var isMuted = false

    @Volatile
    private var isCapturing = false

    // Callback for emitting encoded Opus frames
    var onFrameEncoded: ((ByteArray) -> Unit)? = null

    /**
     * Check if RECORD_AUDIO permission is granted
     */
    fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Initialize AudioRecord for microphone capture
     * Must call this before startCapture()
     */
    fun initialize() {
        require(hasPermission()) { "RECORD_AUDIO permission not granted" }

        try {
            // Calculate minimum buffer size
            val minBufferSize = AudioRecord.getMinBufferSize(
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT
            )

            if (minBufferSize == AudioRecord.ERROR || minBufferSize == AudioRecord.ERROR_BAD_VALUE) {
                throw RuntimeException("Invalid AudioRecord buffer size: $minBufferSize")
            }

            // Use buffer size that fits multiple 20ms frames
            val bufferSize = maxOf(minBufferSize, FRAME_SIZE_BYTES * 4)

            audioRecord = AudioRecord(
                MediaRecorder.AudioSource.VOICE_COMMUNICATION, // Optimized for VoIP
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT,
                bufferSize
            )

            if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
                throw RuntimeException("AudioRecord failed to initialize")
            }

            Log.d(TAG, "AudioRecord initialized: $SAMPLE_RATE Hz, buffer=$bufferSize bytes")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize AudioRecord", e)
            throw e
        }
    }

    /**
     * Start capturing audio from microphone
     * Runs on background coroutine
     */
    fun startCapture(scope: CoroutineScope) {
        val audioRecord = this.audioRecord
            ?: throw IllegalStateException("AudioRecord not initialized")

        if (isCapturing) {
            Log.w(TAG, "Already capturing")
            return
        }

        try {
            audioRecord.startRecording()
            isCapturing = true

            // Launch capture loop on IO dispatcher
            captureJob = scope.launch(Dispatchers.IO) {
                captureLoop()
            }

            Log.d(TAG, "Audio capture started")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start audio capture", e)
            isCapturing = false
            throw e
        }
    }

    /**
     * Main capture loop - reads PCM from microphone and encodes to Opus
     */
    private suspend fun captureLoop() {
        val audioRecord = this.audioRecord ?: return

        val buffer = ByteArray(FRAME_SIZE_BYTES)
        val pcmSamples = ShortArray(FRAME_SIZE_SAMPLES)

        Log.d(TAG, "Capture loop started")

        try {
            while (isCapturing && coroutineContext.isActive) {
                // Read 20ms of PCM audio (960 samples = 1920 bytes)
                val bytesRead = audioRecord.read(buffer, 0, FRAME_SIZE_BYTES)

                if (bytesRead < 0) {
                    Log.e(TAG, "AudioRecord read error: $bytesRead")
                    break
                }

                if (bytesRead != FRAME_SIZE_BYTES) {
                    Log.w(TAG, "Incomplete frame: $bytesRead bytes (expected $FRAME_SIZE_BYTES)")
                    continue
                }

                // Convert byte array to short array (little-endian)
                ByteBuffer.wrap(buffer)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .asShortBuffer()
                    .get(pcmSamples)

                // If muted, send silence instead of real audio
                if (isMuted) {
                    pcmSamples.fill(0)
                }

                // Encode PCM to Opus
                try {
                    val opusFrame = opusCodec.encode(pcmSamples)

                    // Emit encoded frame
                    onFrameEncoded?.invoke(opusFrame)

                } catch (e: Exception) {
                    Log.e(TAG, "Opus encoding failed", e)
                    // Continue capturing even if one frame fails
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Capture loop error", e)
        } finally {
            Log.d(TAG, "Capture loop ended")
        }
    }

    /**
     * Stop capturing audio
     */
    fun stopCapture() {
        if (!isCapturing) {
            return
        }

        isCapturing = false

        // Cancel capture coroutine
        captureJob?.cancel()
        captureJob = null

        // Stop AudioRecord
        try {
            audioRecord?.stop()
            Log.d(TAG, "Audio capture stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping AudioRecord", e)
        }
    }

    /**
     * Mute microphone (sends silence)
     */
    fun setMuted(muted: Boolean) {
        isMuted = muted
        Log.d(TAG, "Microphone muted: $muted")
    }

    /**
     * Check if microphone is muted
     */
    fun isMuted(): Boolean = isMuted

    /**
     * Release resources
     */
    fun release() {
        stopCapture()

        try {
            audioRecord?.release()
            audioRecord = null
            Log.d(TAG, "AudioRecord released")
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing AudioRecord", e)
        }
    }
}
