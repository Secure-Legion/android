package com.securelegion.voice

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.AutomaticGainControl
import android.media.audiofx.NoiseSuppressor
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

    // Audio effects for quality improvement
    private var acousticEchoCanceler: AcousticEchoCanceler? = null
    private var noiseSuppressor: NoiseSuppressor? = null
    private var automaticGainControl: AutomaticGainControl? = null

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
    @Suppress("MissingPermission")  // Permission check via require() above
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

            // Initialize audio effects for better call quality
            initializeAudioEffects(audioRecord!!.audioSessionId)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize AudioRecord", e)
            throw e
        }
    }

    /**
     * Initialize audio effects (AEC, NS, AGC) if supported by device
     * These greatly improve call quality by removing echo, background noise, and normalizing volume
     */
    private fun initializeAudioEffects(audioSessionId: Int) {
        try {
            // Acoustic Echo Canceler (AEC) - Removes echo from speaker playback
            if (AcousticEchoCanceler.isAvailable()) {
                acousticEchoCanceler = AcousticEchoCanceler.create(audioSessionId)
                if (acousticEchoCanceler != null) {
                    acousticEchoCanceler?.enabled = true
                    Log.i(TAG, "✓ Acoustic Echo Canceler enabled")
                } else {
                    Log.w(TAG, "✗ AcousticEchoCanceler.create returned null")
                }
            } else {
                Log.w(TAG, "✗ Acoustic Echo Canceler not available on this device")
            }

            // Noise Suppressor (NS) - Removes background noise (traffic, keyboard, etc)
            if (NoiseSuppressor.isAvailable()) {
                noiseSuppressor = NoiseSuppressor.create(audioSessionId)
                if (noiseSuppressor != null) {
                    noiseSuppressor?.enabled = true
                    Log.i(TAG, "✓ Noise Suppressor enabled")
                } else {
                    Log.w(TAG, "✗ NoiseSuppressor.create returned null")
                }
            } else {
                Log.w(TAG, "✗ Noise Suppressor not available on this device")
            }

            // Automatic Gain Control (AGC) - Normalizes audio volume
            if (AutomaticGainControl.isAvailable()) {
                automaticGainControl = AutomaticGainControl.create(audioSessionId)
                if (automaticGainControl != null) {
                    automaticGainControl?.enabled = true
                    Log.i(TAG, "✓ Automatic Gain Control enabled")
                } else {
                    Log.w(TAG, "✗ AutomaticGainControl.create returned null")
                }
            } else {
                Log.w(TAG, "✗ Automatic Gain Control not available on this device")
            }

            val enabledEffects = listOfNotNull(
                if (acousticEchoCanceler?.enabled == true) "AEC" else null,
                if (noiseSuppressor?.enabled == true) "NS" else null,
                if (automaticGainControl?.enabled == true) "AGC" else null
            )

            if (enabledEffects.isNotEmpty()) {
                Log.i(TAG, "Audio effects enabled: ${enabledEffects.joinToString(", ")}")
            } else {
                Log.w(TAG, "No audio effects available - call quality may be reduced")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error initializing audio effects (continuing without them)", e)
            // Don't throw - we can continue without effects, just with lower quality
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
     * Get the audio session ID for this AudioRecord
     * This should be used by AudioTrack to enable acoustic echo cancellation
     */
    fun getAudioSessionId(): Int {
        return audioRecord?.audioSessionId ?: 0
    }

    /**
     * Release resources
     */
    fun release() {
        stopCapture()

        // Release audio effects
        try {
            acousticEchoCanceler?.release()
            acousticEchoCanceler = null

            noiseSuppressor?.release()
            noiseSuppressor = null

            automaticGainControl?.release()
            automaticGainControl = null

            Log.d(TAG, "Audio effects released")
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing audio effects", e)
        }

        // Release AudioRecord
        try {
            audioRecord?.release()
            audioRecord = null
            Log.d(TAG, "AudioRecord released")
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing AudioRecord", e)
        }
    }
}
