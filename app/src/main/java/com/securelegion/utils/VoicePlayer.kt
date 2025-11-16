package com.securelegion.utils

import android.content.Context
import android.media.MediaPlayer
import android.util.Log
import java.io.File

/**
 * Voice Player for playing voice messages
 * Uses MediaPlayer to play audio files
 */
class VoicePlayer(private val context: Context) {

    companion object {
        private const val TAG = "VoicePlayer"
    }

    private var mediaPlayer: MediaPlayer? = null
    private var currentFilePath: String? = null
    private var onCompletionListener: (() -> Unit)? = null
    private var onProgressListener: ((Int, Int) -> Unit)? = null

    /**
     * Play audio file
     * @param filePath Path to audio file
     * @param onCompletion Called when playback completes
     * @param onProgress Called periodically with (currentPos, duration) in milliseconds
     */
    fun play(
        filePath: String,
        onCompletion: (() -> Unit)? = null,
        onProgress: ((Int, Int) -> Unit)? = null
    ) {
        try {
            // Stop any existing playback
            stop()

            currentFilePath = filePath
            onCompletionListener = onCompletion
            onProgressListener = onProgress

            val file = File(filePath)
            if (!file.exists()) {
                Log.e(TAG, "Audio file not found: $filePath")
                onCompletion?.invoke()
                return
            }

            Log.d(TAG, "Playing: $filePath")

            mediaPlayer = MediaPlayer().apply {
                setDataSource(filePath)
                prepare()

                setOnCompletionListener {
                    Log.d(TAG, "Playback completed")
                    onCompletionListener?.invoke()
                    cleanup()
                }

                setOnErrorListener { _, what, extra ->
                    Log.e(TAG, "MediaPlayer error: what=$what, extra=$extra")
                    onCompletionListener?.invoke()
                    cleanup()
                    true
                }

                start()
                Log.i(TAG, "Playback started (duration: ${duration}ms)")

                // Start progress updates if listener provided
                if (onProgress != null) {
                    startProgressUpdates()
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to play audio", e)
            onCompletion?.invoke()
            cleanup()
        }
    }

    /**
     * Pause playback
     */
    fun pause() {
        try {
            mediaPlayer?.pause()
            Log.d(TAG, "Playback paused")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to pause", e)
        }
    }

    /**
     * Resume playback
     */
    fun resume() {
        try {
            mediaPlayer?.start()
            Log.d(TAG, "Playback resumed")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to resume", e)
        }
    }

    /**
     * Stop playback
     */
    fun stop() {
        try {
            mediaPlayer?.apply {
                if (isPlaying) {
                    stop()
                    Log.d(TAG, "Playback stopped")
                }
            }
            cleanup()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop", e)
        }
    }

    /**
     * Check if currently playing
     */
    fun isPlaying(): Boolean {
        return try {
            mediaPlayer?.isPlaying == true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get current position in milliseconds
     */
    fun getCurrentPosition(): Int {
        return try {
            mediaPlayer?.currentPosition ?: 0
        } catch (e: Exception) {
            0
        }
    }

    /**
     * Get duration in milliseconds
     */
    fun getDuration(): Int {
        return try {
            mediaPlayer?.duration ?: 0
        } catch (e: Exception) {
            0
        }
    }

    /**
     * Seek to position in milliseconds
     */
    fun seekTo(positionMs: Int) {
        try {
            mediaPlayer?.seekTo(positionMs)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to seek", e)
        }
    }

    /**
     * Cleanup resources
     */
    private fun cleanup() {
        try {
            mediaPlayer?.release()
            mediaPlayer = null
            currentFilePath = null
        } catch (e: Exception) {
            Log.e(TAG, "Cleanup error", e)
        }
    }

    /**
     * Start sending progress updates
     */
    private fun startProgressUpdates() {
        val updateInterval = 100L // Update every 100ms

        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        val runnable = object : Runnable {
            override fun run() {
                if (isPlaying()) {
                    val currentPos = getCurrentPosition()
                    val duration = getDuration()
                    onProgressListener?.invoke(currentPos, duration)
                    handler.postDelayed(this, updateInterval)
                }
            }
        }
        handler.post(runnable)
    }

    /**
     * Load audio from ByteArray (for received encrypted voice messages)
     * @param audioBytes The decrypted audio data
     * @param messageId Unique ID to use for temporary file
     * @return File path where audio is saved
     */
    fun loadFromBytes(audioBytes: ByteArray, messageId: String): String {
        val tempDir = File(context.cacheDir, "voice_temp")
        tempDir.mkdirs()

        val tempFile = File(tempDir, "voice_$messageId.m4a")
        tempFile.writeBytes(audioBytes)

        Log.d(TAG, "Loaded audio from bytes: ${tempFile.absolutePath} (${audioBytes.size} bytes)")

        return tempFile.absolutePath
    }

    /**
     * Release all resources
     */
    fun release() {
        stop()
    }
}
