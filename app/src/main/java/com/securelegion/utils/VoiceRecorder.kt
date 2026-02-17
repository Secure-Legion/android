package com.securelegion.utils

import android.content.Context
import android.media.MediaRecorder
import android.os.Build
import android.util.Log
import java.io.File
import java.io.IOException

/**
 * Voice Recorder for voice messages
 * Uses MediaRecorder to record audio in AAC format
 */
class VoiceRecorder(private val context: Context) {

    companion object {
        private const val TAG = "VoiceRecorder"
        private const val SAMPLE_RATE = 44100
        private const val BIT_RATE = 64000 // 64kbps for good quality voice
    }

    private var mediaRecorder: MediaRecorder? = null
    private var outputFile: File? = null
    private var startTime: Long = 0

    /**
     * Start recording audio
     * @return File where audio is being recorded
     */
    fun startRecording(): File {
        try {
            // Create temporary file for recording
            val tempDir = File(context.cacheDir, "voice_temp")
            tempDir.mkdirs()

            outputFile = File.createTempFile(
                "voice_${System.currentTimeMillis()}_",
                ".m4a",
                tempDir
            )

            Log.d(TAG, "Recording to: ${outputFile!!.absolutePath}")

            // Initialize MediaRecorder
            mediaRecorder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                MediaRecorder(context)
            } else {
                @Suppress("DEPRECATION")
                MediaRecorder()
            }

            mediaRecorder?.apply {
                setAudioSource(MediaRecorder.AudioSource.MIC)
                setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
                setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
                setAudioSamplingRate(SAMPLE_RATE)
                setAudioEncodingBitRate(BIT_RATE)
                setOutputFile(outputFile!!.absolutePath)

                try {
                    prepare()
                    start()
                    startTime = System.currentTimeMillis()
                    Log.i(TAG, "Recording started")
                } catch (e: IOException) {
                    Log.e(TAG, "Failed to start recording", e)
                    throw e
                }
            }

            return outputFile!!

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize recording", e)
            cleanup()
            throw e
        }
    }

    /**
     * Stop recording and return audio file
     * @return Pair of (audio file, duration in seconds)
     */
    fun stopRecording(): Pair<File, Int> {
        try {
            val duration = ((System.currentTimeMillis() - startTime) / 1000).toInt()

            mediaRecorder?.apply {
                try {
                    stop()
                    Log.i(TAG, "Recording stopped (duration: ${duration}s)")
                } catch (e: RuntimeException) {
                    // Handle case where recording was too short
                    Log.w(TAG, "Stop failed, recording might be too short", e)
                }
                release()
            }
            mediaRecorder = null

            val file = outputFile ?: throw IllegalStateException("No recording file")

            // Verify file exists and has content
            if (!file.exists() || file.length() == 0L) {
                throw IOException("Recording file is empty or missing")
            }

            Log.d(TAG, "Recording saved: ${file.length()} bytes, ${duration}s")

            return Pair(file, duration)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop recording", e)
            cleanup()
            throw e
        }
    }

    /**
     * Cancel recording and delete file
     */
    fun cancelRecording() {
        try {
            mediaRecorder?.apply {
                try {
                    stop()
                } catch (e: RuntimeException) {
                    // Ignore errors on cancel
                }
                release()
            }
            mediaRecorder = null

            outputFile?.delete()
            outputFile = null

            Log.i(TAG, "Recording cancelled")

        } catch (e: Exception) {
            Log.e(TAG, "Error cancelling recording", e)
        }
    }

    /**
     * Get current recording duration in seconds
     */
    fun getCurrentDuration(): Int {
        return if (startTime > 0) {
            ((System.currentTimeMillis() - startTime) / 1000).toInt()
        } else {
            0
        }
    }

    /**
     * Cleanup resources
     */
    private fun cleanup() {
        mediaRecorder?.release()
        mediaRecorder = null
        outputFile?.delete()
        outputFile = null
    }

    /**
     * Read audio file as ByteArray
     */
    fun readAudioFile(file: File): ByteArray {
        return file.readBytes()
    }

    /**
     * Save audio ByteArray to file in permanent storage (ENCRYPTED)
     * @param audioBytes The audio data (will be encrypted before saving)
     * @param duration Duration in seconds
     * @return File path where encrypted audio is saved
     */
    fun saveVoiceMessage(audioBytes: ByteArray, duration: Int): String {
        val voiceDir = File(context.filesDir, "voice_messages")
        voiceDir.mkdirs()

        val fileName = "voice_${System.currentTimeMillis()}.enc" // .enc for encrypted
        val voiceFile = File(voiceDir, fileName)

        // Encrypt audio before saving to disk
        val keyManager = com.securelegion.crypto.KeyManager.getInstance(context)
        val encryptedBytes = keyManager.encryptVoiceFile(audioBytes)
        voiceFile.writeBytes(encryptedBytes)

        Log.d(TAG, "Voice message saved (encrypted): ${voiceFile.absolutePath} (${audioBytes.size} bytes → ${encryptedBytes.size} bytes, ${duration}s)")

        return voiceFile.absolutePath
    }

    /**
     * Delete temporary recording files
     */
    fun cleanupTempFiles() {
        val tempDir = File(context.cacheDir, "voice_temp")
        tempDir.listFiles()?.forEach { file ->
            val age = System.currentTimeMillis() - file.lastModified()
            // Delete files older than 1 hour
            if (age > 3600000) {
                file.delete()
                Log.d(TAG, "Deleted old temp file: ${file.name}")
            }
        }
    }
}
