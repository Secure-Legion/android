package com.securelegion.services

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import java.io.File

/**
 * VoiceTorService - Separate Tor instance for voice calling
 *
 * Runs a dedicated Tor daemon on port 9052 with Single Onion Service configuration:
 * - HiddenServiceNonAnonymousMode 1
 * - HiddenServiceSingleHopMode 1
 * - SOCKSPort 0 (no SOCKS, hidden service only)
 *
 * This provides 3-hop latency (instead of 6-hop) for voice calls while preserving
 * 6-hop anonymity for messaging on the main Tor instance.
 */
class VoiceTorService : Service() {

    companion object {
        private const val TAG = "VoiceTorService"
        const val ACTION_START = "com.securelegion.services.VoiceTorService.START"
        const val ACTION_STOP = "com.securelegion.services.VoiceTorService.STOP"
    }

    private var torProcess: Process? = null
    private var torThread: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVoiceTor()
            ACTION_STOP -> stopVoiceTor()
        }
        return START_STICKY
    }

    private fun startVoiceTor() {
        if (torProcess != null && torProcess?.isAlive == true) {
            Log.i(TAG, "Voice Tor already running")
            return
        }

        torThread = Thread {
            try {
                Log.i(TAG, "Starting VOICE Tor instance (Single Onion Service mode)...")

                // Get voice torrc path (created by TorManager)
                val voiceTorrc = File(filesDir, "voice_torrc")
                if (!voiceTorrc.exists()) {
                    Log.e(TAG, "Voice torrc not found at: ${voiceTorrc.absolutePath}")
                    return@Thread
                }

                // Get Tor binary from main TorService
                val torBinary = File(applicationInfo.nativeLibraryDir, "libtor.so")
                if (!torBinary.exists()) {
                    Log.e(TAG, "Tor binary not found at: ${torBinary.absolutePath}")
                    return@Thread
                }

                Log.i(TAG, "Voice torrc: ${voiceTorrc.absolutePath}")
                Log.i(TAG, "Tor binary: ${torBinary.absolutePath}")

                // Build command to run Tor
                val command = arrayOf(
                    torBinary.absolutePath,
                    "-f", voiceTorrc.absolutePath
                )

                Log.i(TAG, "Executing: ${command.joinToString(" ")}")

                // Start Tor process
                val processBuilder = ProcessBuilder(*command)
                processBuilder.redirectErrorStream(true)
                torProcess = processBuilder.start()

                Log.i(TAG, "✓ Voice Tor process started")

                // Read Tor output for debugging
                torProcess?.inputStream?.bufferedReader()?.use { reader ->
                    reader.lineSequence().forEach { line ->
                        Log.d(TAG, "Voice Tor: $line")
                    }
                }

                // Wait for process to exit
                val exitCode = torProcess?.waitFor() ?: -1
                Log.w(TAG, "Voice Tor process exited with code: $exitCode")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to start voice Tor process", e)
            }
        }

        torThread?.start()
    }

    private fun stopVoiceTor() {
        Log.i(TAG, "Stopping voice Tor...")

        try {
            torProcess?.destroy()
            torProcess = null

            torThread?.interrupt()
            torThread = null

            Log.i(TAG, "✓ Voice Tor stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping voice Tor", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVoiceTor()
    }
}
