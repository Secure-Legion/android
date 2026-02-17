package com.securelegion.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securelegion.R
import kotlinx.coroutines.*
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

        // Share TorService's notification so no separate notification appears
        private const val NOTIFICATION_ID = 1001 // Same as TorService
        private const val CHANNEL_ID = "tor_service_channel" // Same as TorService
        private const val CHANNEL_NAME = "Tor Hidden Service"

        // Voice Tor health status (accessible from UI)
        @Volatile var isHealthy: Boolean = false
        @Volatile var circuitEstablished: Double? = null
        @Volatile var networkLiveness: Double? = null
    }

    private var torProcess: Process? = null
    private var torThread: Thread? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var metricsHealthJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // CRITICAL: Must call startForeground() immediately when started with startForegroundService()
        // Android 8+ requires this within 5-10 seconds or it kills the app
        val notification = createNotification("Initializing Voice Tor...")
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

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

                Log.i(TAG, "Voice Tor process started")

                // Start health monitoring after a delay (give Tor time to start)
                serviceScope.launch {
                    delay(10000) // Wait 10s for Tor to bootstrap
                    startMetricsHealthMonitor()
                }

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

    /**
     * Start voice Tor health monitoring via MetricsPort (port 9036)
     * Polls metrics every 5 seconds to detect voice call issues
     */
    private fun startMetricsHealthMonitor() {
        metricsHealthJob?.cancel()
        metricsHealthJob = serviceScope.launch(Dispatchers.IO) {
            Log.i(TAG, "Starting voice Tor health monitor (MetricsPort 9036)")

            while (isActive) {
                try {
                    val metricsText = fetchVoiceMetrics()

                    if (metricsText != null) {
                        // Parse health metrics
                        val established = parsePrometheusGauge(metricsText, "tor_circuit_established")
                        val liveness = parsePrometheusGauge(metricsText, "tor_network_liveness")

                        // Update status
                        circuitEstablished = established
                        networkLiveness = liveness
                        isHealthy = established == 1.0 && liveness == 1.0

                        if (!isHealthy) {
                            Log.w(TAG, "Voice Tor unhealthy: circuits=$established, liveness=$liveness")
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling voice Tor metrics", e)
                    isHealthy = false
                }

                delay(5000) // Poll every 5 seconds (voice is latency-sensitive)
            }
        }
    }

    /**
     * Fetch metrics from voice Tor MetricsPort (localhost 9036, no proxy)
     */
    private suspend fun fetchVoiceMetrics(): String? = withContext(Dispatchers.IO) {
        try {
            val client = okhttp3.OkHttpClient.Builder()
                .proxy(java.net.Proxy.NO_PROXY)
                .connectTimeout(2, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(2, java.util.concurrent.TimeUnit.SECONDS)
                .build()

            val request = okhttp3.Request.Builder()
                .url("http://127.0.0.1:9036/metrics")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    response.body?.string()
                } else {
                    null
                }
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Parse Prometheus gauge metric
     */
    private fun parsePrometheusGauge(metrics: String, metricName: String): Double? {
        val line = metrics.lineSequence()
            .firstOrNull { it.startsWith(metricName) && !it.startsWith("#") }
            ?: return null

        return line.substringAfterLast(' ').toDoubleOrNull()
    }

    /**
     * Create notification for foreground service
     * Required when using startForegroundService() on Android 8+
     */
    private fun createNotification(message: String): Notification {
        // Create notification channel (Android 8+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_MIN
            ).apply {
                description = "Voice Tor network status"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Voice Tor Service")
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_notification_logo)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(message: String) {
        val notification = createNotification(message)
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun stopVoiceTor() {
        Log.i(TAG, "Stopping voice Tor...")

        try {
            // Stop health monitoring
            metricsHealthJob?.cancel()
            metricsHealthJob = null

            // Stop Tor process
            torProcess?.destroy()
            torProcess = null

            torThread?.interrupt()
            torThread = null

            // Reset health status
            isHealthy = false
            circuitEstablished = null
            networkLiveness = null

            Log.i(TAG, "Voice Tor stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping voice Tor", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVoiceTor()
        serviceScope.cancel()
    }
}
