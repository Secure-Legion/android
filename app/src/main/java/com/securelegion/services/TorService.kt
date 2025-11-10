package com.securelegion.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import com.securelegion.MainActivity
import com.securelegion.R
import com.securelegion.crypto.TorManager
import com.securelegion.crypto.RustBridge

/**
 * Foreground service that keeps Tor hidden service running 24/7
 * Enables the Ping-Pong Wake Protocol by maintaining persistent .onion address
 *
 * This service:
 * - Runs in foreground with persistent notification
 * - Keeps Tor connection alive when app is closed
 * - Listens for incoming Ping tokens on .onion address
 * - Survives app termination (user must explicitly stop)
 * - Uses WakeLock for reliable background operation
 */
class TorService : Service() {

    private lateinit var torManager: TorManager
    private var wakeLock: PowerManager.WakeLock? = null
    private var isServiceRunning = false

    companion object {
        private const val TAG = "TorService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "tor_service_channel"
        private const val CHANNEL_NAME = "Tor Hidden Service"

        const val ACTION_START_TOR = "com.securelegion.action.START_TOR"
        const val ACTION_STOP_TOR = "com.securelegion.action.STOP_TOR"

        // Track service state
        @Volatile
        private var running = false

        fun isRunning(): Boolean = running

        /**
         * Start the Tor service
         */
        fun start(context: Context) {
            val intent = Intent(context, TorService::class.java).apply {
                action = ACTION_START_TOR
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /**
         * Stop the Tor service
         */
        fun stop(context: Context) {
            val intent = Intent(context, TorService::class.java).apply {
                action = ACTION_STOP_TOR
            }
            context.startService(intent)
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "TorService created")

        // Initialize TorManager
        torManager = TorManager.getInstance(this)

        // Create notification channel
        createNotificationChannel()

        // Acquire partial wake lock to keep CPU running
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "SecureLegion::TorServiceWakeLock"
        ).apply {
            setReferenceCounted(false)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: ${intent?.action}")

        when (intent?.action) {
            ACTION_START_TOR -> startTorService()
            ACTION_STOP_TOR -> stopTorService()
            else -> startTorService() // Default to starting
        }

        // Service should restart if killed by system
        return START_STICKY
    }

    private fun startTorService() {
        if (isServiceRunning) {
            Log.d(TAG, "Tor service already running")
            return
        }

        Log.i(TAG, "Starting Tor foreground service")

        // Start as foreground service with notification IMMEDIATELY to avoid ANR
        val notification = createNotification("Initializing Tor...")
        startForeground(NOTIFICATION_ID, notification)

        // Acquire wake lock
        wakeLock?.acquire()

        isServiceRunning = true
        running = true

        // Initialize Tor in BACKGROUND THREAD to avoid ANR
        Thread {
            try {
                if (!torManager.isInitialized()) {
                    Log.d(TAG, "Tor not initialized, initializing now...")
                    torManager.initializeAsync { success, onionAddress ->
                        if (success && onionAddress != null) {
                            Log.i(TAG, "Tor initialized successfully. Hidden service: $onionAddress")

                            // Start listening for incoming Ping tokens
                            startIncomingListener()

                            updateNotification("Connected - $onionAddress")
                        } else {
                            Log.e(TAG, "Tor initialization failed")
                            updateNotification("Connection failed - Retrying...")
                            // TODO: Implement retry logic
                        }
                    }
                } else {
                    val onionAddress = torManager.getOnionAddress()
                    Log.d(TAG, "Tor already initialized. Address: $onionAddress")

                    // Start listening for incoming Ping tokens
                    startIncomingListener()

                    updateNotification("Connected - $onionAddress")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error during Tor initialization", e)
                updateNotification("Error - Check logs")
            }
        }.start()
    }

    private fun startIncomingListener() {
        try {
            Log.d(TAG, "Starting hidden service listener on port 9150...")
            val success = RustBridge.startHiddenServiceListener(9150)
            if (success) {
                Log.i(TAG, "Hidden service listener started successfully")

                // Start polling for incoming Pings
                startPingPoller()
            } else {
                Log.e(TAG, "Failed to start hidden service listener")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting listener", e)
        }
    }

    private fun startPingPoller() {
        // Poll for incoming Pings in background thread
        Thread {
            Log.d(TAG, "Ping poller thread started")
            while (isServiceRunning) {
                try {
                    val pingBytes = RustBridge.pollIncomingPing()
                    if (pingBytes != null) {
                        Log.i(TAG, "Received incoming Ping token: ${pingBytes.size} bytes")
                        handleIncomingPing(pingBytes)
                    }

                    // Poll every second
                    Thread.sleep(1000)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "Ping poller interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling for pings", e)
                }
            }
            Log.d(TAG, "Ping poller thread stopped")
        }.start()
    }

    private fun handleIncomingPing(encodedData: ByteArray) {
        try {
            // Wire format: [connection_id (8 bytes LE)][encrypted_ping_wire]
            if (encodedData.size < 8) {
                Log.e(TAG, "Invalid ping data: too short")
                return
            }

            // Extract connection_id (first 8 bytes, little-endian)
            val connectionId = java.nio.ByteBuffer.wrap(encodedData, 0, 8)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .long

            // Extract encrypted ping wire message (rest of bytes)
            val encryptedPingWire = encodedData.copyOfRange(8, encodedData.size)

            Log.i(TAG, "Received Ping on connection $connectionId: ${encryptedPingWire.size} bytes")

            // Decrypt and store the Ping, get ping_id
            val pingId = RustBridge.decryptIncomingPing(encryptedPingWire)
            if (pingId == null) {
                Log.e(TAG, "Failed to decrypt Ping")
                return
            }

            Log.i(TAG, "Ping decrypted successfully. Ping ID: $pingId")

            // TODO: Show notification to user asking for authentication
            // For now, auto-accept for testing
            Log.i(TAG, "Auto-accepting Ping for testing (TODO: show auth dialog)")

            // Create encrypted Pong response
            val encryptedPong = RustBridge.respondToPing(pingId, true)
            if (encryptedPong == null) {
                Log.e(TAG, "Failed to create Pong response")
                return
            }

            Log.i(TAG, "Created encrypted Pong: ${encryptedPong.size} bytes")

            // Send Pong back to sender
            RustBridge.sendPongBytes(connectionId, encryptedPong)

            Log.i(TAG, "Pong sent successfully!")

            // Show toast for testing
            Toast.makeText(this, "Incoming message authenticated!", Toast.LENGTH_SHORT).show()

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming Ping", e)
        }
    }

    private fun stopTorService() {
        Log.i(TAG, "Stopping Tor service")

        isServiceRunning = false
        running = false

        // Release wake lock
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
            }
        }

        // Stop foreground service
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps Tor hidden service running for incoming messages"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(status: String): Notification {
        // Intent to open app when notification is tapped
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Secure Legion")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun updateNotification(status: String) {
        val notification = createNotification(status)
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    override fun onBind(intent: Intent?): IBinder? {
        // This is not a bound service
        return null
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "TorService destroyed")

        running = false
        isServiceRunning = false

        // Release wake lock
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
            }
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.d(TAG, "onTaskRemoved - App swiped away, keeping service running")
        // Service continues running even when app is swiped away
        // This is intentional for Ping-Pong protocol
    }
}
