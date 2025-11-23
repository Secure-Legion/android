package com.securelegion.services

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securelegion.ChatActivity
import com.securelegion.LockActivity
import com.securelegion.MainActivity
import com.securelegion.R
import com.securelegion.crypto.TorManager
import com.securelegion.crypto.RustBridge
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.math.min

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
    private var isPingPollerRunning = false
    private var isTapPollerRunning = false
    private var isPongPollerRunning = false
    private var isAckPollerRunning = false
    private var isListenerRunning = false

    // Network monitoring
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var hasNetworkConnection = false

    // AlarmManager for service restart
    private var alarmManager: AlarmManager? = null

    // Reconnection state
    private var isReconnecting = false
    private var reconnectAttempts = 0
    private var lastReconnectTime = 0L
    private val reconnectHandler = Handler(Looper.getMainLooper())

    // SOCKS failure tracking
    private var socksFailureCount = 0
    private var lastSocksFailureTime = 0L
    private val SOCKS_FAILURE_THRESHOLD = 3  // Restart Tor after 3 consecutive failures
    private val SOCKS_FAILURE_WINDOW = 60000L  // 60 second window

    // Reconnection constants
    private val INITIAL_RETRY_DELAY = 5000L        // 5 seconds
    private val MAX_RETRY_DELAY = 60000L           // 60 seconds
    private val MIN_RETRY_INTERVAL = 3000L         // 3 seconds minimum between retries

    // AlarmManager constants
    private val RESTART_CHECK_INTERVAL = 15 * 60 * 1000L  // 15 minutes

    companion object {
        private const val TAG = "TorService"
        private const val NOTIFICATION_ID = 1001
        private const val RESTART_REQUEST_CODE = 1001
        private const val CHANNEL_ID = "tor_service_channel"
        private const val CHANNEL_NAME = "Tor Hidden Service"
        private const val AUTH_CHANNEL_ID = "message_auth_channel"
        private const val AUTH_CHANNEL_NAME = "Message Authentication"

        const val ACTION_START_TOR = "com.securelegion.action.START_TOR"
        const val ACTION_STOP_TOR = "com.securelegion.action.STOP_TOR"
        const val ACTION_NOTIFICATION_DELETED = "com.securelegion.action.NOTIFICATION_DELETED"
        const val ACTION_ACCEPT_MESSAGE = "com.securelegion.action.ACCEPT_MESSAGE"
        const val ACTION_DECLINE_MESSAGE = "com.securelegion.action.DECLINE_MESSAGE"
        const val EXTRA_PING_ID = "ping_id"
        const val EXTRA_CONNECTION_ID = "connection_id"
        const val EXTRA_SENDER_NAME = "sender_name"

        // Track service state
        @Volatile
        private var running = false

        @Volatile
        private var torConnected = false

        @Volatile
        private var listenersReady = false

        fun isRunning(): Boolean = running

        fun isTorConnected(): Boolean = torConnected

        /**
         * Check if all listeners and pollers are ready for messaging
         * This means:
         * - Hidden service listener started (port 8080)
         * - Tap listener started (port 9151)
         * - Pong listener started (port 9152)
         * - All pollers running
         */
        fun areListenersReady(): Boolean = listenersReady

        /**
         * Check if messaging is fully ready (Tor connected + listeners ready)
         * Call this from SplashActivity to ensure 100% messaging functionality
         */
        fun isMessagingReady(): Boolean = torConnected && listenersReady

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

        /**
         * Report a SOCKS failure from MessageService or other components
         * TorService will track failures and automatically restart Tor if needed
         */
        fun reportSocksFailure(context: Context) {
            val intent = Intent(context, TorService::class.java).apply {
                action = "com.securelegion.action.REPORT_SOCKS_FAILURE"
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

        // Setup network monitoring
        setupNetworkMonitoring()

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
            ACTION_NOTIFICATION_DELETED -> handleNotificationDeleted()
            ACTION_ACCEPT_MESSAGE -> handleAcceptMessage(intent)
            ACTION_DECLINE_MESSAGE -> handleDeclineMessage(intent)
            "com.securelegion.action.REPORT_SOCKS_FAILURE" -> handleSocksFailure()
            else -> startTorService() // Default to starting
        }

        // Service should restart if killed by system
        return START_STICKY
    }

    /**
     * Android 15+: Handle foreground service timeout gracefully
     * Called when the service exceeds its allotted time limit
     */
    override fun onTimeout(startId: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            Log.w(TAG, "Foreground service timeout reached - stopping gracefully")

            // Show notification to user
            updateNotification("Service timeout - Please restart")

            // Clean up resources
            isServiceRunning = false
            running = false
            torConnected = false

            // Stop the service gracefully
            stopSelf(startId)
        }
    }

    private fun handleAcceptMessage(intent: Intent) {
        val pingId = intent.getStringExtra(EXTRA_PING_ID)
        val connectionId = intent.getLongExtra(EXTRA_CONNECTION_ID, -1)
        val senderName = intent.getStringExtra(EXTRA_SENDER_NAME) ?: "Unknown"

        if (pingId == null || connectionId == -1L) {
            Log.e(TAG, "Invalid accept message intent")
            return
        }

        Log.i(TAG, "User accepted message from $senderName")

        // Create encrypted Pong response (authenticated = true)
        val encryptedPong = RustBridge.respondToPing(pingId, true)
        if (encryptedPong == null) {
            Log.e(TAG, "Failed to create Pong response")
            ThemedToast.show(this, "Failed to accept message")
            return
        }

        Log.i(TAG, "Created encrypted Pong: ${encryptedPong.size} bytes")

        Log.i(TAG, "Sending Pong and waiting for incoming message...")
        ThemedToast.show(this, "Accepting message from $senderName...")

        // Send Pong back to sender and receive the message
        // sendPongBytes() returns the encrypted message after sending the Pong
        val encryptedMessage = RustBridge.sendPongBytes(connectionId, encryptedPong)

        if (encryptedMessage != null && encryptedMessage.isNotEmpty()) {
            Log.i(TAG, "Received encrypted message: ${encryptedMessage.size} bytes")
            // Process the received message
            processReceivedMessage(encryptedMessage, pingId, senderName)
        } else {
            Log.w(TAG, "No message received or empty message")
            ThemedToast.show(this, "No message received from $senderName")
        }

        // Cancel the auth notification
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.cancel(connectionId.toInt())
    }

    private fun handleDeclineMessage(intent: Intent) {
        val pingId = intent.getStringExtra(EXTRA_PING_ID)
        val connectionId = intent.getLongExtra(EXTRA_CONNECTION_ID, -1)
        val senderName = intent.getStringExtra(EXTRA_SENDER_NAME) ?: "Unknown"

        if (pingId == null || connectionId == -1L) {
            Log.e(TAG, "Invalid decline message intent")
            return
        }

        Log.i(TAG, "User declined message from $senderName")

        // Create encrypted Pong response (authenticated = false)
        val encryptedPong = RustBridge.respondToPing(pingId, false)
        if (encryptedPong != null) {
            RustBridge.sendPongBytes(connectionId, encryptedPong)
            Log.i(TAG, "Sent decline Pong to $senderName")
        }

        ThemedToast.show(this, "Declined message from $senderName")

        // Cancel the auth notification
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.cancel(connectionId.toInt())
    }

    private fun startTorService() {
        if (isServiceRunning) {
            Log.d(TAG, "Tor service already running")
            return
        }

        Log.i(TAG, "Starting Tor foreground service (SDK ${Build.VERSION.SDK_INT})")

        // Start as foreground service with notification IMMEDIATELY to avoid ANR
        val notification = createNotification("Connecting to Tor...")
        Log.d(TAG, "Notification created")

        // Android 14+ requires specifying foreground service type
        // Using SPECIAL_USE for Tor connectivity (24/7 operation required for message protocol)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            Log.d(TAG, "Using Android 14+ startForeground with SPECIAL_USE service type")
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
            Log.i(TAG, "startForeground called successfully (Android 14+, SPECIAL_USE)")
        } else {
            Log.d(TAG, "Using legacy startForeground")
            startForeground(NOTIFICATION_ID, notification)
            Log.i(TAG, "startForeground called successfully (legacy)")
        }

        // Acquire wake lock
        wakeLock?.acquire()

        isServiceRunning = true
        running = true

        // Schedule AlarmManager backup for service restart
        scheduleServiceRestart()

        // Initialize Tor in BACKGROUND THREAD to avoid ANR
        Thread {
            try {
                if (!torManager.isInitialized()) {
                    Log.d(TAG, "Tor not initialized, initializing now...")
                    torManager.initializeAsync { success, onionAddress ->
                        if (success && onionAddress != null) {
                            Log.i(TAG, "Tor initialized successfully. Hidden service: $onionAddress")

                            // Reset reconnection state on success
                            isReconnecting = false
                            reconnectAttempts = 0
                            torConnected = true

                            // Ensure SOCKS proxy is running for outgoing connections
                            ensureSocksProxyRunning()

                            // Test SOCKS connectivity immediately after login
                            updateNotification("Testing connection...")
                            Thread.sleep(2000) // Give SOCKS proxy time to fully initialize
                            testSocksConnectivityAtStartup()

                            // Start listening for incoming Ping tokens
                            startIncomingListener()

                            // Schedule background message retry worker
                            com.securelegion.workers.MessageRetryWorker.schedule(this@TorService)
                            Log.d(TAG, "Message retry worker scheduled")

                            // PHASE 6: Send taps to all contacts to notify them we're online
                            sendTapsToAllContacts()

                            updateNotification("Connected to Tor")
                        } else {
                            Log.e(TAG, "Tor initialization failed - scheduling retry")
                            torConnected = false
                            updateNotification("Connection failed - Retrying...")

                            // Schedule retry with exponential backoff
                            scheduleReconnect()
                        }
                    }
                } else {
                    val onionAddress = torManager.getOnionAddress()
                    Log.d(TAG, "Tor already initialized. Address: $onionAddress")

                    // Check if Tor is actually still running (e.g., after app restart)
                    val isTorActuallyRunning = try {
                        RustBridge.getBootstrapStatus() >= 100
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to check bootstrap status: ${e.message}")
                        false
                    }

                    if (isTorActuallyRunning) {
                        // Tor is still running, just restore state
                        Log.i(TAG, "Tor already running - restoring service state")
                        torConnected = true
                        updateNotification("Connected to Tor")

                        // Ensure SOCKS proxy is running for outgoing connections
                        ensureSocksProxyRunning()

                        // Ensure listener is started (in case service was restarted)
                        startIncomingListener()

                        // Schedule background message retry worker
                        com.securelegion.workers.MessageRetryWorker.schedule(this@TorService)
                        Log.d(TAG, "Message retry worker scheduled")

                        // PHASE 6: Send taps to all contacts to notify them we're online
                        sendTapsToAllContacts()
                    } else {
                        // Tor not running - need to reconnect
                        Log.d(TAG, "Tor not running - triggering reconnection")
                        updateNotification("Connecting to Tor...")
                        attemptReconnect()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error during Tor initialization", e)
                torConnected = false
                updateNotification("Error - Retrying...")
                scheduleReconnect()
            }
        }.start()
    }

    private fun startIncomingListener() {
        try {
            // Check if listener is already running - if so, just start pollers
            if (isListenerRunning) {
                Log.d(TAG, "Listener already running, skipping restart")
                startPingPoller()
                startTapPoller()
                startPongPoller()
                return
            }

            Log.d(TAG, "Starting hidden service listener on port 8080...")
            val success = RustBridge.startHiddenServiceListener(8080)
            if (success) {
                Log.i(TAG, "Hidden service listener started successfully")
                isListenerRunning = true
            } else {
                Log.w(TAG, "Listener already running (started by TorManager)")
                isListenerRunning = true
            }

            // Start polling for incoming Pings (whether we started the listener or it's already running)
            startPingPoller()

            // PHASE 7: Start tap listener on port 9151
            Log.d(TAG, "Starting tap listener on port 9151...")
            val tapSuccess = RustBridge.startTapListener(9151)
            if (tapSuccess) {
                Log.i(TAG, "Tap listener started successfully")
            } else {
                Log.w(TAG, "Tap listener already running")
            }

            // Start polling for incoming taps
            startTapPoller()

            // PHASE 8: Start pong listener on port 9152
            Log.d(TAG, "Starting pong listener on port 9152...")
            val pongSuccess = RustBridge.startPongListener(9152)
            if (pongSuccess) {
                Log.i(TAG, "Pong listener started successfully")
            } else {
                Log.w(TAG, "Pong listener already running")
            }

            // Start polling for incoming pongs
            startPongPoller()

            // PHASE 9: Start ACK listener on port 9153
            Log.d(TAG, "Starting ACK listener on port 9153...")
            val ackSuccess = RustBridge.startAckListener(9153)
            if (ackSuccess) {
                Log.i(TAG, "ACK listener started successfully")
            } else {
                Log.w(TAG, "ACK listener already running")
            }

            // Start polling for incoming ACKs
            startAckPoller()

            // Ensure SOCKS proxy is running for outgoing connections
            ensureSocksProxyRunning()

            // Verify SOCKS proxy is actually running
            if (RustBridge.isSocksProxyRunning()) {
                // All listeners, pollers, and SOCKS proxy ready - mark as ready for messaging
                listenersReady = true
                Log.i(TAG, "✓ All listeners, pollers, and SOCKS proxy (9050) ready - messaging enabled")
            } else {
                Log.w(TAG, "SOCKS proxy not running - messaging may not work for outgoing messages")
                listenersReady = true // Still mark as ready since incoming works
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting listener", e)
            // Mark as running anyway to prevent restart attempts
            isListenerRunning = true
            // Try to start Ping poller anyway in case listener is already running
            startPingPoller()
            // Try to start tap poller
            try {
                startTapPoller()
            } catch (e2: Exception) {
                Log.e(TAG, "Error starting tap poller", e2)
            }
            // Try to start pong poller
            try {
                startPongPoller()
            } catch (e3: Exception) {
                Log.e(TAG, "Error starting pong poller", e3)
            }
            // Try to start ACK poller
            try {
                startAckPoller()
            } catch (e4: Exception) {
                Log.e(TAG, "Error starting ACK poller", e4)
            }
            // Mark as ready even if some pollers failed (best effort)
            listenersReady = true
            Log.w(TAG, "Listeners ready with some errors - messaging may be limited")
        }
    }

    private fun startPingPoller() {
        // Check if already running
        if (isPingPollerRunning) {
            Log.d(TAG, "Ping poller already running, skipping")
            return
        }

        isPingPollerRunning = true

        // Poll for incoming Pings in background thread
        Thread {
            Log.d(TAG, "Ping poller thread started")
            var pollCount = 0
            while (isServiceRunning) {
                try {
                    val pingBytes = RustBridge.pollIncomingPing()
                    if (pingBytes != null) {
                        Log.i(TAG, "Received incoming Ping token: ${pingBytes.size} bytes")
                        handleIncomingPing(pingBytes)
                    } else {
                        // Log every 10 seconds to confirm poller is running
                        pollCount++
                        if (pollCount % 10 == 0) {
                            Log.d(TAG, "Ping poller alive (poll #$pollCount, no ping)")
                        }
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

    /**
     * PHASE 7: Start tap poller with bidirectional handling
     */
    private fun startTapPoller() {
        if (isTapPollerRunning) {
            Log.d(TAG, "Tap poller already running, skipping")
            return
        }

        isTapPollerRunning = true

        // Poll for incoming taps in background thread
        Thread {
            Log.d(TAG, "Tap poller thread started")
            while (isServiceRunning) {
                try {
                    val tapBytes = RustBridge.pollIncomingTap()
                    if (tapBytes != null) {
                        Log.i(TAG, "Received incoming tap: ${tapBytes.size} bytes")
                        handleIncomingTap(tapBytes)
                    }

                    // Poll every 2 seconds (taps are less frequent than Pings)
                    Thread.sleep(2000)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "Tap poller interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling for taps", e)
                }
            }
            Log.d(TAG, "Tap poller thread stopped")
        }.start()
    }

    /**
     * PHASE 7: Handle incoming tap with bidirectional retry logic
     * When we receive a tap from Contact X, we check:
     * 1. Do we have a pending Ping FROM them? → Send Pong
     * 2. Do we have pending messages TO them? → Retry Ping
     */
    private fun handleIncomingTap(tapWireBytes: ByteArray) {
        try {
            Log.i(TAG, "Handling incoming tap (${tapWireBytes.size} bytes)")

            // Decrypt tap to get sender's X25519 public key
            val senderX25519PubKey = RustBridge.decryptIncomingTap(tapWireBytes)
            if (senderX25519PubKey == null) {
                Log.e(TAG, "Failed to decrypt tap")
                return
            }

            Log.i(TAG, "Tap decrypted, sender X25519: ${android.util.Base64.encodeToString(senderX25519PubKey, android.util.Base64.NO_WRAP)}")

            // Look up contact by X25519 public key
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            val senderX25519Base64 = android.util.Base64.encodeToString(senderX25519PubKey, android.util.Base64.NO_WRAP)
            val contact = database.contactDao().getContactByX25519PublicKey(senderX25519Base64)

            if (contact == null) {
                Log.w(TAG, "Tap from unknown contact (not in database)")
                return
            }

            Log.i(TAG, "Tap from contact: ${contact.displayName} (ID: ${contact.id})")

            // ==== BIDIRECTIONAL HANDLING ====

            // CHECK 1: Do we have a pending Ping FROM them?
            val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
            val hasPendingPing = prefs.contains("ping_${contact.id}_id")

            if (hasPendingPing) {
                Log.i(TAG, "Found pending Ping from ${contact.displayName} - will download on user request")
                // Note: We DON'T auto-download - user manually clicks download button
                // This is by design for privacy/security
            }

            // CHECK 2: Do we have pending messages TO them?
            // Wrap in coroutine scope since we're calling suspend functions
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val pendingMessages = database.messageDao().getMessagesAwaitingPong()
                        .filter { it.contactId == contact.id }

                    if (pendingMessages.isNotEmpty()) {
                        Log.i(TAG, "Found ${pendingMessages.size} pending message(s) to ${contact.displayName} - triggering retry")

                        // Trigger retry for each pending message
                        val messageService = com.securelegion.services.MessageService(this@TorService)
                        for (message in pendingMessages) {
                            // Skip if Ping already delivered (prevents ghost pings)
                            if (message.pingDelivered) {
                                Log.d(TAG, "Ping already delivered for ${message.messageId} - skipping tap retry (no ghost ping)")
                                continue
                            }

                            try {
                                val result = messageService.sendPingForMessage(message)
                                if (result.isSuccess) {
                                    // Update retry counter
                                    val updatedMessage = message.copy(
                                        retryCount = message.retryCount + 1,
                                        lastRetryTimestamp = System.currentTimeMillis()
                                    )
                                    database.messageDao().updateMessage(updatedMessage)
                                    Log.i(TAG, "Retried Ping for message ${message.messageId} after tap")
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to retry Ping for message ${message.messageId}", e)
                            }
                        }
                    } else {
                        Log.d(TAG, "No pending messages to ${contact.displayName}")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error checking pending messages", e)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling tap", e)
        }
    }

    /**
     * PHASE 8: Start pong poller for receiving delayed pong responses
     */
    private fun startPongPoller() {
        if (isPongPollerRunning) {
            Log.d(TAG, "Pong poller already running, skipping")
            return
        }

        isPongPollerRunning = true

        // Poll for incoming pongs in background thread
        Thread {
            Log.d(TAG, "Pong poller thread started")
            while (isServiceRunning) {
                try {
                    val pongBytes = RustBridge.pollIncomingPong()
                    if (pongBytes != null) {
                        Log.i(TAG, "Received incoming pong via listener: ${pongBytes.size} bytes")

                        // Decrypt and store pong in GLOBAL_PONG_SESSIONS
                        val success = RustBridge.decryptAndStorePongFromListener(pongBytes)
                        if (success) {
                            Log.i(TAG, "✓ Pong decrypted and stored successfully")
                        } else {
                            Log.e(TAG, "✗ Failed to decrypt and store pong")
                        }
                    }

                    // Poll every 2 seconds (pongs are relatively infrequent)
                    Thread.sleep(2000)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "Pong poller interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling for pongs", e)
                }
            }
            Log.d(TAG, "Pong poller thread stopped")
        }.start()
    }

    /**
     * PHASE 9: Start ACK poller for receiving delivery confirmations
     */
    private fun startAckPoller() {
        if (isAckPollerRunning) {
            Log.d(TAG, "ACK poller already running, skipping")
            return
        }

        isAckPollerRunning = true

        // Poll for incoming ACKs in background thread
        Thread {
            Log.d(TAG, "ACK poller thread started")
            while (isServiceRunning) {
                try {
                    val ackBytes = RustBridge.pollIncomingAck()
                    if (ackBytes != null) {
                        Log.i(TAG, "Received incoming ACK via listener: ${ackBytes.size} bytes")

                        // Decrypt and store ACK in GLOBAL_ACK_SESSIONS, get item_id (ping_id or message_id)
                        val itemId = RustBridge.decryptAndStoreAckFromListener(ackBytes)
                        if (itemId != null) {
                            Log.i(TAG, "✓ ACK decrypted successfully for item: $itemId")
                            // Handle the ACK to update delivery status
                            handleIncomingAck(itemId)
                        } else {
                            Log.e(TAG, "✗ Failed to decrypt and store ACK")
                        }
                    }

                    // Poll every 2 seconds (ACKs are relatively infrequent)
                    Thread.sleep(2000)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "ACK poller interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling for ACKs", e)
                }
            }
            Log.d(TAG, "ACK poller thread stopped")
        }.start()
    }

    /**
     * Handle incoming ACK to update delivery status
     * @param itemId The ping_id or message_id that was acknowledged
     */
    private fun handleIncomingAck(itemId: String) {
        try {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                    // Try to find message by pingId first (for PING_ACK)
                    var message = database.messageDao().getMessageByPingId(itemId)

                    if (message != null) {
                        // This is a PING_ACK - mark pingDelivered = true
                        Log.i(TAG, "Received PING_ACK for message ${message.messageId} (pingId: $itemId)")
                        val updatedMessage = message.copy(pingDelivered = true)
                        database.messageDao().updateMessage(updatedMessage)
                        Log.i(TAG, "✓ Marked pingDelivered=true for message ${message.messageId}")
                    } else {
                        // Try to find message by messageId (for MESSAGE_ACK)
                        message = database.messageDao().getMessageByMessageId(itemId)
                        if (message != null) {
                            // This is a MESSAGE_ACK - mark messageDelivered = true
                            Log.i(TAG, "Received MESSAGE_ACK for message ${message.messageId}")
                            val updatedMessage = message.copy(
                                messageDelivered = true,
                                status = com.securelegion.database.entities.Message.STATUS_DELIVERED
                            )
                            database.messageDao().updateMessage(updatedMessage)
                            Log.i(TAG, "✓ Marked messageDelivered=true and status=DELIVERED for message ${message.messageId}")
                        } else {
                            Log.w(TAG, "Could not find message for ACK item_id: $itemId")
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error updating message delivery status", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming ACK", e)
        }
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

            // Get database instance for tracking and deduplication
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            // Try to decrypt as Ping first (may throw exception if it's actually a Pong)
            var pingId: String? = null
            try {
                pingId = RustBridge.decryptIncomingPing(encryptedPingWire)
            } catch (e: Exception) {
                Log.w(TAG, "⚠️  decryptIncomingPing threw exception: ${e.message}")
            }

            if (pingId == null) {
                Log.w(TAG, "⚠️  Failed to decrypt as Ping - trying as Pong...")

                // This might be a Pong response! Try to decrypt as Pong
                try {
                    val pongPingId = RustBridge.decryptIncomingPong(encryptedPingWire)

                    if (pongPingId != null) {
                        Log.i(TAG, "✓ Successfully decrypted as Pong for Ping ID: $pongPingId")

                        // Track this pongId to prevent duplicate processing (PRIMARY deduplication)
                        val pongTracking = com.securelegion.database.entities.ReceivedId(
                            receivedId = "pong_$pongPingId",
                            idType = com.securelegion.database.entities.ReceivedId.TYPE_PONG,
                            receivedTimestamp = System.currentTimeMillis()
                        )
                        val rowId = kotlinx.coroutines.runBlocking {
                            database.receivedIdDao().insertReceivedId(pongTracking)
                        }

                        if (rowId == -1L) {
                            Log.w(TAG, "⚠️  DUPLICATE PONG BLOCKED! PongId=pong_$pongPingId already in tracking table")
                            return
                        }
                        Log.i(TAG, "→ New Pong - tracked in database (rowId=$rowId)")

                        // Check if we already sent the message for this Pong (secondary check)


                        val message = kotlinx.coroutines.runBlocking {
                            database.messageDao().getMessageByPingId(pongPingId)
                        }

                        if (message != null && message.messageDelivered) {
                            Log.w(TAG, "⚠️  Duplicate Pong detected! Message for pingId=$pongPingId already delivered (messageId=${message.messageId})")
                            Log.i(TAG, "→ Skipping duplicate message send")
                            return
                        }

                        if (message == null) {
                            Log.w(TAG, "⚠️  Received Pong for unknown pingId=$pongPingId - no message found in database")
                            return
                        }

                        Log.i(TAG, "→ New Pong - sending message payload for messageId=${message.messageId}")

                        // IMMEDIATELY trigger sending the message payload (don't wait for retry worker!)
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            try {
                                val messageService = MessageService(this@TorService)
                                val result = messageService.pollForPongsAndSendMessages()

                                if (result.isSuccess) {
                                    val sentCount = result.getOrNull() ?: 0
                                    Log.i(TAG, "✓ Sent $sentCount message payload(s) immediately after Pong")
                                } else {
                                    Log.e(TAG, "✗ Failed to send message payload: ${result.exceptionOrNull()?.message}")
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Error sending message payload after Pong", e)
                            }
                        }
                        return
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "⚠️  decryptIncomingPong also threw exception: ${e.message}")
                }

                // Neither Ping nor Pong - must be a message blob!
                Log.i(TAG, "→ Not a Ping or Pong - treating as MESSAGE BLOB")
                handleIncomingMessageBlob(encryptedPingWire)
                return
            }

            // Successfully decrypted as Ping
            Log.i(TAG, "✓ Decrypted as Ping. Ping ID: $pingId")

            // Track this pingId to prevent duplicate processing (PRIMARY deduplication)
            Log.d(TAG, "═══ DEDUPLICATION CHECK: Ping ID = $pingId ═══")
            val pingTracking = com.securelegion.database.entities.ReceivedId(
                receivedId = pingId,
                idType = com.securelegion.database.entities.ReceivedId.TYPE_PING,
                receivedTimestamp = System.currentTimeMillis()
            )

            val rowId = try {
                kotlinx.coroutines.runBlocking {
                    Log.d(TAG, "Attempting to insert Ping ID into received_ids table...")
                    val result = database.receivedIdDao().insertReceivedId(pingTracking)
                    Log.d(TAG, "Insert result: rowId=$result (${if (result == -1L) "DUPLICATE" else "NEW"})")
                    result
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ DATABASE INSERT FAILED! This ping will be processed (GHOST RISK!)", e)
                Log.e(TAG, "Exception details: ${e.javaClass.simpleName}: ${e.message}")
                0L // Treat as new if database fails (will cause ghosts but better than crash)
            }

            if (rowId == -1L) {
                Log.w(TAG, "⚠️  DUPLICATE PING BLOCKED! PingId=$pingId already in tracking table")
                Log.w(TAG, "→ This is the deduplication working correctly - no ghost ping created")
                // Still send PING_ACK to allow sender to retry, but don't process/notify
                return
            }
            Log.i(TAG, "✓ NEW PING ACCEPTED - Tracked in database (rowId=$rowId)")

            // Check if this ping has already been processed in messages table (secondary check)


            val existingMessage = kotlinx.coroutines.runBlocking {
                database.messageDao().getMessageByPingId(pingId)
            }

            if (existingMessage != null) {
                Log.w(TAG, "⚠️  Duplicate Ping detected! PingId=$pingId already processed (messageId=${existingMessage.messageId})")
                Log.i(TAG, "→ Skipping notification for duplicate Ping, but will still respond to allow sender to retry")
                // Don't show notification, don't store pending ping, but continue to send PING_ACK
                // This allows the sender to retry getting their message if they didn't receive it
            } else {
                Log.i(TAG, "→ New Ping - processing normally")
            }

            // Get sender information from the Ping token
            val senderPublicKey = RustBridge.getPingSenderPublicKey(pingId)

            // Look up sender in contacts database
            val senderName = if (senderPublicKey != null) {
                lookupContactName(senderPublicKey)
            } else {
                "Unknown Contact"
            }

            Log.i(TAG, "Incoming message request from: $senderName")

            // Only store pending ping and show notification if this is NOT a duplicate
            var contactId: Long? = null
            if (existingMessage == null) {
                // Store pending Ping for user to download later (including encrypted bytes for restore)
                contactId = storePendingPing(pingId, connectionId, senderPublicKey, senderName, encryptedPingWire)

                // Only show notification and broadcast if Ping was stored (sender is in contacts)
                if (contactId != null) {
                    // Show simple notification - no preview or accept/decline
                    showNewMessageNotification()

                    // Broadcast to update MainActivity and ChatActivity if open (explicit broadcast)
                    val intent = Intent("com.securelegion.NEW_PING")
                    intent.setPackage(packageName) // Make it explicit
                    intent.putExtra("CONTACT_ID", contactId)
                    sendBroadcast(intent)
                    Log.d(TAG, "Sent explicit NEW_PING broadcast for contactId=$contactId")
                } else {
                    Log.w(TAG, "Ping from unknown contact - no notification shown")
                }
            } else {
                // For duplicate pings, still need contactId for PING_ACK
                if (senderPublicKey != null) {
                    val publicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)
                    val contact = database.contactDao().getContactByPublicKey(publicKeyBase64)
                    contactId = contact?.id
                }
            }

            // Send PING_ACK back to sender to confirm we stored the Ping (or to allow retry for duplicates)
            if (senderPublicKey != null && contactId != null) {
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val contact = database.contactDao().getContactById(contactId)
                        if (contact != null) {
                            Log.d(TAG, "Sending PING_ACK for pingId=$pingId to ${contact.displayName}")

                            val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                            val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)

                            val ackSuccess = RustBridge.sendDeliveryAck(
                                pingId,
                                "PING_ACK",
                                senderEd25519Pubkey,
                                senderX25519Pubkey,
                                contact.torOnionAddress
                            )

                            if (ackSuccess) {
                                Log.i(TAG, "✓ PING_ACK sent successfully for pingId=$pingId")
                            } else {
                                Log.e(TAG, "✗ Failed to send PING_ACK for pingId=$pingId")
                            }
                        } else {
                            Log.w(TAG, "Could not find contact with ID $contactId to send PING_ACK")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error sending PING_ACK", e)
                    }
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming Ping", e)
        }
    }

    /**
     * Handle incoming message blob
     * Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Message]
     */
    private fun handleIncomingMessageBlob(encryptedMessageWire: ByteArray) {
        try {
            // Friend requests arrive here after being routed by Rust (wire type 0x07 already stripped)
            // Wire format from Rust: [Sender X25519 - 32 bytes][Encrypted Friend Request]
            // Note: Regular messages (TEXT/VOICE) go through a different channel

            Log.i(TAG, "╔════════════════════════════════════════")
            Log.i(TAG, "║ INCOMING MESSAGE BLOB (${encryptedMessageWire.size} bytes)")
            Log.i(TAG, "╚════════════════════════════════════════")

            if (encryptedMessageWire.size < 32) {
                Log.e(TAG, "Message blob too short - missing X25519 public key")
                return
            }

            // Extract sender's X25519 public key (first 32 bytes)
            val senderX25519PublicKey = encryptedMessageWire.copyOfRange(0, 32)
            val encryptedPayload = encryptedMessageWire.copyOfRange(32, encryptedMessageWire.size)

            Log.d(TAG, "Sender X25519 pubkey: ${android.util.Base64.encodeToString(senderX25519PublicKey, android.util.Base64.NO_WRAP).take(16)}...")
            Log.d(TAG, "Encrypted payload: ${encryptedPayload.size} bytes")

            // Look up contact by X25519 public key to see if sender is known
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            val senderX25519Base64 = android.util.Base64.encodeToString(senderX25519PublicKey, android.util.Base64.NO_WRAP)
            val contact = database.contactDao().getContactByX25519PublicKey(senderX25519Base64)

            if (contact == null) {
                // Unknown sender - this must be a friend request
                // Friend requests are the ONLY messages from unknown contacts that are allowed
                Log.i(TAG, "→ Unknown sender - treating as FRIEND REQUEST")
                handleFriendRequest(senderX25519PublicKey, encryptedPayload)
                return
            }

            // Known contact - this is a regular message (but routed incorrectly!)
            Log.w(TAG, "⚠️  Message from known contact ${contact.displayName} came through FRIEND_REQUEST channel!")
            Log.w(TAG, "    This should only happen for friend requests from unknown contacts")
            val encryptedMessage = encryptedPayload

            // Generate message ID from encrypted payload hash (ensures uniqueness per encryption)
            // Each encryption has random nonce, so same plaintext = different encrypted blob = different hash
            // This allows user to send "yo" "yo" "yo" quickly, but blocks true network duplicates
            val encryptedBlobHash = java.security.MessageDigest.getInstance("SHA-256").digest(encryptedPayload)
            val blobMessageId = "blob_" + android.util.Base64.encodeToString(encryptedBlobHash, android.util.Base64.NO_WRAP).take(28)

            Log.i(TAG, "✓ Message from: ${contact.displayName} (blobId: ${blobMessageId.take(16)}...)")

            // Decrypt message using OUR OWN public key (message was encrypted with our public key)
            // MVP encryption: sender encrypts with recipient's public key, recipient decrypts with their own public key
            val ourEd25519PublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Check if message has metadata (version byte)
            var messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_TEXT
            var voiceDuration: Int? = null
            var actualEncryptedMessage = encryptedMessage
            var voiceFilePath: String? = null

            Log.d(TAG, "Parsing message metadata from ${encryptedMessage.size} bytes")
            if (encryptedMessage.isNotEmpty()) {
                Log.d(TAG, "First byte: 0x${String.format("%02X", encryptedMessage[0])}")
            }

            // Check for metadata byte (0x00 = TEXT, 0x01 = VOICE)
            if (encryptedMessage.isNotEmpty()) {
                when (encryptedMessage[0].toInt()) {
                    0x00 -> {
                        // TEXT message - strip metadata byte
                        Log.d(TAG, "Message type: TEXT (v2)")
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)
                        Log.d(TAG, "  Stripped 1 byte metadata, encrypted payload: ${actualEncryptedMessage.size} bytes")
                    }
                    0x01 -> {
                        // VOICE message - extract duration and strip metadata
                        if (encryptedMessage.size >= 5) {
                            Log.d(TAG, "Message type: VOICE (v2)")
                            messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE
                            // Extract duration (4 bytes, big-endian)
                            voiceDuration = ((encryptedMessage[1].toInt() and 0xFF) shl 24) or
                                          ((encryptedMessage[2].toInt() and 0xFF) shl 16) or
                                          ((encryptedMessage[3].toInt() and 0xFF) shl 8) or
                                          (encryptedMessage[4].toInt() and 0xFF)
                            actualEncryptedMessage = encryptedMessage.copyOfRange(5, encryptedMessage.size)
                            Log.d(TAG, "  Voice duration: ${voiceDuration}s")
                            Log.d(TAG, "  Stripped 5 bytes metadata, encrypted payload: ${actualEncryptedMessage.size} bytes")
                        } else {
                            Log.e(TAG, "✗ VOICE message too short - missing duration metadata (only ${encryptedMessage.size} bytes)")
                            return
                        }
                    }
                    else -> {
                        // Legacy message without metadata - treat as TEXT
                        Log.d(TAG, "Message type: TEXT (legacy, no metadata)")
                    }
                }
            }

            Log.d(TAG, "Attempting to decrypt ${actualEncryptedMessage.size} bytes...")
            val plaintext = RustBridge.decryptMessage(actualEncryptedMessage, ourEd25519PublicKey, ourPrivateKey)
            if (plaintext == null) {
                Log.e(TAG, "✗ Failed to decrypt message from ${contact.displayName}")
                Log.e(TAG, "  Encrypted payload size: ${actualEncryptedMessage.size} bytes")
                Log.e(TAG, "  Message type: ${messageType}")
                if (messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE) {
                    Log.e(TAG, "  Voice duration: ${voiceDuration}s")
                }
                return
            }

            Log.i(TAG, "✓ Decrypted message (${messageType}): ${if (messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_TEXT) plaintext.take(50) else "${voiceDuration}s voice, ${plaintext.length} bytes"}...")

            // Save message directly to database (already decrypted)
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    // Use the message ID generated from encrypted payload hash
                    // This was calculated earlier to prevent blocking legitimate rapid messages
                    val messageId = blobMessageId

                    // Get database
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                    // Track this messageId to prevent duplicate processing (PRIMARY deduplication)
                    val messageTracking = com.securelegion.database.entities.ReceivedId(
                        receivedId = messageId,
                        idType = com.securelegion.database.entities.ReceivedId.TYPE_MESSAGE,
                        receivedTimestamp = System.currentTimeMillis()
                    )
                    val rowId = database.receivedIdDao().insertReceivedId(messageTracking)

                    if (rowId == -1L) {
                        Log.w(TAG, "⚠️  DUPLICATE MESSAGE BLOB BLOCKED! MessageId=$messageId already in tracking table")
                        Log.i(TAG, "→ Skipping duplicate message blob processing")

                        // Send MESSAGE_ACK to stop sender from retrying
                        try {
                            val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                            val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)

                            val ackSuccess = RustBridge.sendDeliveryAck(
                                messageId,
                                "MESSAGE_ACK",
                                senderEd25519Pubkey,
                                senderX25519Pubkey,
                                contact.torOnionAddress
                            )

                            if (ackSuccess) {
                                Log.i(TAG, "✓ MESSAGE_ACK sent for duplicate message blob")
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Error sending MESSAGE_ACK for duplicate blob", e)
                        }
                        return@launch
                    }
                    Log.i(TAG, "→ New Message Blob - tracked in database (rowId=$rowId)")

                    // PRIMARY deduplication via ReceivedId table above is sufficient
                    // No secondary check needed - this was blocking rapid identical messages

                    // If it's a voice message, save the audio file
                    if (messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE) {
                        try {
                            val voiceRecorder = com.securelegion.utils.VoiceRecorder(this@TorService)
                            val audioBytes = plaintext.toByteArray(Charsets.ISO_8859_1)
                            voiceFilePath = voiceRecorder.saveVoiceMessage(audioBytes, voiceDuration ?: 0)
                            Log.d(TAG, "✓ Saved voice file: $voiceFilePath")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to save voice file", e)
                            // Continue anyway, will just show broken voice message
                        }
                    }

                    // Create message entity (store plaintext in encryptedContent field for now)
                    val message = com.securelegion.database.entities.Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = if (messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_TEXT) plaintext else "", // Store plaintext for TEXT, empty for VOICE
                        messageType = messageType,
                        voiceDuration = voiceDuration,
                        voiceFilePath = voiceFilePath,
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = com.securelegion.database.entities.Message.STATUS_DELIVERED,
                        signatureBase64 = "", // TODO: Verify signature
                        nonceBase64 = "" // Not needed for already-decrypted messages
                    )

                    // Save to database
                    val savedMessageId = database.messageDao().insertMessage(message)
                    Log.i(TAG, "✓ Message saved to database: $savedMessageId")

                    // Send MESSAGE_ACK to sender to confirm receipt
                    try {
                        val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                        val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)

                        val ackSuccess = RustBridge.sendDeliveryAck(
                            messageId,
                            "MESSAGE_ACK",
                            senderEd25519Pubkey,
                            senderX25519Pubkey,
                            contact.torOnionAddress
                        )

                        if (ackSuccess) {
                            Log.i(TAG, "✓ MESSAGE_ACK sent successfully for messageId=$messageId")
                        } else {
                            Log.e(TAG, "✗ Failed to send MESSAGE_ACK for messageId=$messageId")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error sending MESSAGE_ACK", e)
                    }

                    // Clear pending Ping from SharedPreferences (message has been downloaded)
                    val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
                    prefs.edit().apply {
                        remove("ping_${contact.id}_id")
                        remove("ping_${contact.id}_connection")
                        remove("ping_${contact.id}_name")
                        remove("ping_${contact.id}_timestamp")
                        remove("ping_${contact.id}_data")
                        remove("ping_${contact.id}_onion")
                        apply()
                    }
                    Log.i(TAG, "✓ Cleared pending Ping for contact ${contact.id}")

                    // Broadcast to ChatActivity so it can refresh (explicit broadcast)
                    val intentChat = Intent("com.securelegion.MESSAGE_RECEIVED")
                    intentChat.setPackage(packageName) // Make it explicit
                    intentChat.putExtra("CONTACT_ID", contact.id)
                    sendBroadcast(intentChat)
                    Log.i(TAG, "✓ Broadcast explicit MESSAGE_RECEIVED for contact ${contact.id}")

                    // Broadcast to MainActivity to refresh chat list preview (explicit broadcast)
                    val intentMain = Intent("com.securelegion.NEW_PING")
                    intentMain.setPackage(packageName) // Make it explicit
                    intentMain.putExtra("CONTACT_ID", contact.id)
                    sendBroadcast(intentMain)
                    Log.i(TAG, "✓ Broadcast explicit NEW_PING to refresh MainActivity chat list")
                } catch (e: Exception) {
                    Log.e(TAG, "Error saving message", e)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming message blob", e)
        }
    }

    /**
     * Handle incoming friend request from unknown contact
     * Wire format: [0x07][Sender X25519 - 32 bytes][Encrypted FriendRequest JSON]
     * Note: Wire type byte and X25519 key are already stripped by caller
     */
    private fun handleFriendRequest(senderX25519PublicKey: ByteArray, encryptedFriendRequest: ByteArray) {
        try {
            Log.i(TAG, "╔════════════════════════════════════════")
            Log.i(TAG, "║ FRIEND REQUEST from unknown contact")
            Log.i(TAG, "╚════════════════════════════════════════")

            // Wire type byte (0x07) has already been stripped by caller
            if (encryptedFriendRequest.size < 1) {
                Log.e(TAG, "Friend request too short")
                return
            }

            // Reconstruct wire format for decryption: [Sender X25519 - 32 bytes][Encrypted Data]
            // The encryptMessage function creates this format, and decryptMessage expects it
            val wireMessage = senderX25519PublicKey + encryptedFriendRequest

            Log.d(TAG, "Reconstructed wire message: ${wireMessage.size} bytes (32 byte X25519 + ${encryptedFriendRequest.size} byte payload)")

            // Decrypt friend request (decryptMessage will derive X25519 private key from Ed25519)
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val ourEd25519PublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            val friendRequestJson = com.securelegion.crypto.RustBridge.decryptMessage(
                wireMessage,
                ourEd25519PublicKey,
                ourPrivateKey
            )

            if (friendRequestJson == null) {
                Log.e(TAG, "Failed to decrypt friend request")
                return
            }

            Log.i(TAG, "Decrypted friend request JSON: $friendRequestJson")

            // Parse friend request
            val friendRequest = com.securelegion.models.FriendRequest.fromJson(friendRequestJson)
            Log.i(TAG, "Friend request from: ${friendRequest.displayName}")
            Log.i(TAG, "  IPFS CID: ${friendRequest.ipfsCid}")

            // Store in SharedPreferences as pending friend request
            val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
            val existingRequests = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()

            // Add new request (use JSON as storage format)
            val updatedRequests = existingRequests.toMutableSet()
            updatedRequests.add(friendRequestJson)
            prefs.edit().putStringSet("pending_requests", updatedRequests).apply()

            Log.i(TAG, "Friend request stored - total pending: ${updatedRequests.size}")

            // Show notification
            showFriendRequestNotification(friendRequest.displayName)

        } catch (e: Exception) {
            Log.e(TAG, "Error handling friend request", e)
        }
    }

    /**
     * Show notification for new friend request
     */
    private fun showFriendRequestNotification(senderName: String) {
        try {
            // Launch via LockActivity to prevent showing app before authentication
            val intent = android.content.Intent(this, com.securelegion.LockActivity::class.java).apply {
                putExtra("TARGET_ACTIVITY", "MainActivity")
                putExtra("SHOW_FRIEND_REQUESTS", true)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            val pendingIntent = android.app.PendingIntent.getActivity(
                this,
                0,
                intent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            )

            val notification = androidx.core.app.NotificationCompat.Builder(this, AUTH_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("New Friend Request")
                .setContentText("$senderName wants to add you as a friend")
                .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
                .setCategory(androidx.core.app.NotificationCompat.CATEGORY_SOCIAL)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()

            val notificationManager = getSystemService(android.app.NotificationManager::class.java)
            notificationManager.notify(1000, notification)

            Log.i(TAG, "Friend request notification shown")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show friend request notification", e)
        }
    }

    private fun lookupContactName(senderPublicKey: ByteArray): String {
        return try {
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            // Convert public key to Base64
            val publicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)

            // Look up contact by public key
            val contact = database.contactDao().getContactByPublicKey(publicKeyBase64)

            contact?.displayName ?: "Unknown Contact"
        } catch (e: Exception) {
            Log.e(TAG, "Failed to lookup contact name", e)
            "Unknown Contact"
        }
    }

    /**
     * Store pending Ping for user to manually download later
     */
    private fun storePendingPing(pingId: String, connectionId: Long, senderPublicKey: ByteArray?, senderName: String, encryptedPingWire: ByteArray): Long? {
        try {
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            // Find contact by public key
            if (senderPublicKey != null) {
                val publicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)
                Log.d(TAG, "Looking up contact by public key (Base64, first 20 chars): ${publicKeyBase64.take(20)}...")

                // Debug: List all contacts and their public keys
                val allContacts = kotlinx.coroutines.runBlocking {
                    database.contactDao().getAllContacts()
                }
                Log.d(TAG, "Total contacts in database: ${allContacts.size}")
                for (c in allContacts) {
                    Log.d(TAG, "  Contact: ${c.displayName}, PubKey (first 20 chars): ${c.publicKeyBase64.take(20)}...")
                }

                val contact = database.contactDao().getContactByPublicKey(publicKeyBase64)

                if (contact != null) {
                    // Store pending Ping info in SharedPreferences (including encrypted bytes for restore)
                    val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
                    val encryptedPingBase64 = android.util.Base64.encodeToString(encryptedPingWire, android.util.Base64.NO_WRAP)
                    prefs.edit().apply {
                        putString("ping_${contact.id}_id", pingId)
                        putLong("ping_${contact.id}_connection", connectionId)
                        putString("ping_${contact.id}_name", senderName)
                        putLong("ping_${contact.id}_timestamp", System.currentTimeMillis())
                        putString("ping_${contact.id}_data", encryptedPingBase64)  // Save encrypted Ping for restore
                        putString("ping_${contact.id}_onion", contact.torOnionAddress)  // Save sender's .onion address for new connection
                        apply()
                    }
                    Log.i(TAG, "Stored pending Ping for contact ${contact.id}: $senderName")
                    return contact.id  // Return contact ID for broadcast
                } else {
                    Log.w(TAG, "Cannot store Ping - sender not in contacts: $senderName")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store pending Ping", e)
        }
        return null  // Failed to find/store contact
    }

    /**
     * PHASE 6: Send taps to all contacts when Tor connects
     * This notifies contacts that we're online and they should retry any pending operations
     */
    private fun sendTapsToAllContacts() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.i(TAG, "Sending taps to all contacts...")

                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                // Get all contacts
                val contacts = database.contactDao().getAllContacts()

                if (contacts.isEmpty()) {
                    Log.d(TAG, "No contacts to send taps to")
                    return@launch
                }

                Log.i(TAG, "Sending taps to ${contacts.size} contact(s)")

                var successCount = 0
                var failureCount = 0

                for (contact in contacts) {
                    try {
                        // Get contact keys
                        val recipientEd25519PubKey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                        val recipientX25519PubKey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)

                        // Send tap
                        val success = RustBridge.sendTap(
                            recipientEd25519PubKey,
                            recipientX25519PubKey,
                            contact.torOnionAddress
                        )

                        if (success) {
                            Log.d(TAG, "Sent tap to ${contact.displayName}")
                            successCount++
                        } else {
                            Log.w(TAG, "Failed to send tap to ${contact.displayName}")
                            failureCount++
                        }

                        // Small delay between attempts to avoid overwhelming Tor
                        // (Don't delay after last contact)
                        if (contact != contacts.last()) {
                            kotlinx.coroutines.delay(150) // 150ms between taps
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error sending tap to ${contact.displayName}", e)
                        failureCount++
                    }
                }

                Log.i(TAG, "Tap broadcast complete: $successCount success, $failureCount failed")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send taps to contacts", e)
            }
        }
    }

    /**
     * Show simple notification that a message is waiting
     */
    private fun showNewMessageNotification() {
        // Launch via LockActivity to prevent showing app before authentication
        val openAppIntent = Intent(this, LockActivity::class.java).apply {
            putExtra("TARGET_ACTIVITY", "MainActivity")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openAppPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Get pending message count
        val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
        val pendingCount = prefs.all.filter { it.key.endsWith("_id") }.size

        // Only show notification if there are pending messages
        if (pendingCount > 0) {
            // Build notification
            val notification = NotificationCompat.Builder(this, AUTH_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("New Message")
                .setContentText("You have $pendingCount pending ${if (pendingCount == 1) "message" else "messages"}")
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setAutoCancel(true)
                .setContentIntent(openAppPendingIntent)
                .setNumber(pendingCount) // Shows badge on app icon
                .build()

            // Show notification
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(999, notification) // Use fixed ID so it updates instead of creating multiple

            Log.i(TAG, "New message notification shown ($pendingCount pending)")
        } else {
            // Cancel notification if no pending messages
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.cancel(999)
            Log.d(TAG, "No pending messages - notification cancelled")
        }
    }

    /**
     * Receive encrypted message after sending Pong
     */
    /**
     * Process a received encrypted message (decrypt, save to database, notify)
     */
    private fun processReceivedMessage(encryptedMessage: ByteArray, pingId: String, senderName: String) {
        try {
            Log.i(TAG, "Processing received encrypted message: ${encryptedMessage.size} bytes")

            // Get sender's public key from the Ping token
            val senderPublicKey = RustBridge.getPingSenderPublicKey(pingId)
            if (senderPublicKey == null) {
                Log.e(TAG, "Failed to get sender public key from Ping")
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    ThemedToast.show(this@TorService, "Failed to verify sender")
                }
                return
            }

            // Look up sender in contacts database
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            // Convert public key to Base64
            val publicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)

            // Get contact by public key
            val contact = database.contactDao().getContactByPublicKey(publicKeyBase64)

            if (contact == null) {
                Log.e(TAG, "Sender not in contacts - cannot decrypt message")
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    ThemedToast.show(this@TorService, "Message from unknown contact")
                }
                return
            }

            Log.i(TAG, "Message from contact: ${contact.displayName} (ID: ${contact.id})")

            // Get our Ed25519 private key for decryption
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Decrypt message using sender's Ed25519 public key and our private key
            val senderEd25519PublicKey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
            val messageText = RustBridge.decryptMessage(encryptedMessage, senderEd25519PublicKey, ourPrivateKey)

            if (messageText == null || messageText.isEmpty()) {
                Log.e(TAG, "Failed to decrypt message")
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    ThemedToast.show(this@TorService, "Failed to decrypt message")
                }
                return
            }

            Log.i(TAG, "Message decrypted successfully: ${messageText.take(50)}...")

            // Save message to database with deduplication
            kotlinx.coroutines.runBlocking {
                // Use pingId as messageId for deduplication (ping-based messages)
                // For direct messages without ping, we'll need a different approach
                val deterministicMessageId = "msg_$pingId"

                // Track this messageId to prevent duplicate processing (PRIMARY deduplication)
                val messageTracking = com.securelegion.database.entities.ReceivedId(
                    receivedId = deterministicMessageId,
                    idType = com.securelegion.database.entities.ReceivedId.TYPE_MESSAGE,
                    receivedTimestamp = System.currentTimeMillis()
                )
                val rowId = database.receivedIdDao().insertReceivedId(messageTracking)

                if (rowId == -1L) {
                    Log.w(TAG, "⚠️  DUPLICATE MESSAGE BLOCKED! MessageId=$deterministicMessageId already in tracking table")
                    Log.i(TAG, "→ Skipping duplicate message processing, but will send MESSAGE_ACK")

                    // Send MESSAGE_ACK to stop sender from retrying
                    try {
                        val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                        val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)

                        val ackSuccess = RustBridge.sendDeliveryAck(
                            deterministicMessageId,
                            "MESSAGE_ACK",
                            senderEd25519Pubkey,
                            senderX25519Pubkey,
                            contact.torOnionAddress
                        )

                        if (ackSuccess) {
                            Log.i(TAG, "✓ MESSAGE_ACK sent for duplicate message")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error sending MESSAGE_ACK for duplicate", e)
                    }
                    return@runBlocking
                }
                Log.i(TAG, "→ New Message - tracked in database (rowId=$rowId)")

                // PRIMARY deduplication via ReceivedId table above is sufficient
                // No secondary check needed - this was blocking rapid identical messages

                val message = com.securelegion.database.entities.Message(
                    contactId = contact.id,
                    messageId = deterministicMessageId,
                    encryptedContent = messageText,
                    isSentByMe = false,
                    timestamp = System.currentTimeMillis(),
                    status = com.securelegion.database.entities.Message.STATUS_DELIVERED,
                    signatureBase64 = "",
                    nonceBase64 = "",
                    isRead = false,
                    requiresReadReceipt = true,
                    selfDestructAt = null,
                    pingId = pingId,  // Store pingId for reference
                    messageDelivered = true  // Mark as delivered since we received it
                )

                val insertedMessage = database.messageDao().insertMessage(message)
                Log.i(TAG, "✓ Message saved to database with ID: $insertedMessage (messageId: $deterministicMessageId)")

                // Send MESSAGE_ACK to sender to confirm receipt
                try {
                    val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                    val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)

                    val ackSuccess = RustBridge.sendDeliveryAck(
                        deterministicMessageId,
                        "MESSAGE_ACK",
                        senderEd25519Pubkey,
                        senderX25519Pubkey,
                        contact.torOnionAddress
                    )

                    if (ackSuccess) {
                        Log.i(TAG, "✓ MESSAGE_ACK sent successfully for messageId=$deterministicMessageId")
                    } else {
                        Log.e(TAG, "✗ Failed to send MESSAGE_ACK for messageId=$deterministicMessageId")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending MESSAGE_ACK", e)
                }

                // Broadcast to update ChatActivity if it's open for this contact
                val messageReceivedIntent = Intent("com.securelegion.MESSAGE_RECEIVED").apply {
                    putExtra("CONTACT_ID", contact.id)
                }
                sendBroadcast(messageReceivedIntent)
                Log.d(TAG, "Broadcast sent: MESSAGE_RECEIVED for contact ${contact.id}")

                // Update app badge count
                updateAppBadgeCount(database)

                // Show notification on main thread
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    showMessageNotification(contact.displayName, messageText, contact.id)
                }

                // Send read receipt if required
                if (message.requiresReadReceipt) {
                    sendReadReceipt(contact.id, insertedMessage)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to process received message", e)
        }
    }

    private fun receiveIncomingMessage(connectionId: Long, pingId: String, senderName: String) {
        Thread {
            try {
                Log.d(TAG, "Waiting for message on connection $connectionId from $senderName...")

                // Receive message from sender (Rust code will handle reading from connection)
                val encryptedMessage = RustBridge.receiveIncomingMessage(connectionId)

                if (encryptedMessage != null && encryptedMessage.isNotEmpty()) {
                    Log.i(TAG, "Received encrypted message: ${encryptedMessage.size} bytes")
                    // Reuse the processing logic
                    processReceivedMessage(encryptedMessage, pingId, senderName)
                } else {
                    Log.w(TAG, "No message received or empty message")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error receiving incoming message", e)
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    ThemedToast.show(this@TorService, "Error receiving message: ${e.message}")
                }
            }
        }.start()
    }

    /**
     * Show notification for received message with preview and actions
     */
    private fun showMessageNotification(senderName: String, messageText: String, contactId: Long) {
        // Create intent to open chat when notification is tapped
        // Launch via LockActivity to prevent showing chat before authentication
        val openChatIntent = Intent(this, LockActivity::class.java).apply {
            putExtra("TARGET_ACTIVITY", "ChatActivity")
            putExtra(ChatActivity.EXTRA_CONTACT_ID, contactId)
            putExtra(ChatActivity.EXTRA_CONTACT_NAME, senderName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openChatPendingIntent = PendingIntent.getActivity(
            this,
            contactId.toInt(),
            openChatIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Create reply action intent (also via LockActivity)
        val replyIntent = Intent(this, LockActivity::class.java).apply {
            putExtra("TARGET_ACTIVITY", "ChatActivity")
            putExtra(ChatActivity.EXTRA_CONTACT_ID, contactId)
            putExtra(ChatActivity.EXTRA_CONTACT_NAME, senderName)
            putExtra("FOCUS_INPUT", true)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val replyPendingIntent = PendingIntent.getActivity(
            this,
            (contactId + 10000).toInt(),
            replyIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Truncate message preview if too long
        val messagePreview = if (messageText.length > 100) {
            messageText.take(100) + "..."
        } else {
            messageText
        }

        // Build notification
        val notification = NotificationCompat.Builder(this, AUTH_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(senderName)
            .setContentText(messagePreview)
            .setStyle(NotificationCompat.BigTextStyle().bigText(messageText))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(openChatPendingIntent)
            .addAction(R.drawable.ic_send, "Reply", replyPendingIntent)
            .build()

        // Show notification
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(contactId.toInt() + 20000, notification)

        Log.i(TAG, "Message notification shown for $senderName")
    }

    /**
     * Update app badge count with unread message count
     */
    private fun updateAppBadgeCount(database: com.securelegion.database.SecureLegionDatabase) {
        try {
            kotlinx.coroutines.runBlocking {
                val unreadCount = database.messageDao().getTotalUnreadCount()
                Log.d(TAG, "Updating app badge count: $unreadCount unread messages")

                // Update badge using ShortcutBadger or similar
                // For now, just log it - badge implementation varies by launcher
                if (unreadCount > 0) {
                    Log.i(TAG, "App badge should show: $unreadCount")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update badge count", e)
        }
    }

    /**
     * Send read receipt back to sender when message is received
     */
    private fun sendReadReceipt(contactId: Long, messageId: Long) {
        Thread {
            try {
                Log.d(TAG, "Sending read receipt for message $messageId to contact $contactId")

                // Get contact info
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)
                val contact = kotlinx.coroutines.runBlocking {
                    database.contactDao().getContactById(contactId)
                }

                if (contact == null) {
                    Log.e(TAG, "Contact not found for read receipt")
                    return@Thread
                }

                // Create read receipt payload
                val receiptPayload = """
                    {
                        "type": "read_receipt",
                        "messageId": $messageId,
                        "timestamp": ${System.currentTimeMillis()}
                    }
                """.trimIndent()

                // Encrypt receipt
                val recipientX25519PublicKey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)
                val encryptedReceipt = RustBridge.encryptMessage(receiptPayload, recipientX25519PublicKey)

                // Send via Tor to contact's .onion address
                // TODO: Implement Tor send message protocol
                // For now, just log it - this will be implemented when we add outgoing message support
                Log.i(TAG, "Read receipt prepared (${encryptedReceipt.size} bytes) - waiting for outgoing protocol implementation")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send read receipt", e)
            }
        }.start()
    }

    /**
     * Handle notification deletion - recreate it immediately
     * This is called when user swipes away the notification
     */
    private fun handleNotificationDeleted() {
        Log.w(TAG, "Notification deleted by user - recreating to keep service alive")

        // Determine current status
        val status = when {
            !torConnected -> "Connecting to Tor network..."
            !listenersReady -> "Starting listeners..."
            else -> "Connected to Tor"
        }

        // Recreate the notification and reattach to foreground
        val notification = createNotification(status)
        try {
            startForeground(NOTIFICATION_ID, notification)
            Log.i(TAG, "Notification recreated - service remains active")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to recreate notification", e)
        }
    }

    private fun stopTorService() {
        Log.i(TAG, "Stopping Tor service")

        isServiceRunning = false
        running = false
        listenersReady = false

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
            // Tor service channel (low priority - shows only shield icon in status bar)
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows shield icon when Tor is running. Only displays notification for connection issues."
                setShowBadge(false)
                // Disable sound and vibration for this persistent notification
                setSound(null, null)
                enableVibration(false)
            }

            // Message authentication channel (high priority)
            val authChannel = NotificationChannel(
                AUTH_CHANNEL_ID,
                AUTH_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Requires your approval to receive encrypted messages"
                setShowBadge(true)
                enableVibration(true)
                enableLights(true)
            }

            // Badge channel (for app icon badge with unread count)
            val badgeChannel = NotificationChannel(
                "badge_channel",
                "Message Badge",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows unread message count on app icon"
                setShowBadge(true)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(serviceChannel)
            notificationManager.createNotificationChannel(authChannel)
            notificationManager.createNotificationChannel(badgeChannel)
        }
    }

    private fun createNotification(status: String): Notification {
        // Launch via LockActivity to prevent showing app before authentication
        val intent = Intent(this, LockActivity::class.java).apply {
            putExtra("TARGET_ACTIVITY", "MainActivity")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Determine if this is a problem state that needs user attention
        val isProblemState = status.contains("Connecting", ignoreCase = true) ||
                             status.contains("Reconnecting", ignoreCase = true) ||
                             status.contains("Failed", ignoreCase = true) ||
                             status.contains("Error", ignoreCase = true) ||
                             status.contains("Retrying", ignoreCase = true)

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)

        // Only show notification text for problem states
        // Normal "Connected" state shows only the shield icon in status bar
        if (isProblemState) {
            builder.setContentTitle("Secure Legion")
                   .setContentText(status)
                   .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        } else {
            // Connected state - completely silent notification (just icon)
            builder.setContentTitle("")
                   .setContentText("")
                   .setPriority(NotificationCompat.PRIORITY_MIN)
                   .setShowWhen(false)  // Don't show timestamp
                   .setSilent(true)      // Silent notification
        }

        // Android 12+ (API 31+): Make notification truly non-dismissible
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        }

        return builder.build()
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

    // ==================== NETWORK MONITORING ====================

    private fun setupNetworkMonitoring() {
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val networkRequest = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Network available - checking if reconnection needed")
                hasNetworkConnection = true

                // If we were disconnected, attempt immediate reconnection
                if (!torConnected && !isReconnecting) {
                    Log.i(TAG, "Network restored - attempting immediate Tor reconnection")
                    reconnectHandler.post {
                        attemptReconnect()
                    }
                }
            }

            override fun onLost(network: Network) {
                Log.w(TAG, "Network lost")
                hasNetworkConnection = false
                torConnected = false
                updateNotification("Network disconnected")
            }
        }

        try {
            connectivityManager?.registerNetworkCallback(networkRequest, networkCallback!!)
            Log.d(TAG, "Network monitoring registered")

            // Check initial network state
            val activeNetwork = connectivityManager?.activeNetwork
            val capabilities = connectivityManager?.getNetworkCapabilities(activeNetwork)
            hasNetworkConnection = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            Log.d(TAG, "Initial network state: ${if (hasNetworkConnection) "connected" else "disconnected"}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register network callback", e)
        }
    }

    // ==================== HEALTH CHECK MONITORING ====================

    private fun checkTorHealth() {
        try {
            val isInitialized = torManager.isInitialized()

            if (!isInitialized && hasNetworkConnection && !isReconnecting) {
                Log.w(TAG, "Health check failed: Tor not initialized but network available - attempting reconnect")
                if (torConnected) {
                    torConnected = false
                    // Stop SOCKS proxy when Tor disconnects
                    if (RustBridge.isSocksProxyRunning()) {
                        Log.d(TAG, "Stopping SOCKS proxy due to Tor disconnection")
                        RustBridge.stopSocksProxy()
                    }
                }
                attemptReconnect()
            } else if (isInitialized) {
                if (!torConnected && !isReconnecting) {
                    Log.i(TAG, "Health check: Tor reconnected successfully")
                    torConnected = true
                    isReconnecting = false
                    reconnectAttempts = 0

                    // Reset SOCKS failure count on successful reconnect
                    socksFailureCount = 0

                    // Ensure SOCKS proxy is running for outgoing connections
                    ensureSocksProxyRunning()

                    // Start listener when health check detects reconnection
                    startIncomingListener()

                    // Send taps to all contacts to notify them we're online
                    sendTapsToAllContacts()

                    updateNotification("Connected to Tor")
                }

                // Test SOCKS connectivity even when connected
                testSocksConnectivity()
            } else if (!hasNetworkConnection) {
                Log.d(TAG, "Health check: No network connection available")
                torConnected = false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error during health check", e)
        }
    }

    /**
     * Test actual SOCKS connectivity (not just if proxy is running)
     */
    private fun testSocksConnectivity() {
        Thread {
            try {
                if (!RustBridge.isSocksProxyRunning()) {
                    Log.w(TAG, "SOCKS health test: Proxy not running")
                    handleSocksFailure()
                    return@Thread
                }

                // Test by attempting to connect to check.torproject.org
                val testResult = RustBridge.testSocksConnectivity()
                if (!testResult) {
                    Log.w(TAG, "SOCKS health test: Connectivity test failed")
                    handleSocksFailure()
                } else {
                    // Success - reset failure count
                    if (socksFailureCount > 0) {
                        Log.i(TAG, "SOCKS health test: Passed - resetting failure count")
                    }
                    socksFailureCount = 0
                    lastSocksFailureTime = 0L
                }
            } catch (e: Exception) {
                Log.e(TAG, "SOCKS health test failed with exception", e)
                handleSocksFailure()
            }
        }.start()
    }

    /**
     * Test SOCKS connectivity immediately after login - more aggressive than regular health check
     * Forces immediate Tor restart if connection is broken
     */
    private fun testSocksConnectivityAtStartup() {
        Thread {
            try {
                Log.i(TAG, "Testing SOCKS connectivity at startup...")

                // Check if proxy is running
                if (!RustBridge.isSocksProxyRunning()) {
                    Log.e(TAG, "Startup SOCKS test: Proxy not running - forcing restart")
                    updateNotification("Connection failed - Restarting...")
                    forceTorRestart()
                    return@Thread
                }

                // Test actual connectivity through the proxy
                val testResult = RustBridge.testSocksConnectivity()
                if (!testResult) {
                    Log.e(TAG, "Startup SOCKS test: Connection test failed - forcing restart")
                    updateNotification("Connection broken - Restarting...")
                    forceTorRestart()
                } else {
                    Log.i(TAG, "✓ Startup SOCKS test: Connection verified successfully")
                    socksFailureCount = 0
                    lastSocksFailureTime = 0L
                    updateNotification("Connected to Tor")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Startup SOCKS test failed with exception - forcing restart", e)
                updateNotification("Connection error - Restarting...")
                forceTorRestart()
            }
        }.start()
    }

    /**
     * Handle SOCKS failure - track failures and force Tor restart if threshold exceeded
     */
    private fun handleSocksFailure() {
        val currentTime = System.currentTimeMillis()

        // Reset counter if failures are outside the time window
        if (currentTime - lastSocksFailureTime > SOCKS_FAILURE_WINDOW) {
            socksFailureCount = 0
        }

        socksFailureCount++
        lastSocksFailureTime = currentTime

        Log.w(TAG, "SOCKS failure reported ($socksFailureCount/$SOCKS_FAILURE_THRESHOLD)")

        if (socksFailureCount >= SOCKS_FAILURE_THRESHOLD) {
            Log.e(TAG, "SOCKS failure threshold exceeded - forcing Tor restart")
            updateNotification("Restarting Tor (connectivity issues)...")
            forceTorRestart()
        } else {
            // Try restarting just the SOCKS proxy first
            Log.i(TAG, "Attempting SOCKS proxy restart (failure $socksFailureCount/$SOCKS_FAILURE_THRESHOLD)")
            Thread {
                try {
                    if (RustBridge.isSocksProxyRunning()) {
                        RustBridge.stopSocksProxy()
                        Thread.sleep(1000)
                    }
                    RustBridge.startSocksProxy()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to restart SOCKS proxy", e)
                }
            }.start()
        }
    }

    /**
     * Force a complete Tor restart when SOCKS proxy is broken
     */
    private fun forceTorRestart() {
        Log.i(TAG, "========== FORCING TOR RESTART ==========")

        Thread {
            try {
                // Stop everything
                isPingPollerRunning = false
                isTapPollerRunning = false

                // Stop SOCKS proxy
                if (RustBridge.isSocksProxyRunning()) {
                    Log.d(TAG, "Stopping SOCKS proxy...")
                    RustBridge.stopSocksProxy()
                }

                // Stop hidden service listener
                Log.d(TAG, "Stopping listeners...")
                RustBridge.stopListeners()

                // Mark as disconnected and not ready
                torConnected = false
                listenersReady = false

                // Wait a moment for cleanup
                Thread.sleep(2000)

                // Reset failure counters
                socksFailureCount = 0
                reconnectAttempts = 0
                isReconnecting = false

                // Reinitialize Tor from scratch
                Log.i(TAG, "Reinitializing Tor connection...")
                updateNotification("Reconnecting to Tor...")

                torManager.initializeAsync { success, onionAddress ->
                    if (success && onionAddress != null) {
                        Log.i(TAG, "✓ Tor restarted successfully: $onionAddress")
                        torConnected = true

                        // Restart everything
                        ensureSocksProxyRunning()
                        startIncomingListener()
                        sendTapsToAllContacts()

                        updateNotification("Connected to Tor")
                    } else {
                        Log.e(TAG, "✗ Tor restart failed - will retry via health check")
                        updateNotification("Connection failed - Retrying...")
                        scheduleReconnect()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error during forced Tor restart", e)
                updateNotification("Restart failed - Retrying...")
                scheduleReconnect()
            }
        }.start()
    }

    // ==================== RECONNECTION LOGIC ====================

    private fun scheduleReconnect() {
        if (isReconnecting) {
            Log.d(TAG, "Reconnection already scheduled, skipping")
            return
        }

        if (!hasNetworkConnection) {
            Log.d(TAG, "No network connection - waiting for network to become available")
            updateNotification("Waiting for network...")
            return
        }

        // Calculate exponential backoff delay
        val delay = calculateBackoffDelay()

        Log.i(TAG, "Scheduling reconnection attempt #${reconnectAttempts + 1} in ${delay/1000}s")
        updateNotification("Reconnecting in ${delay/1000}s... (attempt ${reconnectAttempts + 1})")

        isReconnecting = true

        reconnectHandler.postDelayed({
            attemptReconnect()
        }, delay)
    }

    private fun attemptReconnect() {
        val now = SystemClock.elapsedRealtime()

        // Prevent rapid retry attempts
        if (now - lastReconnectTime < MIN_RETRY_INTERVAL) {
            val timeSinceLastAttempt = (now - lastReconnectTime) / 1000
            Log.d(TAG, "Skipping reconnect attempt - too soon since last attempt (${timeSinceLastAttempt}s ago)")
            // Schedule retry after the minimum interval instead of giving up
            if (!isReconnecting) {
                isReconnecting = true
                val delayUntilNextAttempt = MIN_RETRY_INTERVAL - (now - lastReconnectTime)
                Log.d(TAG, "Scheduling reconnect in ${delayUntilNextAttempt / 1000}s")
                reconnectHandler.postDelayed({
                    attemptReconnect()
                }, delayUntilNextAttempt)
            }
            return
        }

        lastReconnectTime = now
        reconnectAttempts++

        Log.i(TAG, "Attempting Tor reconnection #$reconnectAttempts")
        updateNotification("Reconnecting to Tor... (attempt $reconnectAttempts)")

        Thread {
            try {
                torManager.initializeAsync { success, onionAddress ->
                    if (success && onionAddress != null) {
                        Log.i(TAG, "Tor reconnected successfully: $onionAddress")

                        // Reset state
                        isReconnecting = false
                        reconnectAttempts = 0
                        torConnected = true

                        // Ensure SOCKS proxy is running for outgoing connections
                        ensureSocksProxyRunning()

                        // Start listening for incoming Pings and Taps
                        startIncomingListener()

                        // PHASE 6: Send taps to all contacts to notify them we're online
                        sendTapsToAllContacts()

                        updateNotification("Connected to Tor")
                    } else {
                        Log.e(TAG, "Tor reconnection attempt #$reconnectAttempts failed")
                        isReconnecting = false
                        torConnected = false

                        // Schedule next retry
                        scheduleReconnect()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error during reconnection attempt #$reconnectAttempts", e)
                isReconnecting = false
                torConnected = false
                scheduleReconnect()
            }
        }.start()
    }

    private fun calculateBackoffDelay(): Long {
        // Exponential backoff: 5s, 10s, 20s, 40s, 60s (max)
        val delay = INITIAL_RETRY_DELAY * (1 shl (reconnectAttempts.coerceAtMost(4)))
        return min(delay, MAX_RETRY_DELAY)
    }

    // ==================== ALARMMANAGER RESTART ====================

    /**
     * Schedule recurring alarm to check if service is running
     * Provides redundancy beyond START_STICKY for aggressive battery optimization
     */
    private fun scheduleServiceRestart() {
        try {
            alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager

            val restartIntent = Intent(this, com.securelegion.receivers.TorServiceRestartReceiver::class.java)
            val pendingIntent = PendingIntent.getBroadcast(
                this,
                RESTART_REQUEST_CODE,
                restartIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val triggerTime = SystemClock.elapsedRealtime() + RESTART_CHECK_INTERVAL

            // Use setExactAndAllowWhileIdle for Android 6+ to work in Doze mode
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                alarmManager?.setExactAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerTime,
                    pendingIntent
                )
            } else {
                alarmManager?.setExact(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerTime,
                    pendingIntent
                )
            }

            Log.i(TAG, "Service restart alarm scheduled (${RESTART_CHECK_INTERVAL / 60000} minutes)")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to schedule service restart alarm", e)
        }
    }

    /**
     * Cancel the recurring restart alarm
     */
    private fun cancelServiceRestart() {
        try {
            alarmManager?.let {
                val restartIntent = Intent(this, com.securelegion.receivers.TorServiceRestartReceiver::class.java)
                val pendingIntent = PendingIntent.getBroadcast(
                    this,
                    RESTART_REQUEST_CODE,
                    restartIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                it.cancel(pendingIntent)
                Log.i(TAG, "Service restart alarm cancelled")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to cancel service restart alarm", e)
        }
    }

    // ==================== LIFECYCLE ====================

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "TorService destroyed")

        running = false
        torConnected = false
        listenersReady = false
        isServiceRunning = false

        // Cancel AlarmManager restart checks
        cancelServiceRestart()

        // Clean up handlers
        reconnectHandler.removeCallbacksAndMessages(null)

        // Unregister network callback
        try {
            networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Error unregistering network callback", e)
        }

        // Release wake lock
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
            }
        }
    }

    /**
     * Ensure SOCKS proxy is running for outgoing Tor connections
     * Checks if proxy is running and starts it if not
     * ALWAYS runs in background thread to avoid blocking the caller
     */
    private fun ensureSocksProxyRunning() {
        Thread {
            try {
                if (!RustBridge.isSocksProxyRunning()) {
                    Log.i(TAG, "SOCKS proxy not running, starting...")
                    val started = RustBridge.startSocksProxy()
                    if (started) {
                        Log.i(TAG, "✓ SOCKS proxy started successfully on 127.0.0.1:9050")
                    } else {
                        Log.e(TAG, "✗ Failed to start SOCKS proxy")
                    }
                } else {
                    Log.d(TAG, "SOCKS proxy already running")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking/starting SOCKS proxy", e)
            }
        }.start()
    }

    /**
     * Generate deterministic message ID from sender + content hash + timestamp
     * This enables deduplication of identical messages received within the same time window
     */
    private fun generateMessageId(senderId: String, content: String, timestamp: Long): String {
        val data = "$senderId:$content:$timestamp".toByteArray()
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data)
        return "blob_" + android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP).take(28)
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.d(TAG, "onTaskRemoved - App swiped away, keeping service running")
        // Service continues running even when app is swiped away
        // This is intentional for Ping-Pong protocol
    }
}
