package com.securelegion.services

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
import com.securelegion.crypto.KeyChainManager
import com.securelegion.database.entities.sendChainKeyBytes
import com.securelegion.database.entities.receiveChainKeyBytes
import com.securelegion.database.entities.rootKeyBytes
import com.securelegion.utils.ThemedToast
import com.securelegion.workers.ImmediateRetryWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.withContext
import java.io.File
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
    private var isMessagePollerRunning = false
    private var isVoicePollerRunning = false
    private var isFriendRequestPollerRunning = false
    private var isPongPollerRunning = false
    private var isSessionCleanupRunning = false
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
    private var downloadFailureCount = 0
    private var downloadFailureWindowStart = 0L
    private val SOCKS_FAILURE_THRESHOLD = 3  // Restart Tor after 3 consecutive failures
    private val SOCKS_FAILURE_WINDOW = 60000L  // 60 second window

    // Reconnection constants
    private val INITIAL_RETRY_DELAY = 5000L        // 5 seconds
    private val MAX_RETRY_DELAY = 60000L           // 60 seconds
    private val MIN_RETRY_INTERVAL = 3000L         // 3 seconds minimum between retries

    // AlarmManager constants
    private val RESTART_CHECK_INTERVAL = 15 * 60 * 1000L  // 15 minutes

    // Single-threaded dispatcher for protocol state mutations (ACKs, DB updates, ratchet)
    // Ensures all protocol operations are serialized to prevent race conditions
    private val protocolDispatcher = kotlinx.coroutines.newSingleThreadContext("Protocol-Executor")

    // Service-scoped coroutine scope for all protocol operations
    // Ensures proper cleanup when service is destroyed
    private val serviceScope = CoroutineScope(SupervisorJob() + protocolDispatcher)

    // Bandwidth monitoring
    private var lastRxBytes = 0L
    private var lastTxBytes = 0L
    private var lastBandwidthUpdate = 0L
    private var currentDownloadSpeed = 0L  // bytes per second
    private var currentUploadSpeed = 0L    // bytes per second
    private val bandwidthHandler = Handler(Looper.getMainLooper())
    private var bandwidthUpdateRunnable: Runnable? = null
    private var torConnected = false
    private var listenersReady = false
    private var isAppInForeground = false
    private val BANDWIDTH_UPDATE_FAST = 5000L      // 5 seconds when app open (matches VPN update interval)
    private val BANDWIDTH_UPDATE_SLOW = 10000L     // 10 seconds when app closed (saves battery)

    // VPN bandwidth (received from TorVpnService)
    private var vpnBytesReceived = 0L
    private var vpnBytesSent = 0L
    private var vpnActive = false
    private var vpnBroadcastReceiver: android.content.BroadcastReceiver? = null

    companion object {
        private const val TAG = "TorService"
        private const val NOTIFICATION_ID = 1001
        private const val RESTART_REQUEST_CODE = 1001
        private const val CHANNEL_ID = "tor_service_channel"
        private const val CHANNEL_NAME = "Tor Hidden Service"
        private const val AUTH_CHANNEL_ID = "message_auth_channel_v2"  // Changed to v2 to recreate with sound
        private const val AUTH_CHANNEL_NAME = "Friend Requests & Messages"

        const val ACTION_START_TOR = "com.securelegion.action.START_TOR"
        const val ACTION_STOP_TOR = "com.securelegion.action.STOP_TOR"
        const val ACTION_NOTIFICATION_DELETED = "com.securelegion.action.NOTIFICATION_DELETED"
        const val ACTION_ACCEPT_MESSAGE = "com.securelegion.action.ACCEPT_MESSAGE"
        const val ACTION_DECLINE_MESSAGE = "com.securelegion.action.DECLINE_MESSAGE"
        const val ACTION_VPN_BANDWIDTH_UPDATE = "com.securelegion.action.VPN_BANDWIDTH_UPDATE"
        const val EXTRA_PING_ID = "ping_id"
        const val EXTRA_CONNECTION_ID = "connection_id"
        const val EXTRA_VPN_RX_BYTES = "vpn_rx_bytes"
        const val EXTRA_VPN_TX_BYTES = "vpn_tx_bytes"
        const val EXTRA_VPN_ACTIVE = "vpn_active"
        const val EXTRA_SENDER_NAME = "sender_name"

        // Track service state
        @Volatile
        private var running = false

        @Volatile
        private var torConnected = false

        @Volatile
        private var listenersReady = false

        @Volatile
        private var instance: TorService? = null

        fun isRunning(): Boolean = running

        fun isTorConnected(): Boolean = torConnected

        /**
         * Notify service when app goes to foreground/background
         * Adjusts bandwidth monitoring frequency (fast when open, slow when closed)
         */
        fun setForegroundState(inForeground: Boolean) {
            instance?.setAppInForeground(inForeground)
        }

        /**
         * Check if all listeners and pollers are ready for messaging
         * This means:
         * - Hidden service listener started (port 8080)
         * - Tap listener started (port 9151)
         * - ACK listener started (port 9153)
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

        // Set instance for static access
        instance = this

        // Initialize TorManager
        torManager = TorManager.getInstance(this)

        // Create notification channel
        createNotificationChannel()

        // Setup network monitoring
        setupNetworkMonitoring()

        // Register VPN bandwidth broadcast receiver
        setupVpnBroadcastReceiver()

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
                // Check if this is a restart due to bridge configuration change
                val prefs = getSharedPreferences("tor_settings", MODE_PRIVATE)
                val bridgeConfigChanged = prefs.getBoolean("bridge_config_changed", false)

                if (bridgeConfigChanged) {
                    Log.i(TAG, "Bridge configuration changed - forcing Tor re-initialization")
                    prefs.edit().putBoolean("bridge_config_changed", false).apply()
                    // Force re-initialization even if Tor was previously initialized
                }

                if (!torManager.isInitialized() || bridgeConfigChanged) {
                    Log.d(TAG, "Tor not initialized (or bridge config changed), initializing now...")
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
        Log.i(TAG, "===== startIncomingListener() CALLED =====")
        try {
            // PHASE 1: Start ACK listener FIRST (port 9153)
            // CRITICAL: Must ALWAYS start ACK listener, even if main listener is already running
            // This initializes ACK_TX channel so any ACKs arriving on port 8080 can be routed
            Log.d(TAG, "Starting ACK listener on port 9153...")
            val ackSuccess = RustBridge.startAckListener(9153)
            if (ackSuccess) {
                Log.i(TAG, "ACK listener started successfully - ACK_TX channel initialized")
            } else {
                Log.w(TAG, "ACK listener already running")
            }

            // Start polling for incoming ACKs
            startAckPoller()

            // Check if listener is already running - if so, just start pollers
            if (isListenerRunning) {
                Log.d(TAG, "Listener already running, skipping restart")
                startPingPoller()
                startMessagePoller()
                startVoicePoller()
                startTapPoller()
                startSessionCleanup()

                // CRITICAL: Always initialize voice service when listener is running
                // Voice streaming server needs to be started on every app launch
                Log.i(TAG, "Listener already running - initializing voice service...")
                startVoiceService()
                return
            }

            // PHASE 2: Now safe to start main listener on port 8080
            Log.d(TAG, "Starting hidden service listener on port 8080...")
            val success = RustBridge.startHiddenServiceListener(8080)
            if (success) {
                Log.i(TAG, "Hidden service listener started successfully")
                isListenerRunning = true
            } else {
                Log.w(TAG, "Listener already running (started by TorManager)")
                isListenerRunning = true
            }

            // Start polling for incoming Pings, MESSAGEs, and VOICE (whether we started the listener or it's already running)
            startPingPoller()
            startMessagePoller()
            startVoicePoller()

            // PHASE 3: Start tap listener on port 9151
            Log.d(TAG, "Starting tap listener on port 9151...")
            val tapSuccess = RustBridge.startTapListener(9151)
            if (tapSuccess) {
                Log.i(TAG, "Tap listener started successfully")
            } else {
                Log.w(TAG, "Tap listener already running")
            }

            // Start polling for incoming taps
            startTapPoller()

            // PHASE 4: Start friend request listener (separate channel to avoid interference)
            Log.d(TAG, "Starting friend request listener...")
            val friendRequestSuccess = RustBridge.startFriendRequestListener()
            if (friendRequestSuccess) {
                Log.i(TAG, "Friend request listener started successfully")
            } else {
                Log.w(TAG, "Friend request listener already running")
            }

            // Start polling for incoming friend requests
            startFriendRequestPoller()

            // PONGs arrive at main listener (port 8080) and are routed by message type
            // Start polling for incoming pongs from main listener queue
            startPongPoller()

            // Start periodic session cleanup (5-minute intervals)
            startSessionCleanup()

            // Ensure SOCKS proxy is running for outgoing connections
            ensureSocksProxyRunning()

            // Verify SOCKS proxy is actually running
            if (RustBridge.isSocksProxyRunning()) {
                // All listeners, pollers, and SOCKS proxy ready - mark as ready for messaging
                listenersReady = true
                Log.i(TAG, "✓ All listeners, pollers, and SOCKS proxy (9050) ready - messaging enabled")

                // Start bandwidth monitoring now that Tor is fully operational
                startBandwidthMonitoring()

                // Initialize voice service
                startVoiceService()
            } else {
                Log.w(TAG, "SOCKS proxy not running - messaging may not work for outgoing messages")
                listenersReady = true // Still mark as ready since incoming works

                // Start bandwidth monitoring anyway
                startBandwidthMonitoring()

                // Initialize voice service anyway
                startVoiceService()
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
                        // CRITICAL FIX: Launch handleIncomingPing in coroutine to avoid blocking the poller thread
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            try {
                                handleIncomingPing(pingBytes)
                            } catch (e: Exception) {
                                Log.e(TAG, "Error in handleIncomingPing coroutine", e)
                            }
                        }
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
     * Start MESSAGE poller for direct routing of TEXT/VOICE/IMAGE/PAYMENT messages
     * Polls MESSAGE channel instead of trying trial decryption on PING channel
     */
    private fun startMessagePoller() {
        if (isMessagePollerRunning) {
            Log.d(TAG, "MESSAGE poller already running, skipping")
            return
        }

        isMessagePollerRunning = true

        // Poll for incoming MESSAGES in background thread
        Thread {
            Log.d(TAG, "MESSAGE poller thread started")
            var pollCount = 0
            while (isServiceRunning) {
                try {
                    val messageBytes = RustBridge.pollIncomingMessage()
                    if (messageBytes != null) {
                        Log.i(TAG, "Received incoming MESSAGE: ${messageBytes.size} bytes")
                        handleIncomingMessage(messageBytes)
                    } else {
                        // Log every 10 seconds to confirm poller is running
                        pollCount++
                        if (pollCount % 10 == 0) {
                            Log.d(TAG, "MESSAGE poller alive (poll #$pollCount, no message)")
                        }
                    }

                    // Poll every second (same as PING)
                    Thread.sleep(1000)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "MESSAGE poller interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling for messages", e)
                }
            }
            Log.d(TAG, "MESSAGE poller thread stopped")
        }.start()
    }

    /**
     * Start VOICE poller for call signaling (CALL_OFFER/ANSWER/REJECT/END/BUSY)
     * Completely separate from MESSAGE channel to allow simultaneous text messaging during voice calls
     */
    private fun startVoicePoller() {
        if (isVoicePollerRunning) {
            Log.d(TAG, "VOICE poller already running, skipping")
            return
        }

        isVoicePollerRunning = true

        // Poll for incoming VOICE call signaling in background thread
        Thread {
            Log.d(TAG, "VOICE poller thread started")
            var pollCount = 0
            while (isServiceRunning) {
                try {
                    val voiceBytes = RustBridge.pollVoiceMessage()
                    if (voiceBytes != null) {
                        Log.i(TAG, "Received incoming VOICE call signaling: ${voiceBytes.size} bytes")
                        handleIncomingVoiceMessage(voiceBytes)
                    } else {
                        // Log every 10 seconds to confirm poller is running
                        pollCount++
                        if (pollCount % 10 == 0) {
                            Log.d(TAG, "VOICE poller alive (poll #$pollCount, no call signaling)")
                        }
                    }

                    // Poll every second (same as MESSAGE)
                    Thread.sleep(1000)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "VOICE poller interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling for voice call signaling", e)
                }
            }
            Log.d(TAG, "VOICE poller thread stopped")
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
     * PHASE 7.5: Start friend request poller (separate from TAP)
     * Polls for incoming friend request wire protocol messages (0x07 FRIEND_REQUEST, 0x08 FRIEND_REQUEST_ACCEPTED)
     */
    private fun startFriendRequestPoller() {
        if (isFriendRequestPollerRunning) {
            Log.d(TAG, "Friend request poller already running, skipping")
            return
        }

        isFriendRequestPollerRunning = true

        // Poll for incoming friend requests in background thread
        Thread {
            Log.d(TAG, "Friend request poller thread started")
            while (isServiceRunning) {
                try {
                    val friendRequestBytes = RustBridge.pollFriendRequest()
                    if (friendRequestBytes != null) {
                        Log.i(TAG, "Received incoming friend request: ${friendRequestBytes.size} bytes")
                        handleIncomingFriendRequest(friendRequestBytes)
                    }

                    // Poll every 2 seconds (friend requests are infrequent)
                    Thread.sleep(2000)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "Friend request poller interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error polling for friend requests", e)
                }
            }
            Log.d(TAG, "Friend request poller thread stopped")
        }.start()
    }

    /**
     * PHASE 8: Start pong poller
     * Polls for incoming PONGs from contacts who are downloading messages
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
            var pollCount = 0
            while (isServiceRunning) {
                try {
                    val pongBytes = RustBridge.pollIncomingPong()
                    if (pongBytes != null) {
                        Log.i(TAG, "Received incoming Pong: ${pongBytes.size} bytes")
                        handleIncomingPong(pongBytes)
                    } else {
                        // Log every 30 seconds to confirm poller is running
                        pollCount++
                        if (pollCount % 30 == 0) {
                            Log.d(TAG, "Pong poller alive (poll #$pollCount, no pong)")
                        }
                    }

                    // Poll every second (PONGs arrive when user taps Download)
                    Thread.sleep(1000)
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

            // Send TAP_ACK to confirm we received the TAP (with retry logic)
            serviceScope.launch {
                sendAckWithRetry(
                    connectionId = null,  // No existing connection from TAP
                    itemId = System.currentTimeMillis().toString(),
                    ackType = "TAP_ACK",
                    contactId = contact.id,
                    maxRetries = 3,
                    initialDelayMs = 1000L
                )
            }

            // ==== BIDIRECTIONAL HANDLING ====

            // CHECK 1: Do we have pending Pings FROM them? (Check ping_inbox database)
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val pendingPingsCount = database.pingInboxDao().countPendingByContact(contact.id)

                    if (pendingPingsCount > 0) {
                        Log.i(TAG, "Found $pendingPingsCount pending Ping(s) from ${contact.displayName} in inbox")

                        // Get all pending pings from this contact
                        val pendingPings = database.pingInboxDao().getPendingByContact(contact.id)

                        // Send PING_ACK for each ping we haven't acknowledged yet
                        for (ping in pendingPings) {
                            if (ping.pingAckedAt == null) {
                                try {
                                    // Send PING_ACK to acknowledge we saw the ping
                                    sendAckWithRetry(
                                        connectionId = null,
                                        itemId = ping.pingId,
                                        ackType = "PING_ACK",
                                        contactId = contact.id,
                                        maxRetries = 3,
                                        initialDelayMs = 1000L
                                    )

                                    // Update ping_inbox to mark PING_ACK sent
                                    database.pingInboxDao().updatePingAckTime(ping.pingId, System.currentTimeMillis())
                                    Log.i(TAG, "✓ Sent PING_ACK for incoming ping ${ping.pingId.take(8)}... from ${contact.displayName}")
                                } catch (e: Exception) {
                                    Log.e(TAG, "Failed to send PING_ACK for ${ping.pingId}", e)
                                }
                            } else {
                                Log.d(TAG, "PING_ACK already sent for ${ping.pingId.take(8)}... at ${ping.pingAckedAt}")
                            }
                        }

                        // Note: We DON'T auto-download - user manually clicks download button
                        // This is by design for privacy/security
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error checking ping_inbox for ${contact.displayName}", e)
                }
            }

            // CHECK 2: Do we have pending messages TO them?
            // TAP = "I'm online" heartbeat, so check ALL message phases and take appropriate action
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    // Query ALL pending/failed messages (not just awaiting pong)
                    val pendingMessages = database.messageDao().getPendingMessages()
                        .filter { it.contactId == contact.id }

                    // Also include messages awaiting pong
                    val awaitingPong = database.messageDao().getMessagesAwaitingPong()
                        .filter { it.contactId == contact.id }

                    val allMessages = (pendingMessages + awaitingPong).distinctBy { it.id }

                    if (allMessages.isEmpty()) {
                        Log.d(TAG, "No pending messages to ${contact.displayName}")
                        return@launch
                    }

                    Log.i(TAG, "Found ${allMessages.size} pending message(s) to ${contact.displayName} (${pendingMessages.size} unsent, ${awaitingPong.size} awaiting pong) - checking phases")

                    val messageService = com.securelegion.services.MessageService(this@TorService)

                    for (message in allMessages) {
                        // ============ ACK-BASED FLOW CONTROL FOR TAP ============
                        // Contact is online - check what phase each message is in and take action

                        // PHASE 4: MESSAGE_ACK received → Skip (already delivered)
                        if (message.messageDelivered) {
                            Log.d(TAG, "✓ ${message.messageId}: MESSAGE_ACK received, skip")
                            continue
                        }

                        // PHASE 3: PONG_ACK received → Receiver is downloading, just wait
                        if (message.pongDelivered) {
                            Log.d(TAG, "✓ ${message.messageId}: PONG_ACK received, receiver downloading, skip")
                            continue
                        }

                        // PHASE 2: PING_ACK received → They got notification, check for Pong
                        if (message.pingDelivered) {
                            Log.i(TAG, "✓ ${message.messageId}: PING_ACK received - checking for Pong (contact online)")
                            // Poll for Pong - contact might have sent it
                            val pongResult = messageService.pollForPongsAndSendMessages()
                            if (pongResult.isSuccess) {
                                val sentCount = pongResult.getOrNull() ?: 0
                                if (sentCount > 0) {
                                    Log.i(TAG, "✓ Pong received and message blob sent!")
                                }
                            }
                            continue
                        }

                        // PHASE 1: No PING_ACK → Check for Pong first, then retry Ping if needed
                        Log.i(TAG, "→ ${message.messageId}: No PING_ACK yet - checking for Pong first (PING_ACK may have been lost)")

                        // CRITICAL: Poll for Pong even without PING_ACK
                        // Reason: PING_ACK might have been lost in transit, but receiver may have sent PONG
                        // This prevents download stalls where receiver is waiting for blob but sender never checked for Pong
                        val pongResult = messageService.pollForPongsAndSendMessages()
                        if (pongResult.isSuccess) {
                            val sentCount = pongResult.getOrNull() ?: 0
                            if (sentCount > 0) {
                                Log.i(TAG, "✓ Pong found and message blob sent (PING_ACK was lost but Pong arrived)!")
                                continue  // Skip Ping retry - Pong was found
                            }
                        }

                        // No Pong found - retry Ping since contact is online
                        Log.i(TAG, "→ ${message.messageId}: No Pong found - retrying Ping (contact online via TAP)")
                        try {
                            val result = messageService.sendPingForMessage(message)
                            if (result.isSuccess) {
                                // Update retry counter
                                val updatedMessage = message.copy(
                                    retryCount = message.retryCount + 1,
                                    lastRetryTimestamp = System.currentTimeMillis()
                                )
                                database.messageDao().updateMessage(updatedMessage)
                                Log.i(TAG, "✓ Retried Ping for ${message.messageId} after TAP")
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to retry Ping for ${message.messageId}", e)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error checking pending messages during TAP", e)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling tap", e)
        }
    }

    /**
     * Handle incoming friend request (Phase 1 or Phase 2)
     * Phase 1 (0x07): PIN-encrypted minimal info
     * Phase 2 (0x08): X25519-encrypted full ContactCard
     */
    private fun handleIncomingFriendRequest(encryptedBytes: ByteArray) {
        try {
            Log.i(TAG, "Handling incoming friend request (${encryptedBytes.size} bytes)")

            // Wire format: [type byte][encrypted payload]
            // Type byte was prepended by Rust routing layer
            if (encryptedBytes.isEmpty()) {
                Log.e(TAG, "Empty friend request data")
                return
            }

            val typeByte = encryptedBytes[0]
            val encryptedPayload = encryptedBytes.copyOfRange(1, encryptedBytes.size)

            Log.d(TAG, "Friend request type: 0x${String.format("%02X", typeByte)}")
            Log.d(TAG, "Encrypted payload: ${encryptedPayload.size} bytes")

            when (typeByte.toInt()) {
                0x07 -> handlePhase1FriendRequest(encryptedPayload)
                0x08 -> {
                    // 0x08 is used for both Phase 2 and Phase 3
                    // Determine which by checking pending request direction
                    val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
                    val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

                    var hasOutgoingPhase1 = false
                    var hasOutgoingPhase2 = false

                    for (requestJson in pendingRequestsSet) {
                        try {
                            val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                            if (request.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING) {
                                val json = org.json.JSONObject(request.contactCardJson ?: "{}")
                                // Phase 2 saved state has "hybrid_shared_secret", Phase 1 doesn't
                                if (json.has("hybrid_shared_secret")) {
                                    hasOutgoingPhase2 = true
                                } else if (json.has("username")) {
                                    hasOutgoingPhase1 = true
                                }
                            }
                        } catch (e: Exception) {
                            // Ignore parse errors
                        }
                    }

                    when {
                        hasOutgoingPhase1 -> handlePhase2FriendRequest(encryptedPayload) // We sent Phase 1, this is Phase 2
                        hasOutgoingPhase2 -> handlePhase3Acknowledgment(encryptedPayload) // We sent Phase 2, this is Phase 3
                        else -> Log.e(TAG, "Received 0x08 but no matching outgoing request found")
                    }
                }
                else -> {
                    Log.e(TAG, "Unknown friend request type: 0x${String.format("%02X", typeByte)}")
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling friend request", e)
        }
    }

    /**
     * Handle Phase 1 friend request (PIN-encrypted)
     * Payload: {"username": "...", "friendRequestOnion": "...", "x25519PublicKey": "..."}
     */
    private fun handlePhase1FriendRequest(encryptedPayload: ByteArray) {
        try {
            Log.i(TAG, "Processing Phase 1 friend request (PIN-encrypted)")

            // Retrieve user's own PIN from secure storage
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val myPin = keyManager.getContactPin()

            if (myPin == null) {
                Log.e(TAG, "User's contact PIN not found in storage")
                Log.e(TAG, "User must generate their contact card first before receiving friend requests")
                return
            }

            Log.d(TAG, "Retrieved user's PIN from secure storage")

            val cardManager = ContactCardManager(this)
            val decryptedJson = try {
                cardManager.decryptWithPin(encryptedPayload, myPin)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt Phase 1 friend request", e)
                Log.e(TAG, "Sender may have used wrong PIN or data is corrupted")
                return
            }

            Log.i(TAG, "Phase 1 decrypted successfully: $decryptedJson")

            // Parse the JSON to extract friend request data
            val json = org.json.JSONObject(decryptedJson)
            val username = json.getString("username")
            val friendRequestOnion = json.getString("friend_request_onion")
            val x25519PublicKey = json.getString("x25519_public_key")

            Log.i(TAG, "Phase 1 Friend Request from: $username")
            Log.i(TAG, "Friend Request .onion: $friendRequestOnion")
            Log.i(TAG, "X25519 Public Key: $x25519PublicKey")

            // Store as pending friend request
            val pendingRequest = com.securelegion.models.PendingFriendRequest(
                displayName = username,
                ipfsCid = friendRequestOnion,  // Store the .onion address in ipfsCid field
                direction = com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING,
                status = com.securelegion.models.PendingFriendRequest.STATUS_PENDING,
                timestamp = System.currentTimeMillis(),
                contactCardJson = decryptedJson  // Store Phase 1 data for later use
            )

            savePendingFriendRequest(pendingRequest)

            // Show system notification
            showFriendRequestNotification(username)

            // Send broadcast to update UI badge (explicit broadcast for Android 8.0+)
            val broadcastIntent = android.content.Intent("com.securelegion.FRIEND_REQUEST_RECEIVED")
            broadcastIntent.setPackage(packageName)
            sendBroadcast(broadcastIntent)

            Log.i(TAG, "✓ Phase 1 friend request saved, notification shown, and broadcast sent")

        } catch (e: Exception) {
            Log.e(TAG, "Error processing Phase 1 friend request", e)
        }
    }

    /**
     * Handle Phase 2 friend request (X25519-encrypted)
     * Payload: Full ContactCard JSON encrypted with X25519
     * This is received when someone accepts OUR outgoing friend request
     */
    private fun handlePhase2FriendRequest(encryptedPayload: ByteArray) {
        try {
            Log.i(TAG, "Processing Phase 2 friend request (X25519-encrypted)")

            // Find matching outgoing Phase 1 request to get sender's X25519 public key
            val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            var senderX25519PublicKey: ByteArray? = null
            var matchingRequest: com.securelegion.models.PendingFriendRequest? = null

            for (requestJson in pendingRequestsSet) {
                try {
                    val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    // Look for outgoing requests with Phase 1 data
                    if (request.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING &&
                        request.contactCardJson != null) {

                        val phase1Json = org.json.JSONObject(request.contactCardJson)
                        val x25519Base64 = phase1Json.optString("x25519_public_key", null)

                        if (x25519Base64 != null) {
                            senderX25519PublicKey = android.util.Base64.decode(x25519Base64, android.util.Base64.NO_WRAP)
                            matchingRequest = request
                            Log.d(TAG, "Found matching outgoing request to: ${request.displayName}")
                            break
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse pending request", e)
                }
            }

            if (senderX25519PublicKey == null || matchingRequest == null) {
                Log.e(TAG, "No matching outgoing friend request found for Phase 2")
                return
            }

            // Decrypt with sender's X25519 public key
            val decryptedJson = RustBridge.decryptMessage(
                encryptedPayload,
                senderX25519PublicKey,
                ByteArray(32) // privateKey parameter is deprecated/unused
            )

            if (decryptedJson == null) {
                Log.e(TAG, "Failed to decrypt Phase 2 ContactCard")
                return
            }

            Log.i(TAG, "Phase 2 decrypted successfully")

            // Try to parse as NEW Phase 2 format with signature (v2.1+)
            var contactCard: com.securelegion.models.ContactCard? = null
            var kyberCiphertext: ByteArray? = null

            try {
                val phase2Obj = org.json.JSONObject(decryptedJson)
                if (phase2Obj.has("phase") && phase2Obj.getInt("phase") == 2) {
                    // NEW Phase 2 format with signature
                    Log.d(TAG, "Parsing NEW Phase 2 format with signature...")

                    // Verify Ed25519 signature
                    if (phase2Obj.has("signature") && phase2Obj.has("ed25519_public_key")) {
                        val signature = android.util.Base64.decode(phase2Obj.getString("signature"), android.util.Base64.NO_WRAP)
                        val senderEd25519PublicKey = android.util.Base64.decode(phase2Obj.getString("ed25519_public_key"), android.util.Base64.NO_WRAP)

                        // Reconstruct unsigned JSON
                        val unsignedJson = org.json.JSONObject().apply {
                            put("contact_card", phase2Obj.getJSONObject("contact_card"))
                            if (phase2Obj.has("kyber_ciphertext")) {
                                put("kyber_ciphertext", phase2Obj.getString("kyber_ciphertext"))
                            }
                            put("phase", 2)
                        }.toString()

                        val signatureValid = RustBridge.verifySignature(
                            unsignedJson.toByteArray(Charsets.UTF_8),
                            signature,
                            senderEd25519PublicKey
                        )

                        if (!signatureValid) {
                            Log.e(TAG, "❌ Phase 2 signature verification FAILED - rejecting (possible MitM)")
                            return
                        }
                        Log.i(TAG, "✓ Phase 2 signature verified (Ed25519)")
                    }

                    // Extract contact card and kyber ciphertext
                    val contactCardJson = phase2Obj.getJSONObject("contact_card").toString()
                    contactCard = com.securelegion.models.ContactCard.fromJson(contactCardJson)

                    if (phase2Obj.has("kyber_ciphertext")) {
                        val ciphertextBase64 = phase2Obj.getString("kyber_ciphertext")
                        kyberCiphertext = android.util.Base64.decode(ciphertextBase64, android.util.Base64.NO_WRAP)
                        Log.i(TAG, "✓ Phase 2 with Kyber ciphertext (${kyberCiphertext.size} bytes)")
                    }
                } else {
                    // OLD Phase 2 format (plain ContactCard)
                    contactCard = com.securelegion.models.ContactCard.fromJson(decryptedJson)
                }
            } catch (e: org.json.JSONException) {
                // Fallback: Try parsing as plain ContactCard (old format)
                Log.d(TAG, "Not Phase 2 wrapper, trying plain ContactCard format...")
                contactCard = com.securelegion.models.ContactCard.fromJson(decryptedJson)
            }

            if (contactCard == null) {
                Log.e(TAG, "Failed to parse ContactCard from Phase 2")
                return
            }

            Log.i(TAG, "✓ Friend request accepted by: ${contactCard.displayName}")

            // Add to contacts database (WITHOUT key chain - we'll initialize it below)
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            val contact = com.securelegion.database.entities.Contact(
                displayName = contactCard.displayName,
                solanaAddress = contactCard.solanaAddress,
                publicKeyBase64 = android.util.Base64.encodeToString(contactCard.solanaPublicKey, android.util.Base64.NO_WRAP),
                x25519PublicKeyBase64 = android.util.Base64.encodeToString(contactCard.x25519PublicKey, android.util.Base64.NO_WRAP),
                kyberPublicKeyBase64 = android.util.Base64.encodeToString(contactCard.kyberPublicKey, android.util.Base64.NO_WRAP),
                friendRequestOnion = contactCard.friendRequestOnion,
                messagingOnion = contactCard.messagingOnion,
                voiceOnion = contactCard.voiceOnion,
                contactPin = contactCard.contactPin,
                ipfsCid = contactCard.ipfsCid,
                addedTimestamp = System.currentTimeMillis(),
                friendshipStatus = com.securelegion.database.entities.Contact.FRIENDSHIP_CONFIRMED
            )

            val contactId = kotlinx.coroutines.runBlocking {
                database.contactDao().insertContact(contact)
            }

            Log.i(TAG, "Contact added to database: ${contactCard.displayName} (ID: $contactId)")

            // Initialize key chain with kyber ciphertext if present
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    val ourMessagingOnion = torManager.getOnionAddress()
                    val theirMessagingOnion = contactCard.messagingOnion
                    if (ourMessagingOnion.isNullOrEmpty() || theirMessagingOnion.isNullOrEmpty()) {
                        Log.e(TAG, "Cannot initialize key chain: missing onion address")
                    } else if (kyberCiphertext != null) {
                        // Device A path: Decapsulate the ciphertext from Phase 2
                        com.securelegion.crypto.KeyChainManager.initializeKeyChain(
                            context = this@TorService,
                            contactId = contactId,
                            theirX25519PublicKey = contactCard.x25519PublicKey,
                            theirKyberPublicKey = contactCard.kyberPublicKey,
                            ourMessagingOnion = ourMessagingOnion,
                            theirMessagingOnion = theirMessagingOnion,
                            kyberCiphertext = kyberCiphertext
                        )
                        Log.i(TAG, "✓ Key chain initialized for ${contactCard.displayName} (quantum - decapsulated)")
                    } else {
                        // Legacy path without Kyber
                        Log.w(TAG, "⚠️  No Kyber ciphertext - key chain will be initialized without quantum parameters")
                        com.securelegion.crypto.KeyChainManager.initializeKeyChain(
                            context = this@TorService,
                            contactId = contactId,
                            theirX25519PublicKey = contactCard.x25519PublicKey,
                            theirKyberPublicKey = contactCard.kyberPublicKey,
                            ourMessagingOnion = ourMessagingOnion,
                            theirMessagingOnion = theirMessagingOnion
                        )
                        Log.i(TAG, "✓ Key chain initialized for ${contactCard.displayName} (legacy)")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to initialize key chain for ${contactCard.displayName}", e)
                }
            }

            // Remove pending outgoing request
            removePendingRequest(matchingRequest)

            // Show "Friend request accepted" notification
            showFriendRequestAcceptedNotification(contactCard.displayName)

            Log.i(TAG, "✓ Phase 2 complete - ${contactCard.displayName} added to contacts")

            // Send Phase 3 ACK back to sender's friend-request .onion
            sendPhase3Acknowledgment(contactCard)

        } catch (e: Exception) {
            Log.e(TAG, "Error processing Phase 2 friend request", e)
        }
    }

    /**
     * Send Phase 3 ACK to confirm friend request is complete
     */
    private fun sendPhase3Acknowledgment(contactCard: com.securelegion.models.ContactCard) {
        try {
            Log.i(TAG, "Sending Phase 3 ACK to ${contactCard.displayName}")

            // Build ACK payload with OUR full ContactCard so they can add us
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val torManager = TorManager.getInstance(this@TorService)
            val ownContactCard = com.securelegion.models.ContactCard(
                displayName = keyManager.getUsername() ?: "Unknown",
                solanaPublicKey = keyManager.getSolanaPublicKey(),
                x25519PublicKey = keyManager.getEncryptionPublicKey(),
                kyberPublicKey = keyManager.getKyberPublicKey(),
                solanaAddress = keyManager.getSolanaAddress(),
                friendRequestOnion = keyManager.getFriendRequestOnion() ?: "",
                messagingOnion = keyManager.getMessagingOnion() ?: "",
                voiceOnion = torManager.getVoiceOnionAddress() ?: "",
                contactPin = keyManager.getContactPin() ?: "",
                ipfsCid = keyManager.getIPFSCID(),
                timestamp = System.currentTimeMillis() / 1000
            )
            val ackPayload = ownContactCard.toJson()

            // Encrypt with their X25519 public key
            val encryptedAck = com.securelegion.crypto.RustBridge.encryptMessage(
                plaintext = ackPayload,
                recipientX25519PublicKey = contactCard.x25519PublicKey
            )

            // Send to their friend-request .onion (reuse Phase 2 function - same wire format)
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                val success = com.securelegion.crypto.RustBridge.sendFriendRequestAccepted(
                    recipientOnion = contactCard.friendRequestOnion,
                    encryptedAcceptance = encryptedAck
                )

                if (success) {
                    Log.i(TAG, "✓ Phase 3 ACK sent to ${contactCard.displayName}")
                } else {
                    Log.e(TAG, "Failed to send Phase 3 ACK to ${contactCard.displayName}")
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error sending Phase 3 ACK", e)
        }
    }

    /**
     * Handle Phase 3 acknowledgment (X25519-encrypted)
     * Payload: Simple confirmation that they received and processed Phase 2
     */
    private fun handlePhase3Acknowledgment(encryptedPayload: ByteArray) {
        try {
            Log.i(TAG, "Processing Phase 3 acknowledgment (X25519-encrypted)")

            // Find matching pending request (the one we're waiting for)
            val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            var matchingRequest: com.securelegion.models.PendingFriendRequest? = null
            var senderX25519PublicKey: ByteArray? = null

            for (requestJson in pendingRequestsSet) {
                try {
                    val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    // Look for outgoing pending requests (we sent Phase 2, waiting for ACK)
                    if (request.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING &&
                        request.status == com.securelegion.models.PendingFriendRequest.STATUS_PENDING &&
                        request.contactCardJson != null) {

                        val partialJson = org.json.JSONObject(request.contactCardJson)
                        val x25519Base64 = partialJson.optString("x25519_public_key", null)

                        if (x25519Base64 != null) {
                            senderX25519PublicKey = android.util.Base64.decode(x25519Base64, android.util.Base64.NO_WRAP)
                            matchingRequest = request
                            Log.d(TAG, "Found matching pending request for: ${request.displayName}")
                            break
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse pending request", e)
                }
            }

            if (senderX25519PublicKey == null || matchingRequest == null) {
                Log.e(TAG, "No matching pending request found for Phase 3 ACK")
                return
            }

            // Decrypt ACK
            val decryptedJson = com.securelegion.crypto.RustBridge.decryptMessage(
                encryptedPayload,
                senderX25519PublicKey,
                ByteArray(32) // privateKey parameter is deprecated/unused
            )

            if (decryptedJson == null) {
                Log.e(TAG, "Failed to decrypt Phase 3 ACK")
                return
            }

            Log.i(TAG, "Phase 3 ACK decrypted successfully")

            // Parse the full ContactCard from the ACK
            val contactCard = com.securelegion.models.ContactCard.fromJson(decryptedJson)
            Log.i(TAG, "✓ Friend request fully confirmed by: ${contactCard.displayName}")

            // Add to contacts database and initialize key chain (both in coroutine)
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    // Add contact to database first
                    val contactId = addContactToDatabase(contactCard)

                    if (contactId == null) {
                        Log.e(TAG, "Failed to add contact to database")
                        return@launch
                    }

                    // Extract precomputed shared secret from saved Phase 2 state
                    val savedJson = org.json.JSONObject(matchingRequest.contactCardJson ?: "{}")
                    val precomputedSharedSecret = if (savedJson.has("hybrid_shared_secret")) {
                        val sharedSecretBase64 = savedJson.getString("hybrid_shared_secret")
                        android.util.Base64.decode(sharedSecretBase64, android.util.Base64.NO_WRAP)
                    } else null

                    val torManager = com.securelegion.crypto.TorManager.getInstance(this@TorService)
                    val ourMessagingOnion = torManager.getOnionAddress()
                    val theirMessagingOnion = contactCard.messagingOnion

                    if (ourMessagingOnion.isNullOrEmpty() || theirMessagingOnion.isNullOrEmpty()) {
                        Log.e(TAG, "Cannot initialize key chain: missing onion address")
                        return@launch
                    }

                    if (precomputedSharedSecret != null) {
                        // Device B path: Use shared secret from Phase 2 encapsulation
                        com.securelegion.crypto.KeyChainManager.initializeKeyChain(
                            context = this@TorService,
                            contactId = contactId,
                            theirX25519PublicKey = contactCard.x25519PublicKey,
                            theirKyberPublicKey = contactCard.kyberPublicKey,
                            ourMessagingOnion = ourMessagingOnion,
                            theirMessagingOnion = theirMessagingOnion,
                            precomputedSharedSecret = precomputedSharedSecret
                        )
                        Log.i(TAG, "✓ Key chain initialized for ${contactCard.displayName} (quantum - precomputed secret)")
                    } else {
                        // Legacy path without quantum parameters
                        Log.w(TAG, "⚠️  No precomputed shared secret - initializing key chain in legacy mode")
                        com.securelegion.crypto.KeyChainManager.initializeKeyChain(
                            context = this@TorService,
                            contactId = contactId,
                            theirX25519PublicKey = contactCard.x25519PublicKey,
                            theirKyberPublicKey = contactCard.kyberPublicKey,
                            ourMessagingOnion = ourMessagingOnion,
                            theirMessagingOnion = theirMessagingOnion
                        )
                        Log.i(TAG, "✓ Key chain initialized for ${contactCard.displayName} (legacy)")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to add contact or initialize key chain for ${contactCard.displayName}", e)
                }
            }

            // Remove the pending request
            removePendingRequest(matchingRequest)

            // Show "Friend added" notification
            showFriendRequestAcceptedNotification(contactCard.displayName)

            // Send broadcast to update UI
            val broadcastIntent = android.content.Intent("com.securelegion.FRIEND_REQUEST_COMPLETED")
            broadcastIntent.setPackage(packageName)
            sendBroadcast(broadcastIntent)

            Log.i(TAG, "✓ Phase 3 complete - ACK received from ${contactCard.displayName}")

        } catch (e: Exception) {
            Log.e(TAG, "Error processing Phase 3 acknowledgment", e)
        }
    }

    /**
     * Add ContactCard to contacts database
     * Returns the inserted contact ID, or null on error
     */
    private suspend fun addContactToDatabase(contactCard: com.securelegion.models.ContactCard): Long? {
        return try {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                val contact = com.securelegion.database.entities.Contact(
                    displayName = contactCard.displayName,
                    solanaAddress = contactCard.solanaAddress,
                    publicKeyBase64 = android.util.Base64.encodeToString(contactCard.solanaPublicKey, android.util.Base64.NO_WRAP),
                    x25519PublicKeyBase64 = android.util.Base64.encodeToString(contactCard.x25519PublicKey, android.util.Base64.NO_WRAP),
                    kyberPublicKeyBase64 = android.util.Base64.encodeToString(contactCard.kyberPublicKey, android.util.Base64.NO_WRAP),
                    friendRequestOnion = contactCard.friendRequestOnion,
                    messagingOnion = contactCard.messagingOnion,
                    voiceOnion = contactCard.voiceOnion,
                    contactPin = contactCard.contactPin,
                    ipfsCid = contactCard.ipfsCid,
                    addedTimestamp = System.currentTimeMillis(),
                    friendshipStatus = com.securelegion.database.entities.Contact.FRIENDSHIP_CONFIRMED
                )

                val contactId = database.contactDao().insertContact(contact)
                Log.i(TAG, "Contact added to database: ${contact.displayName} (ID: $contactId)")

                // NOTE: Key chain initialization is handled by the caller (Phase 2/3 handlers)
                // Do NOT initialize here without quantum parameters - causes encryption mismatch!

                contactId
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to add contact to database", e)
            null
        }
    }

    /**
     * Remove pending friend request
     */
    private fun removePendingRequest(request: com.securelegion.models.PendingFriendRequest) {
        try {
            val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            val newSet = pendingRequestsSet.filter { requestJson ->
                try {
                    val existingRequest = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    existingRequest.ipfsCid != request.ipfsCid
                } catch (e: Exception) {
                    true
                }
            }.toMutableSet()

            prefs.edit()
                .putStringSet("pending_requests_v2", newSet)
                .apply()

            Log.i(TAG, "Removed pending request for ${request.displayName}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove pending request", e)
        }
    }

    /**
     * Save pending friend request to SharedPreferences
     */
    private fun savePendingFriendRequest(request: com.securelegion.models.PendingFriendRequest) {
        try {
            val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            // Add new request
            val newSet = pendingRequestsSet.toMutableSet()
            newSet.add(request.toJson())

            prefs.edit()
                .putStringSet("pending_requests_v2", newSet)
                .apply()

            Log.i(TAG, "Saved pending friend request for ${request.displayName}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to save pending friend request", e)
        }
    }

    /**
     * PHASE 8: Handle incoming PONG from listener
     * When receiver taps Download, they send PONG to our listener port 9152
     * We decrypt it, store it, and immediately send the message payload
     */
    private fun handleIncomingPong(pongWireBytes: ByteArray) {
        try {
            Log.i(TAG, "Handling incoming Pong (${pongWireBytes.size} bytes)")

            // Decrypt and store Pong in GLOBAL_PONG_SESSIONS
            val success = RustBridge.decryptAndStorePongFromListener(pongWireBytes)
            if (!success) {
                Log.e(TAG, "Failed to decrypt and store Pong")
                return
            }

            Log.i(TAG, "✓ Pong decrypted and stored successfully")

            // IMMEDIATELY trigger sending the message payload (don't wait for retry worker!)
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    val messageService = MessageService(this@TorService)
                    val result = messageService.pollForPongsAndSendMessages()

                    if (result.isSuccess) {
                        val sentCount = result.getOrNull() ?: 0
                        if (sentCount > 0) {
                            Log.i(TAG, "✓ Sent $sentCount message payload(s) immediately after Pong")
                        } else {
                            Log.d(TAG, "No pending messages found for this Pong")
                        }
                    } else {
                        Log.e(TAG, "✗ Failed to send message payload: ${result.exceptionOrNull()?.message}")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending message payload after Pong", e)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling Pong", e)
        }
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

                        // Decrypt and store ACK in GLOBAL_ACK_SESSIONS, get JSON: {"item_id":"...","ack_type":"..."}
                        val ackJson = RustBridge.decryptAndStoreAckFromListener(ackBytes)
                        if (ackJson != null) {
                            try {
                                // Parse JSON to extract item_id and ack_type
                                val jsonObj = org.json.JSONObject(ackJson)
                                val itemId = jsonObj.getString("item_id")
                                val ackType = jsonObj.getString("ack_type")
                                Log.i(TAG, "✓ ACK decrypted successfully: type=$ackType, item=$itemId")
                                // Handle the ACK to update delivery status
                                handleIncomingAck(itemId, ackType)
                            } catch (e: Exception) {
                                Log.e(TAG, "✗ Failed to parse ACK JSON: $ackJson", e)
                            }
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
     * Start periodic session cleanup timer (every 5 minutes)
     * Cleans up orphaned Ping/Pong/ACK sessions from crashes/failures as safety net
     */
    private fun startSessionCleanup() {
        if (isSessionCleanupRunning) {
            Log.d(TAG, "Session cleanup already running, skipping")
            return
        }

        isSessionCleanupRunning = true

        // Run cleanup every 5 minutes in background thread
        Thread {
            Log.d(TAG, "Session cleanup thread started (5-minute intervals)")
            while (isServiceRunning) {
                try {
                    // Sleep for 5 minutes
                    Thread.sleep(5 * 60 * 1000)  // 5 minutes

                    // Call Rust cleanup for expired sessions (older than 5 minutes)
                    RustBridge.cleanupExpiredSessions()
                    Log.i(TAG, "✓ Periodic Rust session cleanup completed")

                    // CRITICAL FIX: Clean up old received_ids entries to prevent table bloat
                    // Delete entries older than 7 days (604800000 ms)
                    // This prevents duplicate detection from blocking legitimate new messages
                    try {
                        val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                        val dbPassphrase = keyManager.getDatabasePassphrase()
                        val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                        val cutoffTimestamp = System.currentTimeMillis() - (7 * 24 * 60 * 60 * 1000L)
                        kotlinx.coroutines.runBlocking {
                            val deletedCount = database.receivedIdDao().deleteOldIds(cutoffTimestamp)
                            if (deletedCount > 0) {
                                Log.i(TAG, "✓ Cleaned up $deletedCount old received_ids entries (older than 7 days)")
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error cleaning up old received_ids", e)
                    }

                } catch (e: InterruptedException) {
                    Log.d(TAG, "Session cleanup thread interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error in session cleanup", e)
                }
            }
            isSessionCleanupRunning = false
            Log.d(TAG, "Session cleanup thread stopped")
        }.start()
    }

    /**
     * Handle incoming ACK to update delivery status
     * @param itemId The ping_id or message_id that was acknowledged
     * @param ackType The type of ACK: PING_ACK, MESSAGE_ACK, TAP_ACK, or PONG_ACK
     */
    private fun handleIncomingAck(itemId: String, ackType: String) {
        try {
            // PONG_ACK is received by the receiver (who sent the PONG)
            // The receiver has no outgoing message to update - they're waiting to receive one
            // PONG_ACK just means the sender got their PONG and will send the message blob soon
            if (ackType == "PONG_ACK") {
                Log.i(TAG, "✓ Received PONG_ACK - sender acknowledged PONG, expecting message blob soon (pingId: ${itemId.take(8)}...)")
                return
            }

            CoroutineScope(Dispatchers.IO).launch {
                // Retry finding the message up to 5 times with exponential backoff
                // This handles the race condition where ACK arrives before DB update completes
                var retryCount = 0
                val maxRetries = 5
                var message: com.securelegion.database.entities.Message? = null

                // Determine lookup method based on ACK type
                val lookupByPingId = (ackType == "PING_ACK" || ackType == "TAP_ACK" || ackType == "MESSAGE_ACK")

                while (retryCount < maxRetries && message == null) {
                    try {
                        val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                        val dbPassphrase = keyManager.getDatabasePassphrase()
                        val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                        // For PING_ACK, TAP_ACK, PONG_ACK, MESSAGE_ACK: lookup by pingId
                        // (Currently all ACKs use pingId for lookup)
                        message = if (lookupByPingId) {
                            database.messageDao().getMessageByPingId(itemId)
                        } else {
                            database.messageDao().getMessageByMessageId(itemId)
                        }

                        if (message == null && retryCount < maxRetries - 1) {
                            // Message not found yet - wait and retry (ACK may have arrived before DB update)
                            val delayMs = (100L * (1 shl retryCount)) // 100ms, 200ms, 400ms, 800ms, 1600ms
                            Log.d(TAG, "$ackType for $itemId: message not found in DB yet, retry ${retryCount + 1}/$maxRetries after ${delayMs}ms...")
                            kotlinx.coroutines.delay(delayMs)
                            retryCount++
                        } else {
                            break
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error looking up message for $ackType (retry $retryCount)", e)
                        break
                    }
                }

                try {
                    val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                    if (message != null) {
                        // Update appropriate field based on ACK type
                        val updatedMessage = when (ackType) {
                            "PING_ACK" -> {
                                Log.i(TAG, "✓ Received PING_ACK for message ${message.messageId} (pingId: $itemId) after $retryCount retries")
                                // Broadcast to update sender's UI (show single checkmark)
                                val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                                intent.setPackage(packageName)
                                intent.putExtra("CONTACT_ID", message.contactId)
                                sendBroadcast(intent)
                                Log.i(TAG, "✓ Broadcast MESSAGE_RECEIVED for PING_ACK (contact ${message.contactId})")
                                message.copy(
                                    pingDelivered = true,
                                    status = com.securelegion.database.entities.Message.STATUS_PING_SENT
                                )
                            }
                            "MESSAGE_ACK" -> {
                                Log.i(TAG, "✓ Received MESSAGE_ACK for message ${message.messageId}")

                                // Clean up ReceivedId tracking entries (Ping/Pong/Message) after successful delivery
                                // This prevents ReceivedId table bloat while keeping failed deliveries indefinitely
                                // (in case user is offline for months/years)
                                val pingId = message.pingId
                                if (pingId != null) {
                                    try {
                                        val deletedPing = database.receivedIdDao().deleteById(pingId)
                                        val deletedPong = database.receivedIdDao().deleteById("pong_$pingId")
                                        val deletedMsg = database.receivedIdDao().deleteById(message.messageId)
                                        val totalDeleted = deletedPing + deletedPong + deletedMsg
                                        if (totalDeleted > 0) {
                                            Log.d(TAG, "✓ Cleaned up $totalDeleted ReceivedId entries (Ping/Pong/Message) after successful delivery")
                                        }
                                    } catch (e: Exception) {
                                        Log.w(TAG, "Failed to clean up ReceivedId entries (non-critical)", e)
                                    }

                                    // Clean up SharedPreferences ping tracking (prevents memory bloat)
                                    // After MESSAGE_ACK, we'll never need this ping data again
                                    try {
                                        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                                        prefs.edit().apply {
                                            // Remove ping-indexed entries (for Pong lookup)
                                            remove("ping_${pingId}_contact_id")
                                            remove("ping_${pingId}_name")
                                            remove("ping_${pingId}_timestamp")
                                            remove("ping_${pingId}_onion")
                                            // Remove contact-indexed entries (for outgoing tracking)
                                            remove("outgoing_ping_${message.contactId}_id")
                                            remove("outgoing_ping_${message.contactId}_name")
                                            remove("outgoing_ping_${message.contactId}_timestamp")
                                            remove("outgoing_ping_${message.contactId}_onion")
                                            apply()
                                        }
                                        Log.d(TAG, "✓ Cleaned up SharedPreferences ping tracking for ${pingId.take(8)}...")
                                    } catch (e: Exception) {
                                        Log.w(TAG, "Failed to clean up SharedPreferences (non-critical)", e)
                                    }
                                }

                                message.copy(
                                    messageDelivered = true,
                                    status = com.securelegion.database.entities.Message.STATUS_DELIVERED
                                )
                            }
                            "TAP_ACK" -> {
                                Log.i(TAG, "✓ Received TAP_ACK - contact ${message.contactId} confirmed online! Triggering retry for all pending messages")

                                // TAP_ACK means peer is online and ready to receive - retry all pending messages
                                CoroutineScope(Dispatchers.IO).launch {
                                    try {
                                        // Query ALL pending/failed messages for this contact
                                        val pendingMessages = database.messageDao().getPendingMessages()
                                            .filter { it.contactId == message.contactId }
                                        val awaitingPong = database.messageDao().getMessagesAwaitingPong()
                                            .filter { it.contactId == message.contactId }
                                        val allMessages = (pendingMessages + awaitingPong).distinctBy { it.id }

                                        if (allMessages.isNotEmpty()) {
                                            Log.i(TAG, "Found ${allMessages.size} pending messages to retry after TAP_ACK")
                                            val messageService = com.securelegion.services.MessageService(this@TorService)

                                            for (msg in allMessages) {
                                                try {
                                                    // Skip if already delivered
                                                    if (msg.messageDelivered) continue

                                                    // Retry based on phase
                                                    if (msg.pongDelivered) {
                                                        // PONG received - receiver downloading
                                                        Log.d(TAG, "  ${msg.messageId}: PONG received, waiting for download")
                                                    } else if (msg.pingDelivered) {
                                                        // PING delivered - poll for PONG
                                                        Log.d(TAG, "  ${msg.messageId}: PING_ACK received, polling for PONG")
                                                        messageService.pollForPongsAndSendMessages()
                                                    } else {
                                                        // No PING_ACK - retry PING
                                                        Log.i(TAG, "  ${msg.messageId}: Retrying PING after TAP_ACK")
                                                        messageService.sendPingForMessage(msg)
                                                        database.messageDao().updateMessage(msg.copy(
                                                            retryCount = msg.retryCount + 1,
                                                            lastRetryTimestamp = System.currentTimeMillis()
                                                        ))
                                                    }
                                                } catch (e: Exception) {
                                                    Log.e(TAG, "Failed to retry message ${msg.messageId} after TAP_ACK", e)
                                                }
                                            }
                                        }
                                    } catch (e: Exception) {
                                        Log.e(TAG, "Error processing TAP_ACK retry logic", e)
                                    }
                                }

                                message.copy(tapDelivered = true)
                            }
                            else -> {
                                Log.w(TAG, "Unknown ACK type: $ackType")
                                null
                            }
                        }

                        if (updatedMessage != null) {
                            database.messageDao().updateMessage(updatedMessage)
                            Log.i(TAG, "✓ Updated message ${message.messageId} for $ackType")

                            // Cancel immediate retry worker if MESSAGE_ACK (message fully delivered)
                            if (ackType == "MESSAGE_ACK") {
                                ImmediateRetryWorker.cancelForMessage(this@TorService, message.messageId)
                                Log.d(TAG, "Cancelled immediate retry worker for ${message.messageId}")

                                // Broadcast to update sender's UI (show double checkmarks)
                                val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                                intent.setPackage(packageName)
                                intent.putExtra("CONTACT_ID", message.contactId)
                                sendBroadcast(intent)
                                Log.i(TAG, "✓ Broadcast MESSAGE_RECEIVED to update sender UI for contact ${message.contactId}")
                            }
                        }
                    } else {
                        Log.w(TAG, "Could not find message for $ackType item_id: $itemId")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error updating message delivery status for $ackType", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming $ackType", e)
        }
    }

    /**
     * Handle incoming MESSAGE from MESSAGE channel (direct routing, no trial decryption needed)
     * Wire format: [connection_id (8 bytes LE)][encrypted_message_blob]
     */
    private fun handleIncomingMessage(encodedData: ByteArray) {
        try {
            // Wire format: [connection_id (8 bytes LE)][encrypted_message_blob]
            if (encodedData.size < 8) {
                Log.e(TAG, "Invalid MESSAGE data: too short")
                return
            }

            // Extract connection_id (first 8 bytes, little-endian)
            val connectionId = java.nio.ByteBuffer.wrap(encodedData, 0, 8)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .long

            // Extract encrypted message blob (rest of bytes)
            val encryptedMessageBlob = encodedData.copyOfRange(8, encodedData.size)

            Log.i(TAG, "✓ Received MESSAGE on connection $connectionId via direct routing: ${encryptedMessageBlob.size} bytes")

            // Process message blob directly (no trial decryption needed!)
            handleIncomingMessageBlob(encryptedMessageBlob)
        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming MESSAGE", e)
        }
    }

    /**
     * Handle incoming VOICE call signaling from VOICE channel
     * Wire format: [connection_id (8 bytes LE)][Sender X25519 Public Key (32 bytes)][Encrypted Payload]
     * Completely separate from MESSAGE to allow simultaneous text messaging during voice calls
     */
    private fun handleIncomingVoiceMessage(encodedData: ByteArray) {
        try {
            // Wire format: [connection_id (8 bytes LE)][Sender X25519 key (32 bytes)][Encrypted payload]
            if (encodedData.size < 40) {  // 8 + 32 minimum
                Log.e(TAG, "Invalid VOICE data: too short (${encodedData.size} bytes)")
                return
            }

            // Extract connection_id (first 8 bytes, little-endian)
            val connectionId = java.nio.ByteBuffer.wrap(encodedData, 0, 8)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .long

            // Extract sender X25519 public key (next 32 bytes)
            val senderX25519PublicKey = encodedData.copyOfRange(8, 40)

            // Extract encrypted payload (rest of bytes)
            val encryptedPayload = encodedData.copyOfRange(40, encodedData.size)

            Log.i(TAG, "✓ Received VOICE call signaling on connection $connectionId: ${encryptedPayload.size} bytes")

            // Look up contact by X25519 public key to get onion address
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            val contact = kotlinx.coroutines.runBlocking {
                database.contactDao().getContactByX25519PublicKey(
                    android.util.Base64.encodeToString(senderX25519PublicKey, android.util.Base64.NO_WRAP)
                )
            }

            if (contact == null) {
                Log.w(TAG, "⚠️  Cannot process VOICE call signaling - contact not found for X25519 key")
                return
            }

            val senderOnion = contact.messagingOnion ?: contact.torOnionAddress ?: ""
            if (senderOnion.isEmpty()) {
                Log.w(TAG, "⚠️  Cannot process VOICE call signaling - no onion address for contact ${contact.id}")
                return
            }

            // Process call signaling through MessageService
            kotlinx.coroutines.GlobalScope.launch(Dispatchers.IO) {
                try {
                    val messageService = MessageService(this@TorService)
                    val encryptedPayloadBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    // Call existing handler (it will decrypt, parse, and route to IncomingCallActivity)
                    messageService.handleCallSignaling(
                        encryptedData = encryptedPayloadBase64,
                        senderPublicKey = senderX25519PublicKey,
                        senderOnionAddress = senderOnion,
                        contactId = contact.id  // Pass contact ID to avoid redundant lookup
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing VOICE call signaling", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming VOICE call signaling", e)
        }
    }

    private suspend fun handleIncomingPing(encodedData: ByteArray) {
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
                val pongPingId = try {
                    Log.d(TAG, "Calling decryptIncomingPong()...")
                    val startTime = System.currentTimeMillis()
                    val result = RustBridge.decryptIncomingPong(encryptedPingWire)
                    val elapsed = System.currentTimeMillis() - startTime
                    Log.d(TAG, "decryptIncomingPong() completed in ${elapsed}ms")
                    result
                } catch (e: Exception) {
                    Log.e(TAG, "⚠️  decryptIncomingPong threw exception: ${e.message}")
                    Log.e(TAG, "Stack trace:", e)
                    null
                }

                if (pongPingId != null) {
                    Log.i(TAG, "✓ Successfully decrypted as Pong for Ping ID: $pongPingId")

                    // Track this pongId to prevent duplicate processing (PRIMARY deduplication)
                    val pongTracking = com.securelegion.database.entities.ReceivedId(
                        receivedId = "pong_$pongPingId",
                        idType = com.securelegion.database.entities.ReceivedId.TYPE_PONG,
                        receivedTimestamp = System.currentTimeMillis()
                    )
                    val rowId = tryInsertReceivedId(database, pongTracking, "PONG")

                    if (rowId == -1L) {
                        Log.w(TAG, "⚠️  DUPLICATE PONG received! PongId=pong_$pongPingId already in tracking table")

                        // CRITICAL FIX: Check if message was already delivered before blocking retry
                        val message = withContext(Dispatchers.IO) {
                            database.messageDao().getMessageByPingId(pongPingId)
                        }

                        if (message != null && message.messageDelivered) {
                            Log.i(TAG, "→ Message already delivered (messageId=${message.messageId}) - sending PONG_ACK and blocking duplicate")

                            // Send PONG_ACK for duplicate to stop sender from retrying
                            val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
                            val contactIdForPing = prefs.getString("ping_${pongPingId}_contact_id", null)?.toLongOrNull() ?: -1L

                            if (contactIdForPing > 0) {
                                serviceScope.launch {
                                    sendAckWithRetry(
                                        connectionId = connectionId,
                                        itemId = pongPingId,
                                        ackType = "PONG_ACK",
                                        contactId = contactIdForPing,
                                        maxRetries = 3,
                                        initialDelayMs = 1000L
                                    )
                                }
                            }
                            return
                        } else {
                            Log.i(TAG, "→ Message NOT yet delivered - allowing retry download (messageDelivered=${message?.messageDelivered})")
                            // Continue to line 2211 to retry message send
                        }
                    }
                    Log.i(TAG, "→ New Pong - tracked in database (rowId=$rowId)")

                    // SEND PONG_ACK to confirm receipt of PONG
                    // Use sendAckWithRetry() for automatic retry with exponential backoff
                    // Look up contact by ping_id
                    val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
                    val contactIdForPing = prefs.getString("ping_${pongPingId}_contact_id", null)?.toLongOrNull() ?: -1L

                    if (contactIdForPing > 0) {
                        serviceScope.launch {
                            sendAckWithRetry(
                                connectionId = connectionId,
                                itemId = pongPingId,
                                ackType = "PONG_ACK",
                                contactId = contactIdForPing,
                                maxRetries = 3,
                                initialDelayMs = 1000L
                            )
                        }
                    } else {
                        Log.w(TAG, "⚠️  Cannot send PONG_ACK - no contact_id found for ping_id=$pongPingId")
                    }

                    // Check if we already sent the message for this Pong (secondary check)
                    // CRITICAL FIX: Use suspend function instead of runBlocking to avoid freezing
                    val message = withContext(Dispatchers.IO) {
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

                // Neither Ping nor Pong - must be a message blob!
                Log.i(TAG, "→ Not a Ping or Pong - treating as MESSAGE BLOB")
                handleIncomingMessageBlob(encryptedPingWire)
                return
            }

            // Successfully decrypted as Ping
            Log.i(TAG, "✓ Decrypted as Ping. Ping ID: $pingId")

            // Get sender information from the Ping token
            val senderPublicKey = RustBridge.getPingSenderPublicKey(pingId)

            // Look up sender in contacts database
            val contactInfo = if (senderPublicKey != null) {
                val publicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)
                withContext(Dispatchers.IO) {
                    database.contactDao().getContactByPublicKey(publicKeyBase64)
                }
            } else {
                null
            }

            val contactId = contactInfo?.id
            val senderName = contactInfo?.displayName ?: "Unknown Contact"
            Log.i(TAG, "Incoming message request from: $senderName (contactId=$contactId)")

            if (contactId == null) {
                Log.w(TAG, "Ping from unknown contact - ignoring")
                return
            }

            // PING INBOX STATE TRACKING: Check current state
            Log.d(TAG, "═══ PING INBOX CHECK: pingId=$pingId ═══")
            val existingPing = withContext(Dispatchers.IO) {
                database.pingInboxDao().getByPingId(pingId)
            }

            val now = System.currentTimeMillis()
            var shouldNotify = false

            when {
                existingPing != null && existingPing.state == com.securelegion.database.entities.PingInbox.STATE_MSG_STORED -> {
                    // Message already stored - just update retry tracking
                    Log.i(TAG, "✓ Message $pingId already stored (state=MSG_STORED)")
                    Log.i(TAG, "→ Updating retry tracking and sending PING_ACK (idempotent)")
                    withContext(Dispatchers.IO) {
                        database.pingInboxDao().updatePingRetry(pingId, now)
                    }
                    // No notification needed
                }

                existingPing != null -> {
                    // PING seen before but message not stored yet - update retry tracking
                    Log.i(TAG, "✓ PING $pingId seen before (state=${existingPing.state}, attempt=${existingPing.attemptCount + 1})")
                    withContext(Dispatchers.IO) {
                        database.pingInboxDao().updatePingRetry(pingId, now)
                    }
                    Log.i(TAG, "→ Updated retry tracking, sending PING_ACK")
                    // Don't notify again
                }

                else -> {
                    // New PING - insert into ping_inbox as PING_SEEN
                    Log.i(TAG, "✓ NEW PING $pingId - inserting as PING_SEEN")
                    val pingInbox = com.securelegion.database.entities.PingInbox(
                        pingId = pingId,
                        contactId = contactId,
                        state = com.securelegion.database.entities.PingInbox.STATE_PING_SEEN,
                        firstSeenAt = now,
                        lastUpdatedAt = now,
                        lastPingAt = now,
                        pingAckedAt = null,  // Will update after sending ACK
                        attemptCount = 1
                    )

                    val inserted = withContext(Dispatchers.IO) {
                        try {
                            database.pingInboxDao().insert(pingInbox)
                            true
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to insert ping_inbox entry", e)
                            false
                        }
                    }

                    if (inserted) {
                        // Store pending ping for UI display
                        storePendingPing(pingId, connectionId, senderPublicKey, senderName, encryptedPingWire)

                        shouldNotify = true
                        Log.i(TAG, "→ Will show notification and send PING_ACK")
                    }
                }
            }

            // Show notification for new pings only
            if (shouldNotify) {
                showNewMessageNotification()

                // Broadcast to update MainActivity and ChatActivity if open
                val intent = Intent("com.securelegion.NEW_PING")
                intent.setPackage(packageName)
                intent.putExtra("CONTACT_ID", contactId)
                sendBroadcast(intent)
                Log.d(TAG, "Sent NEW_PING broadcast for contactId=$contactId")
            }

            // Send PING_ACK (always, regardless of state - "I saw your ping")
            serviceScope.launch {
                try {
                    sendAckWithRetry(
                        connectionId = connectionId,
                        itemId = pingId,
                        ackType = "PING_ACK",
                        contactId = contactId,
                        maxRetries = 1,
                        initialDelayMs = 0L
                    )

                    // Update pingAckedAt timestamp
                    withContext(Dispatchers.IO) {
                        database.pingInboxDao().updatePingAckTime(pingId, System.currentTimeMillis())
                    }

                    Log.d(TAG, "✓ PING_ACK sent for pingId=$pingId")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to send PING_ACK", e)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming Ping", e)
        }
    }

    /**
     * Safely inserts a received ID into the database with error handling.
     * Returns 0L (treat as new) on database failure to prevent app crashes.
     * This is better than crashing - a ghost duplicate (~0.0001% risk) is acceptable.
     *
     * CRITICAL FIX: Now a suspend function to avoid blocking the ping handler thread
     *
     * @param database The SecureLegion database instance
     * @param receivedId The ReceivedId entity to insert
     * @param itemType The type of item ("PING", "PONG", "MESSAGE") for logging
     * @return Row ID on success, -1L if duplicate, 0L on database failure
     */
    private suspend fun tryInsertReceivedId(
        database: com.securelegion.database.SecureLegionDatabase,
        receivedId: com.securelegion.database.entities.ReceivedId,
        itemType: String
    ): Long {
        return try {
            withContext(Dispatchers.IO) {
                Log.d(TAG, "Attempting to insert $itemType ID into received_ids table...")
                val result = database.receivedIdDao().insertReceivedId(receivedId)
                Log.d(TAG, "Insert result: rowId=$result (${if (result == -1L) "DUPLICATE" else "NEW"})")
                result
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ DATABASE INSERT FAILED! This $itemType will be processed (GHOST RISK!)", e)
            Log.e(TAG, "Exception details: ${e.javaClass.simpleName}: ${e.message}")
            0L // Treat as new if database fails (will cause ghosts but better than crash)
        }
    }

    /**
     * Sends ACK with automatic retry logic.
     * Tries existing connection first, falls back to new connection, then retries with backoff.
     * This prevents sender from having to retry the entire PING/PONG/MESSAGE.
     *
     * @param connectionId The connection ID from the incoming message
     * @param itemId The ping ID or message ID to acknowledge
     * @param ackType "PING_ACK", "PONG_ACK", or "MESSAGE_ACK"
     * @param contactId The contact database ID
     * @param maxRetries Maximum number of retry attempts (default: 3)
     * @param initialDelayMs Initial delay between retries in milliseconds (default: 1000ms)
     */
    private suspend fun sendAckWithRetry(
        connectionId: Long? = null,  // Optional - null if no existing connection available
        itemId: String,
        ackType: String,
        contactId: Long,
        maxRetries: Int = 3,
        initialDelayMs: Long = 1000L
    ) {
        val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
        val dbPassphrase = keyManager.getDatabasePassphrase()
        val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)
        val contact = database.contactDao().getContactById(contactId) ?: run {
            Log.w(TAG, "Could not find contact with ID $contactId to send $ackType")
            return
        }

        val senderX25519Pubkey = android.util.Base64.decode(
            contact.x25519PublicKeyBase64,
            android.util.Base64.NO_WRAP
        )
        val senderEd25519Pubkey = android.util.Base64.decode(
            contact.publicKeyBase64,
            android.util.Base64.NO_WRAP
        )

        var attempt = 0
        var delayMs = initialDelayMs

        while (attempt < maxRetries) {
            try {
                var ackSuccess = false

                // PATH 1: DISABLED - Connection reuse for ACKs
                //
                // ARCHITECTURAL DECISION: All ACKs MUST go to dedicated port 9153 for clean separation.
                // Connection reuse optimization is disabled because:
                //   1. Reusing connections sends ACKs to port 8080 (wrong port)
                //   2. Causes routing confusion between PING/PONG and ACK handlers
                //   3. Performance difference (~200ms) is negligible for background confirmations
                //   4. Clean architecture > micro-optimization
                //
                // Connection reuse code preserved below but disabled:
                if (false && connectionId != null) {
                    ackSuccess = RustBridge.sendAckOnConnection(
                        connectionId!!,  // Safe because null check above
                        itemId,
                        ackType,
                        senderX25519Pubkey
                    )

                    if (ackSuccess) {
                        Log.i(TAG, "✓ $ackType sent successfully on existing connection for $itemId (attempt ${attempt + 1})")
                        return // Success!
                    }
                    Log.d(TAG, "Connection closed, falling back to new connection for $ackType (attempt ${attempt + 1})")
                }

                // All ACKs now use PATH 2 (new connection to port 9153)
                Log.d(TAG, "Sending $ackType via new connection to port 9153 (connection reuse disabled)")

                // PATH 2: Open new connection (always available)
                val onionAddress = contact.messagingOnion ?: contact.torOnionAddress ?: ""
                ackSuccess = RustBridge.sendDeliveryAck(
                    itemId,
                    ackType,
                    senderEd25519Pubkey,
                    senderX25519Pubkey,
                    onionAddress
                )

                if (ackSuccess) {
                    Log.i(TAG, "✓ $ackType sent successfully via new connection for $itemId (attempt ${attempt + 1})")
                    return // Success!
                }

                // Both paths failed
                attempt++
                if (attempt < maxRetries) {
                    Log.w(TAG, "⚠️ $ackType send failed (attempt $attempt/$maxRetries), retrying in ${delayMs}ms...")
                    kotlinx.coroutines.delay(delayMs)
                    delayMs *= 2 // Exponential backoff: 1s, 2s, 4s
                } else {
                    Log.e(TAG, "✗ $ackType send FAILED after $maxRetries attempts for $itemId")
                    Log.e(TAG, "→ Sender will retry ${if (ackType == "PING_ACK") "PING" else if (ackType == "PONG_ACK") "PONG" else "MESSAGE"}, which is acceptable")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Exception during $ackType send (attempt ${attempt + 1}/$maxRetries)", e)
                attempt++
                if (attempt < maxRetries) {
                    kotlinx.coroutines.delay(delayMs)
                    delayMs *= 2
                }
            }
        }
    }

    /**
     * Handle incoming message blob
     * Wire format: [Sender X25519 Public Key - 32 bytes][Encrypted Message]
     */
    private fun handleIncomingMessageBlob(encryptedMessageWire: ByteArray) {
        try {
            // Wire format: [Sender X25519 - 32 bytes][Encrypted Message]
            // Note: Type byte was stripped by Rust listener during routing

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
                // Unknown sender - check if we have a pending outgoing request
                // If yes, this is a FRIEND_REQUEST_ACCEPTED notification
                // If no, this is a new incoming FRIEND_REQUEST
                val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
                val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()
                val hasPendingOutgoingRequest = pendingRequestsV2.any { requestJson ->
                    try {
                        val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                        request.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING
                        // Note: We can't match by X25519 key here since we don't have their card yet
                        // We'll handle this inside handleFriendRequestAcceptedFromPending
                    } catch (e: Exception) {
                        false
                    }
                }

                if (hasPendingOutgoingRequest) {
                    Log.i(TAG, "→ Unknown sender with pending outgoing request - treating as FRIEND_REQUEST_ACCEPTED")
                    handleFriendRequestAcceptedFromPending(senderX25519PublicKey, encryptedPayload)
                } else {
                    Log.i(TAG, "→ Unknown sender - treating as FRIEND_REQUEST")
                    handleFriendRequest(senderX25519PublicKey, encryptedPayload)
                }
                return
            }

            // Known contact - check if this is a FRIEND_REQUEST_ACCEPTED notification
            if (contact.friendshipStatus == com.securelegion.database.entities.Contact.FRIENDSHIP_PENDING_SENT) {
                Log.i(TAG, "→ Known contact with PENDING status - treating as FRIEND_REQUEST_ACCEPTED")
                handleFriendRequestAccepted(contact, senderX25519PublicKey, encryptedPayload)
                return
            }

            // Known contact - this is a regular message
            // Note: All message types (TEXT, VOICE, FRIEND_REQUEST, etc.) come through the same listener channel
            val encryptedMessage = encryptedPayload

            Log.i(TAG, "Processing message from: ${contact.displayName}")

            // CALL_SIGNALING now arrives via dedicated VOICE channel (separate from MESSAGE)
            // This MESSAGE handler only processes: TEXT, VOICE clips, IMAGES, PAYMENTS

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

            // Check for metadata byte (0x00 = TEXT, 0x01 = VOICE, 0x02 = IMAGE, 0x0A = PAYMENT_REQUEST, etc.)
            if (encryptedMessage.isNotEmpty()) {
                when (encryptedMessage[0].toInt() and 0xFF) {
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
                    0x02 -> {
                        // IMAGE message - strip metadata byte
                        Log.d(TAG, "Message type: IMAGE (v2)")
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)
                        Log.d(TAG, "  Stripped 1 byte metadata, encrypted payload: ${actualEncryptedMessage.size} bytes")
                    }
                    0x0A -> {
                        // PAYMENT_REQUEST message
                        Log.d(TAG, "Message type: PAYMENT_REQUEST")
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)
                        Log.d(TAG, "  Stripped 1 byte metadata, encrypted payload: ${actualEncryptedMessage.size} bytes")
                    }
                    0x0B -> {
                        // PAYMENT_SENT message
                        Log.d(TAG, "Message type: PAYMENT_SENT")
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)
                        Log.d(TAG, "  Stripped 1 byte metadata, encrypted payload: ${actualEncryptedMessage.size} bytes")
                    }
                    0x0C -> {
                        // PAYMENT_ACCEPTED message
                        Log.d(TAG, "Message type: PAYMENT_ACCEPTED")
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)
                        Log.d(TAG, "  Stripped 1 byte metadata, encrypted payload: ${actualEncryptedMessage.size} bytes")
                    }
                    0x0E -> {
                        // PING/PONG connectivity test message
                        Log.i(TAG, "Message type: PING/PONG (connectivity test)")
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)

                        // Decrypt PING/PONG message
                        val decryptedMessage = com.securelegion.crypto.RustBridge.decryptMessage(
                            actualEncryptedMessage,
                            ourEd25519PublicKey,
                            ourPrivateKey
                        )

                        if (decryptedMessage != null) {
                            // Convert back from ISO_8859_1 to get original bytes
                            val messageBytes = decryptedMessage.toByteArray(Charsets.ISO_8859_1)
                            val jsonString = String(messageBytes, Charsets.UTF_8)

                            val pingPongMessage = com.securelegion.voice.ConnectivityTest.parsePingPongMessage(jsonString)

                            when (pingPongMessage) {
                                is com.securelegion.voice.ConnectivityTest.PingPongMessage.Ping -> {
                                    Log.i(TAG, "✓ Received PING - auto-replying with PONG")

                                    // Get contact X25519 and VOICE onion address for PONG reply
                                    // IMPORTANT: Use voiceOnion, not messagingOnion, for security
                                    val senderVoiceOnion = contact.voiceOnion ?: ""
                                    val contactX25519PublicKey = try {
                                        android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)
                                    } catch (e: Exception) {
                                        Log.e(TAG, "Failed to decode contact X25519 key", e)
                                        ByteArray(0)
                                    }

                                    if (senderVoiceOnion.isNotEmpty() && contactX25519PublicKey.isNotEmpty()) {
                                        kotlinx.coroutines.GlobalScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                                            com.securelegion.voice.ConnectivityTest.handleIncomingPing(
                                                pingPongMessage,
                                                contactX25519PublicKey,
                                                senderVoiceOnion
                                            )
                                        }
                                    } else {
                                        Log.e(TAG, "Cannot send PONG - missing voice onion or X25519 key")
                                    }
                                }
                                is com.securelegion.voice.ConnectivityTest.PingPongMessage.Pong -> {
                                    Log.i(TAG, "✓ Received PONG - connectivity confirmed!")
                                    Log.i(TAG, "  Test ID: ${pingPongMessage.testId}")
                                    Log.i(TAG, "  Seq: ${pingPongMessage.seq}")

                                    // Mark PONG as received so testConnectivity() can complete
                                    com.securelegion.voice.ConnectivityTest.markPongReceived(pingPongMessage.testId)
                                }
                                null -> {
                                    Log.w(TAG, "Failed to parse PING/PONG message")
                                }
                            }
                        } else {
                            Log.e(TAG, "Failed to decrypt PING/PONG message")
                        }

                        // Don't save PING/PONG messages to database - they're ephemeral
                        return
                    }
                    0x20 -> {
                        // GROUP_INVITE message
                        Log.i(TAG, "Received GROUP INVITE")
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)

                        // Handle group invite using GroupMessagingService
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            try {
                                val groupMessagingService = GroupMessagingService.getInstance(this@TorService)
                                val result = groupMessagingService.processReceivedGroupInvite(
                                    actualEncryptedMessage,
                                    ourEd25519PublicKey
                                )
                                if (result.isSuccess) {
                                    Log.i(TAG, "✓ Group invite processed: ${result.getOrNull()}")
                                } else {
                                    Log.e(TAG, "✗ Failed to process group invite", result.exceptionOrNull())
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Error processing group invite", e)
                            }
                        }
                        return  // Don't process as regular message
                    }
                    0x21 -> {
                        // GROUP_MESSAGE message
                        Log.i(TAG, "Received GROUP MESSAGE")
                        actualEncryptedMessage = encryptedMessage.copyOfRange(1, encryptedMessage.size)

                        // Handle group message using GroupMessagingService
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            try {
                                val groupMessagingService = GroupMessagingService.getInstance(this@TorService)
                                val result = groupMessagingService.processReceivedGroupMessage(
                                    actualEncryptedMessage,
                                    ourEd25519PublicKey
                                )
                                if (result.isSuccess) {
                                    Log.i(TAG, "✓ Group message processed: ${result.getOrNull()}")
                                } else {
                                    Log.e(TAG, "✗ Failed to process group message", result.exceptionOrNull())
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Error processing group message", e)
                            }
                        }
                        return  // Don't process as regular message
                    }
                    else -> {
                        // Legacy message without metadata - treat as TEXT
                        Log.d(TAG, "Message type: TEXT (legacy, no metadata)")
                    }
                }
            }

            // Get key chain for progressive ephemeral key evolution
            Log.d(TAG, "KEY CHAIN LOAD: Loading key chain from database...")
            Log.d(TAG, "  contactId=${contact.id} (${contact.displayName})")
            val keyChain = kotlinx.coroutines.runBlocking {
                com.securelegion.crypto.KeyChainManager.getKeyChain(this@TorService, contact.id)
            }

            if (keyChain == null) {
                Log.e(TAG, "✗ Key chain not found for contact ${contact.displayName}")
                Log.e(TAG, "  Contact ID: ${contact.id}")
                Log.e(TAG, "  This contact may need to be re-added to initialize key chain")
                return
            }

            Log.d(TAG, "KEY CHAIN LOAD: Loaded from database successfully")
            Log.d(TAG, "  sendCounter=${keyChain.sendCounter}")
            Log.d(TAG, "  receiveCounter=${keyChain.receiveCounter} <- will use this for decryption")
            Log.d(TAG, "Attempting to decrypt ${actualEncryptedMessage.size} bytes with sequence ${keyChain.receiveCounter}...")
            var result = RustBridge.decryptMessageWithEvolution(
                actualEncryptedMessage,
                keyChain.receiveChainKeyBytes,
                keyChain.receiveCounter
            )

            var plaintext: String
            var finalReceiveCounter: Long = keyChain.receiveCounter

            if (result == null) {
                // Decryption failed with expected sequence - try out-of-order decryption
                Log.w(TAG, "⚠️  Decryption failed with sequence ${keyChain.receiveCounter}, attempting out-of-order recovery...")

                // Extract sender's sequence from wire format (first 8 bytes, big-endian)
                if (actualEncryptedMessage.size < 8) {
                    Log.e(TAG, "Message too short to extract sequence")
                    return
                }

                val senderSequence = java.nio.ByteBuffer.wrap(actualEncryptedMessage, 0, 8)
                    .order(java.nio.ByteOrder.BIG_ENDIAN)
                    .long
                Log.i(TAG, "📋 Extracted sender sequence: $senderSequence (our current: ${keyChain.receiveCounter})")

                // Get onion addresses for direction mapping
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                val ourOnion = keyManager.getMessagingOnion()
                val theirOnion = contact.messagingOnion

                if (ourOnion == null || theirOnion == null) {
                    Log.e(TAG, "Cannot perform out-of-order decryption: missing onion addresses")
                    Log.e(TAG, "  Our onion: $ourOnion")
                    Log.e(TAG, "  Their onion: $theirOnion")
                    return
                }

                // Derive key at sender's sequence using root key
                val derivedKey = try {
                    RustBridge.deriveReceiveKeyAtSequence(
                        keyChain.rootKeyBytes,
                        senderSequence,
                        ourOnion,
                        theirOnion
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to derive key at sequence $senderSequence", e)
                    null
                }

                if (derivedKey == null) {
                    Log.e(TAG, "✗ Failed to derive receive key for sequence $senderSequence")
                    return
                }

                Log.i(TAG, "🔑 Successfully derived key at sender's sequence $senderSequence, retrying decryption...")

                // Try decrypting with the derived key
                result = RustBridge.decryptMessageWithEvolution(
                    actualEncryptedMessage,
                    derivedKey,
                    senderSequence
                )

                if (result == null) {
                    Log.e(TAG, "✗ Out-of-order decryption also failed for sequence $senderSequence")
                    return
                }

                Log.i(TAG, "✓ Out-of-order decryption succeeded! Message was encrypted with sequence $senderSequence")
                plaintext = result.plaintext
                finalReceiveCounter = senderSequence
            } else {
                plaintext = result.plaintext
            }

            // Save evolved key to database (key evolution happened atomically in Rust)
            Log.d(TAG, "KEY EVOLUTION: About to update receive chain key")
            Log.d(TAG, "  contactId=${contact.id} (${contact.displayName})")
            Log.d(TAG, "  Current receiveCounter=${keyChain.receiveCounter}")
            Log.d(TAG, "  Actual sequence used=${finalReceiveCounter}")
            Log.d(TAG, "  New receiveCounter will be=${finalReceiveCounter + 1}")
            kotlinx.coroutines.runBlocking {
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)
                database.contactKeyChainDao().updateReceiveChainKey(
                    contactId = contact.id,
                    newReceiveChainKeyBase64 = android.util.Base64.encodeToString(result.evolvedChainKey, android.util.Base64.NO_WRAP),
                    newReceiveCounter = finalReceiveCounter + 1,
                    timestamp = System.currentTimeMillis()
                )
                // VERIFY the update actually persisted
                val verifyKeyChain = database.contactKeyChainDao().getKeyChainByContactId(contact.id)
                Log.d(TAG, "VERIFICATION: After update, database shows receiveCounter=${verifyKeyChain?.receiveCounter}")
                if (verifyKeyChain?.receiveCounter != finalReceiveCounter + 1) {
                    Log.e(TAG, "ERROR: Counter update did NOT persist! Expected ${finalReceiveCounter + 1}, got ${verifyKeyChain?.receiveCounter}")
                } else {
                    Log.d(TAG, "Counter update verified successfully")
                }
            }
            Log.d(TAG, "✓ Message decrypted with sequence ${finalReceiveCounter}")

            Log.i(TAG, "✓ Decrypted message (${messageType}): ${if (messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_TEXT) plaintext.take(50) else "${voiceDuration}s voice, ${plaintext.length} bytes"}...")

            // Save message directly to database (already decrypted)
            Log.d(TAG, "MESSAGE SAVE: Launching coroutine to save message to database")
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    Log.d(TAG, "MESSAGE SAVE: Coroutine started (contactId=${contact.id}, contact=${contact.displayName})")
                    // Generate messageId from ENCRYPTED PAYLOAD (prevents ghost messages across both paths)
                    // Using encrypted bytes ensures same message arriving via both listener and pong has same ID
                    // Encrypted payload includes random nonce, so identical plaintexts get different IDs
                    val messageIdHash = java.security.MessageDigest.getInstance("SHA-256").digest(actualEncryptedMessage)
                    val messageId = "blob_" + android.util.Base64.encodeToString(messageIdHash, android.util.Base64.NO_WRAP).take(28)

                    Log.d(TAG, "MESSAGE SAVE: Message ID generated from encrypted payload hash: $messageId")

                    // Get database
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                    // Track this messageId to prevent duplicate processing (PRIMARY deduplication)
                    val messageTracking = com.securelegion.database.entities.ReceivedId(
                        receivedId = messageId,
                        idType = com.securelegion.database.entities.ReceivedId.TYPE_MESSAGE,
                        receivedTimestamp = System.currentTimeMillis()
                    )
                    Log.d(TAG, "MESSAGE SAVE: Attempting to insert messageId into ReceivedId tracking table...")
                    val rowId = tryInsertReceivedId(database, messageTracking, "MESSAGE")
                    Log.d(TAG, "MESSAGE SAVE: ReceivedId insert result: rowId=$rowId")

                    if (rowId == -1L) {
                        Log.w(TAG, "MESSAGE SAVE: DUPLICATE MESSAGE BLOB BLOCKED! MessageId=$messageId already in tracking table")
                        Log.i(TAG, "MESSAGE SAVE: Skipping duplicate message blob processing")

                        // Send MESSAGE_ACK to stop sender from retrying (with retry logic)
                        serviceScope.launch {
                            sendAckWithRetry(
                                connectionId = null,  // No existing connection available
                                itemId = messageId,
                                ackType = "MESSAGE_ACK",
                                contactId = contact.id
                            )
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

                    // If it's an image message, convert bytes to Base64 for storage
                    var imageBase64: String? = null
                    if (messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE) {
                        try {
                            val imageBytes = plaintext.toByteArray(Charsets.ISO_8859_1)
                            imageBase64 = android.util.Base64.encodeToString(imageBytes, android.util.Base64.NO_WRAP)
                            Log.d(TAG, "✓ Converted image to Base64: ${imageBase64.length} chars")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to convert image to Base64", e)
                            // Continue anyway
                        }
                    }

                    // Parse payment message fields
                    var paymentQuoteJson: String? = null
                    var paymentToken: String? = null
                    var paymentAmount: Long? = null
                    var paymentStatus: String? = null
                    var txSignature: String? = null
                    var receiveAddress: String? = null
                    var displayContent = plaintext

                    if (messageType in listOf(
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST,
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT,
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED
                    )) {
                        try {
                            val json = org.json.JSONObject(plaintext)
                            Log.d(TAG, "Parsing payment JSON: $plaintext")

                            when (messageType) {
                                com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST -> {
                                    // Format: {"type":"PAYMENT_REQUEST","quote":{...}}
                                    val quoteObj = json.optJSONObject("quote")
                                    if (quoteObj != null) {
                                        paymentQuoteJson = quoteObj.toString()
                                        paymentAmount = quoteObj.optLong("amount", 0)
                                        paymentToken = quoteObj.optString("token", "SOL")
                                        paymentStatus = com.securelegion.database.entities.Message.PAYMENT_STATUS_PENDING
                                        val formattedAmount = formatPaymentAmount(paymentAmount!!, paymentToken!!)
                                        displayContent = "Payment Request: $formattedAmount"
                                        Log.d(TAG, "✓ Parsed PAYMENT_REQUEST: $formattedAmount")
                                    }
                                }
                                com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT -> {
                                    // Format: {"type":"PAYMENT_SENT","quote_id":"...","tx_signature":"...","amount":...,"token":"..."}
                                    paymentAmount = json.optLong("amount", 0)
                                    paymentToken = json.optString("token", "SOL")
                                    txSignature = json.optString("tx_signature", null)
                                    paymentStatus = com.securelegion.database.entities.Message.PAYMENT_STATUS_PAID
                                    val formattedAmount = formatPaymentAmount(paymentAmount!!, paymentToken!!)
                                    displayContent = "Payment Received: $formattedAmount"
                                    Log.d(TAG, "✓ Parsed PAYMENT_SENT: $formattedAmount, tx=$txSignature")
                                }
                                com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> {
                                    // Format: {"type":"PAYMENT_ACCEPTED","quote_id":"...","receive_address":"...","amount":...,"token":"..."}
                                    paymentAmount = json.optLong("amount", 0)
                                    paymentToken = json.optString("token", "SOL")
                                    receiveAddress = json.optString("receive_address", null)
                                    paymentStatus = com.securelegion.database.entities.Message.PAYMENT_STATUS_PENDING
                                    val quoteId = json.optString("quote_id", "")
                                    val formattedAmount = formatPaymentAmount(paymentAmount!!, paymentToken!!)
                                    displayContent = "Payment Accepted: $formattedAmount"
                                    Log.d(TAG, "✓ Parsed PAYMENT_ACCEPTED: $formattedAmount to $receiveAddress")

                                    // Auto-execute the transfer!
                                    if (receiveAddress != null && paymentAmount > 0) {
                                        Log.i(TAG, "=== AUTO-EXECUTING PAYMENT TRANSFER ===")
                                        Log.i(TAG, "  Amount: $formattedAmount")
                                        Log.i(TAG, "  To: $receiveAddress")
                                        Log.i(TAG, "  Token: $paymentToken")

                                        // Find our original payment request using messageId pattern: pay_req_{quoteId}
                                        val originalMessageId = "pay_req_$quoteId"
                                        val originalRequest = database.messageDao().getMessageByMessageId(originalMessageId)

                                        if (originalRequest != null && originalRequest.isSentByMe) {
                                            Log.i(TAG, "  Found original request: ${originalRequest.messageId}")
                                            // Execute the blockchain transfer
                                            executePaymentTransfer(
                                                contact = contact,
                                                amount = paymentAmount!!,
                                                token = paymentToken!!,
                                                recipientAddress = receiveAddress,
                                                quoteId = quoteId,
                                                originalMessageId = originalRequest.messageId
                                            )
                                        } else {
                                            Log.e(TAG, "  Could not find original payment request for quote: $quoteId (messageId: $originalMessageId)")
                                        }
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to parse payment JSON", e)
                            displayContent = plaintext
                        }
                    }

                    // Check if this message is for an active download (associate with pingId)
                    val downloadPrefs = getSharedPreferences("active_downloads", MODE_PRIVATE)
                    val downloadPingId = downloadPrefs.getString("download_${contact.id}", null)
                    if (downloadPingId != null) {
                        Log.i(TAG, "⚡ Message associated with active download pingId: ${downloadPingId.take(8)}")
                    }

                    // Create message entity (store plaintext in encryptedContent field for now)
                    val message = com.securelegion.database.entities.Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = when (messageType) {
                            com.securelegion.database.entities.Message.MESSAGE_TYPE_TEXT -> plaintext
                            com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST,
                            com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT,
                            com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> displayContent
                            else -> ""
                        },
                        messageType = messageType,
                        attachmentType = if (messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE) "image" else null,
                        attachmentData = imageBase64, // Store Base64 image data for IMAGE messages
                        voiceDuration = voiceDuration,
                        voiceFilePath = voiceFilePath,
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = com.securelegion.database.entities.Message.STATUS_DELIVERED,
                        signatureBase64 = "", // TODO: Verify signature
                        nonceBase64 = "", // Not needed for already-decrypted messages
                        paymentQuoteJson = paymentQuoteJson,
                        paymentToken = paymentToken,
                        paymentAmount = paymentAmount,
                        paymentStatus = paymentStatus,
                        txSignature = txSignature,
                        pingId = downloadPingId  // ← Associate with download ping
                    )

                    // Save to database
                    Log.d(TAG, "MESSAGE SAVE: About to insert message into database")
                    Log.d(TAG, "  messageId=$messageId")
                    Log.d(TAG, "  contactId=${contact.id}")
                    Log.d(TAG, "  messageType=$messageType")
                    Log.d(TAG, "  content length=${message.encryptedContent.length}")
                    val savedMessageId = database.messageDao().insertMessage(message)
                    Log.i(TAG, "MESSAGE SAVE: Message saved to database successfully! DB row ID=$savedMessageId")

                    // If this was an active download, update ping state to READY for atomic swap
                    if (downloadPingId != null) {
                        val pingPrefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                        Log.i(TAG, "⚡ Setting ping ${downloadPingId.take(8)} to READY state (listener path)")
                        com.securelegion.models.PendingPing.updateState(
                            pingPrefs,
                            contact.id,
                            downloadPingId,
                            com.securelegion.models.PingState.READY,
                            synchronous = true
                        )

                        // Clear active download tracking
                        downloadPrefs.edit().remove("download_${contact.id}").commit()
                        Log.d(TAG, "  ✓ Cleared active download tracking for contact ${contact.id}")
                    }

                    // Send MESSAGE_ACK to sender to confirm receipt (with retry logic)
                    serviceScope.launch {
                        sendAckWithRetry(
                            connectionId = null,  // No existing connection available
                            itemId = messageId,
                            ackType = "MESSAGE_ACK",
                            contactId = contact.id
                        )
                    }

                    // Broadcast to ChatActivity so it can refresh and perform atomic swap (explicit broadcast)
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
                    Log.e(TAG, "MESSAGE SAVE: CRITICAL ERROR - Exception occurred while saving message!", e)
                    Log.e(TAG, "  contactId=${contact.id}")
                    Log.e(TAG, "  Exception type: ${e.javaClass.simpleName}")
                    Log.e(TAG, "  Exception message: ${e.message}")
                    e.printStackTrace()
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

            // NEW: Check if this is a Phase 1 PIN-encrypted message or old X25519-encrypted message
            // Phase 1 messages are PIN-encrypted and contain {"phase":1, ...}
            // Try to detect by attempting PIN decryption (user will need to provide PIN)

            Log.d(TAG, "Received friend request: ${encryptedFriendRequest.size} bytes")
            Log.d(TAG, "This appears to be a Phase 1 PIN-encrypted friend request")

            // For Phase 1, we need the user to provide the PIN to decrypt
            // So we save the encrypted payload and show it as a pending request
            // The user will enter the sender's PIN when they click "Accept"

            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)

            // Store in SharedPreferences as pending friend request (Phase 1)
            // We'll decrypt it when the user provides the PIN
            val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
            val existingRequests = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            // Create PendingFriendRequest with encrypted Phase 1 data
            // We'll show "New Friend Request" and decrypt when user provides PIN
            val pendingRequest = com.securelegion.models.PendingFriendRequest(
                displayName = "New Friend Request",  // Will get real name after PIN decryption
                ipfsCid = "",  // Not used in v2.0
                direction = com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING,
                status = com.securelegion.models.PendingFriendRequest.STATUS_PENDING,
                timestamp = System.currentTimeMillis(),
                contactCardJson = android.util.Base64.encodeToString(encryptedFriendRequest, android.util.Base64.NO_WRAP)  // Store encrypted Phase 1 data
            )

            // Add new request
            val updatedRequests = existingRequests.toMutableSet()
            updatedRequests.add(pendingRequest.toJson())
            prefs.edit().putStringSet("pending_requests_v2", updatedRequests).apply()

            Log.i(TAG, "Phase 1 friend request stored - total pending: ${updatedRequests.size}")

            // Show notification
            showFriendRequestNotification("New Friend Request")

            Log.i(TAG, "Decrypted friend request JSON: (Phase 1 - will decrypt with PIN later)")

            // Broadcast to update MainActivity badge count (explicit broadcast)
            val intent = Intent("com.securelegion.FRIEND_REQUEST_RECEIVED")
            intent.setPackage(packageName)
            sendBroadcast(intent)
            Log.d(TAG, "Broadcast FRIEND_REQUEST_RECEIVED to update badge")

        } catch (e: Exception) {
            Log.e(TAG, "Error handling friend request", e)
        }
    }

    /**
     * Handle incoming friend request accepted notification from pending outgoing request
     * This means someone accepted our friend request - add them to Contacts
     *
     * NEW (Phase 2): Receives full ContactCard encrypted with our X25519 key
     * OLD (v1.0): Receives FriendRequest with CID (for backward compatibility)
     */
    private fun handleFriendRequestAcceptedFromPending(senderX25519PublicKey: ByteArray, encryptedAcceptance: ByteArray) {
        try {
            Log.i(TAG, "╔════════════════════════════════════════")
            Log.i(TAG, "║  FRIEND REQUEST ACCEPTED (FROM PENDING)")
            Log.i(TAG, "╚════════════════════════════════════════")

            // Decrypt acceptance notification
            val wireMessage = senderX25519PublicKey + encryptedAcceptance
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val ourEd25519PublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            val decryptedJson = RustBridge.decryptMessage(
                wireMessage,
                ourEd25519PublicKey,
                ourPrivateKey
            )

            if (decryptedJson.isNullOrEmpty()) {
                Log.e(TAG, "Failed to decrypt acceptance notification")
                return
            }

            Log.d(TAG, "Decrypted JSON (first 200 chars): ${decryptedJson.take(200)}...")

            // Try to parse as NEW Phase 2 format with Kyber ciphertext (v2.1)
            var contactCard: com.securelegion.models.ContactCard? = null
            var kyberCiphertext: ByteArray? = null
            var isPhase2 = false

            try {
                val phase2Obj = org.json.JSONObject(decryptedJson)
                if (phase2Obj.has("phase") && phase2Obj.getInt("phase") == 2) {
                    // NEW Phase 2 format with contact_card + kyber_ciphertext
                    Log.d(TAG, "Parsing Phase 2 with Kyber ciphertext...")
                    val contactCardJson = phase2Obj.getJSONObject("contact_card").toString()
                    contactCard = com.securelegion.models.ContactCard.fromJson(contactCardJson)

                    // Extract Kyber ciphertext if present
                    if (phase2Obj.has("kyber_ciphertext")) {
                        val ciphertextBase64 = phase2Obj.getString("kyber_ciphertext")
                        kyberCiphertext = android.util.Base64.decode(ciphertextBase64, android.util.Base64.NO_WRAP)
                        Log.i(TAG, "✓ Phase 2 (quantum): Received ContactCard + Kyber ciphertext (${kyberCiphertext.size} bytes) from: ${contactCard.displayName}")
                    } else {
                        Log.i(TAG, "✓ Phase 2 (legacy): Received ContactCard from: ${contactCard.displayName}")
                    }

                    // Verify Ed25519 signature (defense-in-depth against .onion MitM)
                    if (phase2Obj.has("signature") && phase2Obj.has("ed25519_public_key")) {
                        val signature = android.util.Base64.decode(phase2Obj.getString("signature"), android.util.Base64.NO_WRAP)
                        val senderEd25519PublicKey = android.util.Base64.decode(phase2Obj.getString("ed25519_public_key"), android.util.Base64.NO_WRAP)

                        // Reconstruct unsigned JSON to verify signature
                        val unsignedJson = org.json.JSONObject().apply {
                            put("contact_card", phase2Obj.getJSONObject("contact_card"))
                            if (phase2Obj.has("kyber_ciphertext")) {
                                put("kyber_ciphertext", phase2Obj.getString("kyber_ciphertext"))
                            }
                            put("phase", 2)
                        }.toString()

                        val signatureValid = RustBridge.verifySignature(
                            unsignedJson.toByteArray(Charsets.UTF_8),
                            signature,
                            senderEd25519PublicKey
                        )

                        if (!signatureValid) {
                            Log.e(TAG, "❌ Phase 2 signature verification FAILED - rejecting contact (possible MitM attack)")
                            return
                        }
                        Log.i(TAG, "✓ Phase 2 signature verified (Ed25519)")
                    } else {
                        Log.w(TAG, "⚠️  Phase 2 has no signature (legacy response)")
                    }

                    isPhase2 = true
                } else {
                    // Try old Phase 2 format (just ContactCard)
                    contactCard = com.securelegion.models.ContactCard.fromJson(decryptedJson)
                    isPhase2 = true
                    Log.i(TAG, "✓ Phase 2 (old format): Received ContactCard from: ${contactCard.displayName}")
                }
            } catch (e: Exception) {
                Log.d(TAG, "Not a Phase 2 ContactCard, trying old v1.0 format... ${e.message}")
            }

            // PHASE 2 PATH: Full contact card received
            if (isPhase2 && contactCard != null) {
                Log.i(TAG, "Phase 2: Adding ${contactCard.displayName} to Contacts directly...")

                // Add contact to database
                try {
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

                    val contact = com.securelegion.database.entities.Contact(
                        displayName = contactCard.displayName,
                        solanaAddress = contactCard.solanaAddress,
                        publicKeyBase64 = android.util.Base64.encodeToString(
                            contactCard.solanaPublicKey,
                            android.util.Base64.NO_WRAP
                        ),
                        x25519PublicKeyBase64 = android.util.Base64.encodeToString(
                            contactCard.x25519PublicKey,
                            android.util.Base64.NO_WRAP
                        ),
                        kyberPublicKeyBase64 = android.util.Base64.encodeToString(
                            contactCard.kyberPublicKey,
                            android.util.Base64.NO_WRAP
                        ),
                        torOnionAddress = contactCard.messagingOnion,  // DEPRECATED - for backward compatibility
                        friendRequestOnion = contactCard.friendRequestOnion,  // NEW - public .onion for friend requests (port 9151)
                        messagingOnion = contactCard.messagingOnion,  // NEW - private .onion for messaging (port 8080)
                        voiceOnion = contactCard.voiceOnion,  // NEW - voice calling .onion (port 9152)
                        ipfsCid = contactCard.ipfsCid,
                        contactPin = contactCard.contactPin,
                        addedTimestamp = System.currentTimeMillis(),
                        lastContactTimestamp = System.currentTimeMillis(),
                        trustLevel = com.securelegion.database.entities.Contact.TRUST_UNTRUSTED,
                        friendshipStatus = com.securelegion.database.entities.Contact.FRIENDSHIP_CONFIRMED
                    )

                    val contactId = kotlinx.coroutines.runBlocking {
                        database.contactDao().insertContact(contact)
                    }

                    Log.i(TAG, "✓ Phase 2: Added ${contactCard.displayName} to Contacts (ID: $contactId)")

                    // Initialize key chain for progressive ephemeral key evolution
                    kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                        try {
                            val ourMessagingOnion = torManager.getOnionAddress()
                            val theirMessagingOnion = contact.messagingOnion ?: contactCard.messagingOnion
                            if (ourMessagingOnion.isNullOrEmpty() || theirMessagingOnion.isNullOrEmpty()) {
                                Log.e(TAG, "Cannot initialize key chain: missing onion address (ours=$ourMessagingOnion, theirs=$theirMessagingOnion) for ${contact.displayName}")
                            } else {
                                // Check if we have a saved shared secret from Phase 2 encapsulation
                                // This happens when Device B (accepter) receives Phase 2b from Device A (initiator)
                                var precomputedSharedSecret: ByteArray? = null
                                try {
                                    val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
                                    val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()
                                    val savedRequest = pendingRequestsSet.mapNotNull { requestJson ->
                                        try {
                                            com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                                        } catch (e: Exception) {
                                            null
                                        }
                                    }.find { it.ipfsCid == contactCard.friendRequestOnion }

                                    if (savedRequest != null && savedRequest.contactCardJson != null) {
                                        val savedData = org.json.JSONObject(savedRequest.contactCardJson)
                                        if (savedData.has("hybrid_shared_secret")) {
                                            val sharedSecretBase64 = savedData.getString("hybrid_shared_secret")
                                            precomputedSharedSecret = android.util.Base64.decode(sharedSecretBase64, android.util.Base64.NO_WRAP)
                                            Log.i(TAG, "✓ Found saved shared secret (${precomputedSharedSecret.size} bytes) from Phase 2 encapsulation")
                                        }
                                    }
                                } catch (e: Exception) {
                                    Log.w(TAG, "Could not load saved shared secret: ${e.message}")
                                }

                                // Initialize key chain with appropriate parameters
                                if (precomputedSharedSecret != null) {
                                    // Device B (accepter) path: Use shared secret from Phase 2 encapsulation
                                    com.securelegion.crypto.KeyChainManager.initializeKeyChain(
                                        context = this@TorService,
                                        contactId = contactId,
                                        theirX25519PublicKey = contactCard.x25519PublicKey,
                                        theirKyberPublicKey = contactCard.kyberPublicKey,
                                        ourMessagingOnion = ourMessagingOnion,
                                        theirMessagingOnion = theirMessagingOnion,
                                        precomputedSharedSecret = precomputedSharedSecret
                                    )
                                    Log.i(TAG, "✓ Key chain initialized for ${contact.displayName} (quantum - precomputed secret)")
                                } else if (kyberCiphertext != null) {
                                    // Device A (initiator) path: Decapsulate ciphertext from Phase 2
                                    com.securelegion.crypto.KeyChainManager.initializeKeyChain(
                                        context = this@TorService,
                                        contactId = contactId,
                                        theirX25519PublicKey = contactCard.x25519PublicKey,
                                        theirKyberPublicKey = contactCard.kyberPublicKey,
                                        ourMessagingOnion = ourMessagingOnion,
                                        theirMessagingOnion = theirMessagingOnion,
                                        kyberCiphertext = kyberCiphertext
                                    )
                                    Log.i(TAG, "✓ Key chain initialized for ${contact.displayName} (quantum - decapsulated)")
                                } else {
                                    // ERROR: Should NEVER reach here - we have Kyber keys but no quantum parameters!
                                    Log.e(TAG, "❌ CRITICAL BUG: Cannot initialize key chain - missing BOTH precomputedSharedSecret AND kyberCiphertext!")
                                    Log.e(TAG, "This will cause encryption mismatch - messages won't decrypt!")
                                    Log.e(TAG, "Contact has Kyber key: ${contactCard.kyberPublicKey.any { it != 0.toByte() }}")
                                    throw IllegalStateException("Cannot initialize key chain without quantum parameters")
                                }
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to initialize key chain for ${contact.displayName}", e)
                        }
                    }

                    // Send Phase 2b confirmation back to them
                    // This tells them we received their contact card and added them
                    kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                        try {
                            Log.d(TAG, "Sending Phase 2b confirmation to ${contactCard.displayName}")

                            // Build our contact card
                            val torManager = TorManager.getInstance(this@TorService)
                            val ownContactCard = com.securelegion.models.ContactCard(
                                displayName = keyManager.getUsername() ?: "Unknown",
                                solanaPublicKey = keyManager.getSolanaPublicKey(),
                                x25519PublicKey = keyManager.getEncryptionPublicKey(),
                                kyberPublicKey = keyManager.getKyberPublicKey(),
                                solanaAddress = keyManager.getSolanaAddress(),
                                friendRequestOnion = keyManager.getFriendRequestOnion() ?: "",
                                messagingOnion = keyManager.getMessagingOnion() ?: "",
                                voiceOnion = torManager.getVoiceOnionAddress() ?: "",
                                contactPin = keyManager.getContactPin() ?: "",
                                ipfsCid = keyManager.deriveContactListCID(),
                                timestamp = System.currentTimeMillis() / 1000
                            )

                            // Encrypt with their X25519 public key
                            val confirmationJson = ownContactCard.toJson()
                            val encryptedConfirmation = RustBridge.encryptMessage(
                                plaintext = confirmationJson,
                                recipientX25519PublicKey = contactCard.x25519PublicKey
                            )

                            // Send via their friend-request.onion
                            val success = RustBridge.sendFriendRequestAccepted(
                                recipientOnion = contactCard.friendRequestOnion,
                                encryptedAcceptance = encryptedConfirmation
                            )

                            if (success) {
                                Log.i(TAG, "✓ Sent Phase 2b confirmation to ${contactCard.displayName}")
                            } else {
                                Log.w(TAG, "Failed to send Phase 2b confirmation (they may be offline)")
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Error sending Phase 2b confirmation", e)
                        }
                    }

                    // Remove any pending outgoing requests to this friend
                    val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
                    val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
                    val updatedRequests = pendingRequestsV2.filter { requestJson ->
                        try {
                            val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                            // Keep requests that don't match this friend
                            request.displayName != contactCard.displayName ||
                            request.direction != com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING
                        } catch (e: Exception) {
                            true  // Keep if can't parse
                        }
                    }.toMutableSet()
                    prefs.edit().putStringSet("pending_requests_v2", updatedRequests).apply()

                    // Broadcast to update AddFriendActivity UI
                    val broadcastIntent = Intent("com.securelegion.FRIEND_REQUEST_RECEIVED")
                    broadcastIntent.setPackage(packageName)
                    sendBroadcast(broadcastIntent)
                    Log.d(TAG, "Broadcast sent to refresh UI after friend added")

                    // Show notification
                    showFriendRequestAcceptedNotification(contactCard.displayName)
                    return

                } catch (e: Exception) {
                    Log.e(TAG, "Failed to add Phase 2 contact to database", e)
                    return
                }
            }

            // OLD v1.0 PATH: Parse as FriendRequest (backward compatibility)
            val acceptance = try {
                com.securelegion.models.FriendRequest.fromJson(decryptedJson)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse as either Phase 2 or v1.0 format", e)
                return
            }

            Log.i(TAG, "v1.0: Acceptance from: ${acceptance.displayName}, CID: ${acceptance.ipfsCid}")

            // Find matching pending outgoing request
            val prefs = getSharedPreferences("friend_requests", MODE_PRIVATE)
            val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()
            val matchingRequest = pendingRequestsV2.mapNotNull { requestJson ->
                try {
                    com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                } catch (e: Exception) {
                    null
                }
            }.find {
                it.ipfsCid == acceptance.ipfsCid &&
                it.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING
            }

            if (matchingRequest == null) {
                Log.w(TAG, "No matching pending outgoing request found for CID: ${acceptance.ipfsCid}")
                return
            }

            Log.i(TAG, "Found matching pending request for: ${matchingRequest.displayName}")

            // Parse the saved contact card and add to Contacts
            if (matchingRequest.contactCardJson == null) {
                Log.w(TAG, "No contact card data saved with pending request - cannot add to Contacts")
                return
            }

            try {
                val contactCard = com.securelegion.models.ContactCard.fromJson(matchingRequest.contactCardJson)
                Log.d(TAG, "Parsed contact card for: ${contactCard.displayName}")

                // Add to Contacts database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

                val contact = com.securelegion.database.entities.Contact(
                    displayName = contactCard.displayName,
                    solanaAddress = contactCard.solanaAddress,
                    publicKeyBase64 = android.util.Base64.encodeToString(
                        contactCard.solanaPublicKey,
                        android.util.Base64.NO_WRAP
                    ),
                    x25519PublicKeyBase64 = android.util.Base64.encodeToString(
                        contactCard.x25519PublicKey,
                        android.util.Base64.NO_WRAP
                    ),
                    kyberPublicKeyBase64 = android.util.Base64.encodeToString(
                        contactCard.kyberPublicKey,
                        android.util.Base64.NO_WRAP
                    ),
                    torOnionAddress = contactCard.messagingOnion,  // DEPRECATED - for backward compatibility
                    friendRequestOnion = contactCard.friendRequestOnion,
                    messagingOnion = contactCard.messagingOnion,
                    voiceOnion = contactCard.voiceOnion,
                    ipfsCid = contactCard.ipfsCid,
                    contactPin = contactCard.contactPin,
                    addedTimestamp = System.currentTimeMillis(),
                    lastContactTimestamp = System.currentTimeMillis(),
                    trustLevel = com.securelegion.database.entities.Contact.TRUST_UNTRUSTED,
                    friendshipStatus = com.securelegion.database.entities.Contact.FRIENDSHIP_CONFIRMED
                )

                val contactId = kotlinx.coroutines.runBlocking {
                    database.contactDao().insertContact(contact)
                }

                Log.i(TAG, "✓ Added ${contactCard.displayName} to Contacts with CONFIRMED status (ID: $contactId)")

                // NOTE: This is the OLD v1.0 friend request handler (DEPRECATED)
                // Key chain initialization should happen in Phase 2 handler with quantum parameters
                // Do NOT initialize here - will cause encryption mismatch!
                Log.w(TAG, "⚠️  OLD v1.0 friend request path - key chain NOT initialized (use NEW Phase 1/2/2b flow)")

                // Remove from pending
                val newPendingSet = pendingRequestsV2.toMutableSet()
                newPendingSet.remove(matchingRequest.toJson())
                prefs.edit().putStringSet("pending_requests_v2", newPendingSet).apply()

                Log.i(TAG, "✓ Friend request accepted! ${acceptance.displayName} is now your friend")
                Log.i(TAG, "   Removed from pending requests, added to Contacts")

                // Broadcast to update AddFriendActivity UI
                val broadcastIntent = Intent("com.securelegion.FRIEND_REQUEST_RECEIVED")
                broadcastIntent.setPackage(packageName)
                sendBroadcast(broadcastIntent)
                Log.d(TAG, "Broadcast sent to refresh UI after friend added")

                // Show notification
                showFriendRequestAcceptedNotification(acceptance.displayName)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to add contact to database", e)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling friend request accepted from pending", e)
        }
    }

    /**
     * Handle incoming friend request accepted notification
     * This means someone accepted our friend request - update their status to CONFIRMED
     */
    private fun handleFriendRequestAccepted(contact: com.securelegion.database.entities.Contact, senderX25519PublicKey: ByteArray, encryptedAcceptance: ByteArray) {
        try {
            Log.i(TAG, "╔════════════════════════════════════════")
            Log.i(TAG, "║  FRIEND REQUEST ACCEPTED RECEIVED")
            Log.i(TAG, "╚════════════════════════════════════════")
            Log.d(TAG, "Contact: ${contact.displayName}, Current status: ${contact.friendshipStatus}")

            // Reconstruct wire format for decryption: [Sender X25519 - 32 bytes][Encrypted Data]
            val wireMessage = senderX25519PublicKey + encryptedAcceptance

            Log.d(TAG, "Reconstructed wire message: ${wireMessage.size} bytes")

            try {
                // Decrypt acceptance notification (same as friend request decryption)
                // decryptMessage will derive X25519 private key from Ed25519
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
                val ourEd25519PublicKey = keyManager.getSigningPublicKey()
                val ourPrivateKey = keyManager.getSigningKeyBytes()

                Log.d(TAG, "Attempting to decrypt acceptance notification...")
                val decryptedJson = RustBridge.decryptMessage(
                    wireMessage,
                    ourEd25519PublicKey,
                    ourPrivateKey
                )

                if (decryptedJson.isNullOrEmpty()) {
                    Log.e(TAG, "Failed to decrypt friend request accepted notification - null result")
                    return
                }

                Log.i(TAG, "✓ Decrypted acceptance notification from ${contact.displayName}")
                Log.d(TAG, "Decrypted JSON: $decryptedJson")

            } catch (e: Exception) {
                Log.e(TAG, "Exception during decryption", e)
                return
            }

            // Update contact status to CONFIRMED
            try {
                Log.d(TAG, "Updating contact status to CONFIRMED...")
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

                val updatedContact = contact.copy(
                    friendshipStatus = com.securelegion.database.entities.Contact.FRIENDSHIP_CONFIRMED
                )

                kotlinx.coroutines.runBlocking {
                    Log.d(TAG, "Calling database updateContact...")
                    database.contactDao().updateContact(updatedContact)
                    Log.d(TAG, "Database update completed")
                }

                Log.i(TAG, "✓ Updated ${contact.displayName} to CONFIRMED status - you are now mutual friends!")

                // Show notification
                Log.d(TAG, "Showing acceptance notification...")
                showFriendRequestAcceptedNotification(contact.displayName)
                Log.d(TAG, "Notification shown successfully")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to update contact status to CONFIRMED", e)
                Log.e(TAG, "Stack trace:", e)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling friend request accepted", e)
            Log.e(TAG, "Stack trace:", e)
        }
    }

    /**
     * Show notification for new friend request
     */
    private fun showFriendRequestNotification(senderName: String) {
        try {
            // Generate consistent notification ID per contact name
            // Use hashCode to create stable ID for each unique sender
            val friendRequestNotificationId = 5000 + Math.abs(senderName.hashCode() % 10000)

            // Check if user is already unlocked - if so, go directly to MainActivity
            val isUnlocked = com.securelegion.utils.SessionManager.isUnlocked(this)

            val intent = if (isUnlocked) {
                // User is already logged in - go directly to MainActivity
                android.content.Intent(this, com.securelegion.MainActivity::class.java).apply {
                    putExtra("SHOW_FRIEND_REQUESTS", true)
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                }
            } else {
                // User is locked - go through LockActivity
                android.content.Intent(this, com.securelegion.LockActivity::class.java).apply {
                    putExtra("TARGET_ACTIVITY", "MainActivity")
                    putExtra("SHOW_FRIEND_REQUESTS", true)
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                }
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
                .setGroup("FRIEND_REQUESTS")
                .build()

            val notificationManager = getSystemService(android.app.NotificationManager::class.java)
            notificationManager.notify(friendRequestNotificationId, notification)

            Log.i(TAG, "Friend request notification shown for $senderName (ID: $friendRequestNotificationId)")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show friend request notification", e)
        }
    }

    /**
     * Send friend request accepted response
     * Used when someone resends a friend request and we already have them confirmed
     */
    private fun sendFriendRequestAcceptedResponse(recipientContactCard: com.securelegion.models.ContactCard) {
        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
            try {
                Log.d(TAG, "Sending FRIEND_REQUEST_ACCEPTED response to ${recipientContactCard.displayName}")

                // Get own account information
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                val ownDisplayName = keyManager.getUsername()
                    ?: throw Exception("Username not set")
                val ownCid = keyManager.getIPFSCID()
                    ?: throw Exception("IPFS CID not found")

                // Create acceptance notification
                val acceptance = com.securelegion.models.FriendRequest(
                    displayName = ownDisplayName,
                    ipfsCid = ownCid
                )

                // Serialize to JSON
                val acceptanceJson = acceptance.toJson()

                // Encrypt the acceptance using recipient's X25519 public key
                val encryptedAcceptance = com.securelegion.crypto.RustBridge.encryptMessage(
                    plaintext = acceptanceJson,
                    recipientX25519PublicKey = recipientContactCard.x25519PublicKey
                )

                // Send via Tor
                val success = com.securelegion.crypto.RustBridge.sendFriendRequestAccepted(
                    recipientOnion = recipientContactCard.friendRequestOnion,
                    encryptedAcceptance = encryptedAcceptance
                )

                if (success) {
                    Log.i(TAG, "✓ Sent FRIEND_REQUEST_ACCEPTED response to ${recipientContactCard.displayName}")
                } else {
                    Log.w(TAG, "Failed to send acceptance response (recipient may be offline)")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error sending friend request accepted response", e)
            }
        }
    }

    /**
     * Show notification for friend request accepted
     */
    private fun showFriendRequestAcceptedNotification(contactName: String) {
        try {
            // Generate consistent notification ID per contact name
            // Use hashCode to create stable ID for each unique contact (different range from friend requests)
            val acceptedNotificationId = 6000 + Math.abs(contactName.hashCode() % 10000)

            // Check if user is already unlocked - if so, go directly to MainActivity
            val isUnlocked = com.securelegion.utils.SessionManager.isUnlocked(this)

            val intent = if (isUnlocked) {
                // User is already logged in - go directly to MainActivity
                android.content.Intent(this, com.securelegion.MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                }
            } else {
                // User is locked - go through LockActivity
                android.content.Intent(this, com.securelegion.LockActivity::class.java).apply {
                    putExtra("TARGET_ACTIVITY", "MainActivity")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                }
            }

            val pendingIntent = android.app.PendingIntent.getActivity(
                this,
                0,
                intent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            )

            val notification = androidx.core.app.NotificationCompat.Builder(this, AUTH_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_friends)
                .setContentTitle("Friend Request Accepted!")
                .setContentText("$contactName accepted your friend request")
                .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
                .setCategory(androidx.core.app.NotificationCompat.CATEGORY_SOCIAL)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .setGroup("FRIEND_REQUESTS")
                .build()

            val notificationManager = getSystemService(android.app.NotificationManager::class.java)
            notificationManager.notify(acceptedNotificationId, notification)

            Log.i(TAG, "Friend request accepted notification shown for $contactName (ID: $acceptedNotificationId)")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show friend request accepted notification", e)
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
    private suspend fun storePendingPing(pingId: String, connectionId: Long, senderPublicKey: ByteArray?, senderName: String, encryptedPingWire: ByteArray): Long? {
        return withContext(Dispatchers.IO) {
            try {
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                // Find contact by public key
                if (senderPublicKey != null) {
                    val publicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)
                    Log.d(TAG, "Looking up contact by public key (Base64, first 20 chars): ${publicKeyBase64.take(20)}...")

                    // Debug: List all contacts and their public keys
                    val allContacts = database.contactDao().getAllContacts()
                    Log.d(TAG, "Total contacts in database: ${allContacts.size}")
                    for (c in allContacts) {
                        Log.d(TAG, "  Contact: ${c.displayName}, PubKey (first 20 chars): ${c.publicKeyBase64.take(20)}...")
                    }

                    val contact = database.contactDao().getContactByPublicKey(publicKeyBase64)

                    if (contact != null) {
                        // Store pending Ping in queue (NEW: supports multiple pings per contact)
                        val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
                        val encryptedPingBase64 = android.util.Base64.encodeToString(encryptedPingWire, android.util.Base64.NO_WRAP)

                        val pendingPing = com.securelegion.models.PendingPing(
                            pingId = pingId,
                            connectionId = connectionId,
                            senderName = senderName,
                            timestamp = System.currentTimeMillis(),
                            encryptedPingData = encryptedPingBase64,
                            senderOnionAddress = contact.messagingOnion ?: contact.torOnionAddress ?: ""
                        )

                        com.securelegion.models.PendingPing.addToQueue(prefs, contact.id, pendingPing)
                        Log.i(TAG, "Added Ping $pingId to queue for contact ${contact.id}: $senderName")
                        return@withContext contact.id  // Return contact ID for broadcast
                    } else {
                        Log.w(TAG, "Cannot store Ping - sender not in contacts: $senderName")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to store pending Ping", e)
            }
            return@withContext null  // Failed to find/store contact
        }
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
                            contact.messagingOnion ?: contact.torOnionAddress ?: ""
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
        // Check if user is already unlocked - if so, go directly to MainActivity
        // If locked, go through LockActivity for authentication
        val isUnlocked = com.securelegion.utils.SessionManager.isUnlocked(this)

        val openAppIntent = if (isUnlocked) {
            // User is already logged in - go directly to MainActivity
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
        } else {
            // User is locked - go through LockActivity
            Intent(this, LockActivity::class.java).apply {
                putExtra("TARGET_ACTIVITY", "MainActivity")
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
        }

        val openAppPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Get pending message count (new format: ping_queue_<contactId>)
        val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)

        // Count total pings across all contacts
        var pendingCount = 0
        prefs.all.forEach { (key, value) ->
            if (key.startsWith("ping_queue_") && value is String) {
                try {
                    val jsonArray = org.json.JSONArray(value)
                    pendingCount += jsonArray.length()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse ping queue for key $key", e)
                }
            }
        }

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
                // Generate messageId from ENCRYPTED MESSAGE (consistent with PATH 1)
                // This ensures same message arriving via both paths has same ID
                val messageIdHash = java.security.MessageDigest.getInstance("SHA-256").digest(encryptedMessage)
                val deterministicMessageId = "blob_" + android.util.Base64.encodeToString(messageIdHash, android.util.Base64.NO_WRAP).take(28)

                Log.d(TAG, "Message ID generated from encrypted payload hash: $deterministicMessageId")

                // Track this messageId to prevent duplicate processing (PRIMARY deduplication)
                val messageTracking = com.securelegion.database.entities.ReceivedId(
                    receivedId = deterministicMessageId,
                    idType = com.securelegion.database.entities.ReceivedId.TYPE_MESSAGE,
                    receivedTimestamp = System.currentTimeMillis()
                )
                val rowId = tryInsertReceivedId(database, messageTracking, "MESSAGE")

                if (rowId == -1L) {
                    Log.w(TAG, "⚠️  DUPLICATE MESSAGE BLOCKED! MessageId=$deterministicMessageId already in tracking table")
                    Log.i(TAG, "→ Skipping duplicate message processing, but will send MESSAGE_ACK")

                    // Send MESSAGE_ACK to stop sender from retrying (with retry logic)
                    serviceScope.launch {
                        sendAckWithRetry(
                            connectionId = null,  // No existing connection available
                            itemId = deterministicMessageId,
                            ackType = "MESSAGE_ACK",
                            contactId = contact.id
                        )
                    }

                    // Clear pending Ping from SharedPreferences (even for duplicates)
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
                    Log.i(TAG, "✓ Cleared pending Ping for contact ${contact.id} (duplicate message)")

                    // Update notification to reflect new pending count (will cancel if 0)
                    showNewMessageNotification()

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

                // Send MESSAGE_ACK to sender to confirm receipt (with retry logic)
                serviceScope.launch {
                    sendAckWithRetry(
                        connectionId = null,  // No existing connection available
                        itemId = deterministicMessageId,
                        ackType = "MESSAGE_ACK",
                        contactId = contact.id
                    )
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
                Log.i(TAG, "✓ Cleared pending Ping for contact ${contact.id} after message download")

                // Update notification to reflect new pending count (will cancel if 0)
                showNewMessageNotification()

                // Broadcast to update ChatActivity if it's open for this contact
                val messageReceivedIntent = Intent("com.securelegion.MESSAGE_RECEIVED").apply {
                    setPackage(packageName)
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

        // Use unique notification ID per MESSAGE (not per contact)
        // Each message gets its own notification that can be dismissed independently
        // Use current time millis to ensure uniqueness
        val messageNotificationId = (System.currentTimeMillis() % 100000).toInt() + 10000

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
            .setGroup("MESSAGES_${contactId}") // Group messages by contact
            .build()

        // Show notification - each message gets unique ID
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(messageNotificationId, notification)

        Log.i(TAG, "Message notification shown for $senderName (unique ID: $messageNotificationId)")
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
        Log.i(TAG, "Stopping Tor service and Tor daemon")

        isServiceRunning = false
        running = false
        listenersReady = false
        torConnected = false

        // Stop bandwidth monitoring
        stopBandwidthMonitoring()

        // Stop all listeners
        try {
            RustBridge.stopListeners()
            Log.d(TAG, "Stopped all listeners")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop listeners", e)
        }

        // Check if this is a bridge configuration change
        val prefs = getSharedPreferences("tor_settings", MODE_PRIVATE)
        val bridgeConfigChanged = prefs.getBoolean("bridge_config_changed", false)

        if (bridgeConfigChanged) {
            // Reset TorManager state to force re-initialization
            Log.i(TAG, "Bridge config changed - resetting TorManager state")
            torManager.resetInitializationState()
        }

        // Stop Tor daemon via JNI
        try {
            val stopIntent = Intent(this, org.torproject.jni.TorService::class.java)
            stopIntent.action = "org.torproject.android.intent.action.STOP"
            startService(stopIntent)
            Log.i(TAG, "Sent stop command to Tor daemon")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop Tor daemon", e)
        }

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
            // Tor service channel (minimal priority - shows only shield icon in status bar)
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_MIN
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
                description = "Friend requests and message approvals"
                setShowBadge(true)
                enableVibration(true)
                enableLights(true)
                setSound(
                    android.provider.Settings.System.DEFAULT_NOTIFICATION_URI,
                    android.media.AudioAttributes.Builder()
                        .setUsage(android.media.AudioAttributes.USAGE_NOTIFICATION)
                        .setContentType(android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build()
                )
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
            .setSmallIcon(R.drawable.ic_notification_logo)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)

        // Only show notification text for problem states
        // Normal "Connected" state shows bandwidth stats
        if (isProblemState) {
            builder.setContentTitle("Secure Legion")
                   .setContentText(status)
                   .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        } else {
            // Connected state - show bandwidth stats
            if (vpnActive) {
                // VPN enabled - show combined stats
                val messagingDown = formatBytes(currentDownloadSpeed)
                val messagingUp = formatBytes(currentUploadSpeed)
                val vpnDown = formatBytesTotal(vpnBytesReceived)
                val vpnUp = formatBytesTotal(vpnBytesSent)

                builder.setContentTitle("🛡️ Secure Legion")
                       .setContentText("Messaging: ↓ $messagingDown ↑ $messagingUp\nVPN: ↓ $vpnDown ↑ $vpnUp")
                       .setStyle(NotificationCompat.BigTextStyle()
                           .bigText("Messaging Tor: ↓ $messagingDown / ↑ $messagingUp\nDevice VPN: ↓ $vpnDown / ↑ $vpnUp"))
                       .setPriority(NotificationCompat.PRIORITY_MIN)
                       .setShowWhen(false)
                       .setSilent(true)
            } else {
                // VPN disabled - show only messaging stats
                val downloadSpeed = formatBytes(currentDownloadSpeed)
                val uploadSpeed = formatBytes(currentUploadSpeed)

                builder.setContentTitle("Connected to the Tor Network")
                       .setContentText("↓ $downloadSpeed / ↑ $uploadSpeed")
                       .setPriority(NotificationCompat.PRIORITY_MIN)
                       .setShowWhen(false)
                       .setSilent(true)
            }
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

    // ==================== VOICE SERVICE ====================

    /**
     * Initialize voice streaming service
     * - Creates voice hidden service .onion address
     * - Registers VoiceCallManager as packet callback
     * - Starts voice streaming server on port 9152
     */
    private fun startVoiceService() {
        Log.i(TAG, "startVoiceService() called")
        try {
            // Get VoiceCallManager singleton instance
            Log.d(TAG, "Getting VoiceCallManager instance...")
            val voiceCallManager = com.securelegion.voice.VoiceCallManager.getInstance(applicationContext)

            // Register as voice packet callback for incoming voice packets
            Log.d(TAG, "Setting voice packet callback...")
            RustBridge.setVoicePacketCallback(voiceCallManager)

            // Register signaling callback for CALL_OFFER/CALL_ANSWER messages over voice onion
            Log.d(TAG, "Setting voice signaling callback...")
            RustBridge.setVoiceSignalingCallback(object : RustBridge.VoiceSignalingCallback {
                override fun onSignalingMessage(senderPubkey: ByteArray, wireMessage: ByteArray) {
                    Log.i(TAG, "Voice signaling message received via HTTP: ${wireMessage.size} bytes")

                    // Wire format: [Type][Sender X25519 Pubkey - 32 bytes][Encrypted Message]
                    if (wireMessage.size < 33) {
                        Log.e(TAG, "Invalid signaling message: too short (${wireMessage.size} bytes)")
                        return
                    }

                    // Extract encrypted payload (skip type byte + 32 byte pubkey)
                    val encryptedPayload = wireMessage.copyOfRange(33, wireMessage.size)

                    // Lookup contact by X25519 public key
                    kotlinx.coroutines.GlobalScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                        try {
                            val keyManager = com.securelegion.crypto.KeyManager.getInstance(applicationContext)
                            val dbPassphrase = keyManager.getDatabasePassphrase()
                            val database = com.securelegion.database.SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)

                            val contact = database.contactDao().getContactByX25519PublicKey(
                                android.util.Base64.encodeToString(senderPubkey, android.util.Base64.NO_WRAP)
                            )

                            if (contact == null) {
                                Log.w(TAG, "⚠️  Cannot process signaling - contact not found for X25519 key")
                                return@launch
                            }

                            val senderOnion = contact.voiceOnion ?: contact.messagingOnion ?: contact.torOnionAddress ?: ""
                            if (senderOnion.isEmpty()) {
                                Log.w(TAG, "⚠️  Cannot process signaling - no onion address for contact ${contact.id}")
                                return@launch
                            }

                            // Process call signaling through MessageService
                            val messageService = MessageService(applicationContext)
                            val encryptedPayloadBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                            messageService.handleCallSignaling(
                                encryptedData = encryptedPayloadBase64,
                                senderPublicKey = senderPubkey,
                                senderOnionAddress = senderOnion,
                                contactId = contact.id
                            )
                            Log.i(TAG, "✓ Voice signaling message processed via HTTP")
                        } catch (e: Exception) {
                            Log.e(TAG, "Error processing voice signaling message", e)
                        }
                    }
                }
            })
            Log.i(TAG, "✓ Voice signaling callback registered")

            // CRITICAL: Start VOICE TOR first (separate Tor instance with Single Onion Service)
            // This Tor runs on port 9052 with HiddenServiceNonAnonymousMode 1 for 3-hop latency
            val torManager = com.securelegion.crypto.TorManager.getInstance(applicationContext)
            Log.i(TAG, "Starting VOICE Tor instance (Single Onion Service mode)...")
            val voiceTorStarted = torManager.startVoiceTor()
            if (!voiceTorStarted) {
                Log.e(TAG, "Failed to start voice Tor - cannot create voice hidden service")
                return
            }
            Log.i(TAG, "✓ Voice Tor started successfully (3-hop Single Onion Service)")

            // IMPORTANT: Start voice streaming server SECOND (bind to localhost:9152)
            // This must happen BEFORE creating the hidden service, otherwise Tor will try
            // to route traffic to a port that isn't listening yet
            Log.d(TAG, "Starting voice streaming server on localhost:9152...")
            RustBridge.startVoiceStreamingServer()
            Log.i(TAG, "✓ Voice streaming server started on localhost:9152")

            // Read voice onion address from torrc-generated hostname file
            // (Single Onion Services don't support ADD_ONION, must be configured in torrc)
            Log.i(TAG, "Reading voice onion address from torrc-generated hostname file...")
            val hostnameFile = File(filesDir, "voice_tor/voice_hidden_service/hostname")

            // Wait for hostname file to be created by Tor (max 30 seconds)
            var attempts = 0
            while (!hostnameFile.exists() && attempts < 30) {
                Thread.sleep(1000)
                attempts++
            }

            if (!hostnameFile.exists()) {
                Log.e(TAG, "❌ Voice hidden service hostname file not found after 30s")
                throw Exception("Voice Tor did not create hostname file")
            }

            val voiceOnion = hostnameFile.readText().trim()
            Log.i(TAG, "✓ Voice onion address from torrc: $voiceOnion")

            // Check if this is different from what's stored
            val existingVoiceOnion = torManager.getVoiceOnionAddress()
            if (existingVoiceOnion != voiceOnion) {
                Log.i(TAG, "Voice onion changed from $existingVoiceOnion to $voiceOnion - updating...")
                torManager.saveVoiceOnionAddress(voiceOnion)
            } else {
                Log.i(TAG, "Voice onion address unchanged: $voiceOnion")
            }

            Log.i(TAG, "✓ Voice streaming service fully initialized")
        } catch (e: Exception) {
            Log.e(TAG, "❌ CRITICAL ERROR initializing voice service: ${e.message}", e)
            e.printStackTrace()
        }
    }

    // ==================== BANDWIDTH MONITORING ====================

    /**
     * Start monitoring network bandwidth and updating notification
     * Updates every 2s when app open, 10s when app closed (saves battery)
     */
    private fun startBandwidthMonitoring() {
        // Initialize baseline
        lastRxBytes = android.net.TrafficStats.getTotalRxBytes()
        lastTxBytes = android.net.TrafficStats.getTotalTxBytes()
        lastBandwidthUpdate = System.currentTimeMillis()

        // Create update runnable
        bandwidthUpdateRunnable = object : Runnable {
            override fun run() {
                updateBandwidthStats()
                // Update notification with current speeds
                updateNotification("Connected to the Tor Network")

                // Adaptive update interval: fast when app open, slow when closed
                val updateInterval = if (isAppInForeground) {
                    BANDWIDTH_UPDATE_FAST  // 5 seconds
                } else {
                    BANDWIDTH_UPDATE_SLOW  // 10 seconds (saves battery)
                }

                // Schedule next update
                bandwidthHandler.postDelayed(this, updateInterval)
            }
        }

        // Start monitoring
        bandwidthHandler.post(bandwidthUpdateRunnable!!)
        Log.d(TAG, "Bandwidth monitoring started")
    }

    /**
     * Update foreground state (called by activities)
     * Adjusts bandwidth update frequency
     */
    fun setAppInForeground(inForeground: Boolean) {
        if (isAppInForeground != inForeground) {
            isAppInForeground = inForeground
            Log.d(TAG, "App foreground state changed: $inForeground (bandwidth updates: ${if (inForeground) "fast (5s)" else "slow (10s)"})")
        }
    }

    /**
     * Stop bandwidth monitoring
     */
    private fun stopBandwidthMonitoring() {
        bandwidthUpdateRunnable?.let {
            bandwidthHandler.removeCallbacks(it)
        }
        bandwidthUpdateRunnable = null
        currentDownloadSpeed = 0
        currentUploadSpeed = 0
        Log.d(TAG, "Bandwidth monitoring stopped")
    }

    /**
     * Update bandwidth statistics
     * Calculates download/upload speeds based on traffic since last update
     */
    private fun updateBandwidthStats() {
        val now = System.currentTimeMillis()
        val currentRxBytes = android.net.TrafficStats.getTotalRxBytes()
        val currentTxBytes = android.net.TrafficStats.getTotalTxBytes()

        // Calculate time delta (in seconds)
        val timeDelta = (now - lastBandwidthUpdate) / 1000.0
        if (timeDelta <= 0) return  // Avoid division by zero

        // Calculate bytes transferred since last update
        val rxDelta = currentRxBytes - lastRxBytes
        val txDelta = currentTxBytes - lastTxBytes

        // Calculate speeds (bytes per second)
        currentDownloadSpeed = (rxDelta / timeDelta).toLong()
        currentUploadSpeed = (txDelta / timeDelta).toLong()

        // Update for next iteration
        lastRxBytes = currentRxBytes
        lastTxBytes = currentTxBytes
        lastBandwidthUpdate = now
    }

    /**
     * Format bytes into human-readable speed string
     * Examples: "1.2 MiB/s", "456 KiB/s", "12 B/s"
     */
    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.1f MiB/s", bytes / (1024.0 * 1024.0))
            bytes >= 1024 -> String.format("%.0f KiB/s", bytes / 1024.0)
            else -> "$bytes B/s"
        }
    }

    /**
     * Format total bytes (not speed) into human-readable string
     * Examples: "1.2 MB", "456 KB", "12 B"
     */
    private fun formatBytesTotal(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
            bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
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
                // attemptReconnect() will call sendTapsToAllContacts() after successful reconnection
                if (!torConnected && !isReconnecting) {
                    Log.i(TAG, "Network restored - attempting immediate Tor reconnection")
                    reconnectHandler.post {
                        attemptReconnect()
                    }
                } else if (torConnected) {
                    // Tor thinks it's connected - wait for Tor circuits to rebuild before sending TAPs
                    // This handles the case where airplane mode didn't trigger onLost() fast enough
                    Log.i(TAG, "Network restored while Tor still connected - waiting 45 seconds for Tor circuits to stabilize")

                    reconnectHandler.postDelayed({
                        Log.i(TAG, "Tor circuits should be ready - sending TAPs and checking pending messages")
                        sendTapsToAllContacts()

                        // Also trigger immediate retry for any pending messages
                        CoroutineScope(Dispatchers.IO).launch {
                            try {
                                val messageService = MessageService(this@TorService)
                                // This will check both STATUS_PENDING and STATUS_PING_SENT messages
                                val pongResult = messageService.pollForPongsAndSendMessages()
                                if (pongResult.isSuccess) {
                                    val sentCount = pongResult.getOrNull() ?: 0
                                    if (sentCount > 0) {
                                        Log.i(TAG, "Network restored: Sent $sentCount pending messages")
                                    }
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Error checking pending messages after network restore", e)
                            }
                        }
                    }, 45000) // 45 second delay for Tor circuit stabilization
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

        // Also listen for airplane mode changes (NetworkCallback doesn't always fire for this)
        val airplaneModeFilter = IntentFilter(Intent.ACTION_AIRPLANE_MODE_CHANGED)
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == Intent.ACTION_AIRPLANE_MODE_CHANGED) {
                    val isAirplaneModeOn = intent.getBooleanExtra("state", false)
                    Log.i(TAG, "Airplane mode changed: ${if (isAirplaneModeOn) "ON" else "OFF"}")

                    // Give the system a moment to settle
                    reconnectHandler.postDelayed({
                        // Check actual network state
                        val network = connectivityManager?.activeNetwork
                        val caps = connectivityManager?.getNetworkCapabilities(network)
                        val hasInternet = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true

                        if (!isAirplaneModeOn && hasInternet && torConnected) {
                            // Airplane mode turned OFF and network is back
                            // Wait 45 seconds for Tor circuits to rebuild before sending TAPs
                            Log.i(TAG, "Airplane mode disabled - network restored, waiting 45 seconds for Tor circuits to stabilize before sending TAPs")

                            reconnectHandler.postDelayed({
                                Log.i(TAG, "Tor circuits should be ready - sending TAPs now")
                                sendTapsToAllContacts()

                                // Also retry pending messages
                                CoroutineScope(Dispatchers.IO).launch {
                                    try {
                                        val messageService = MessageService(this@TorService)
                                        val pongResult = messageService.pollForPongsAndSendMessages()
                                        if (pongResult.isSuccess) {
                                            val sentCount = pongResult.getOrNull() ?: 0
                                            if (sentCount > 0) {
                                                Log.i(TAG, "Airplane mode restored: Sent $sentCount pending messages")
                                            }
                                        }
                                    } catch (e: Exception) {
                                        Log.e(TAG, "Error checking pending messages after airplane mode", e)
                                    }
                                }
                            }, 45000) // 45 second delay for Tor circuit stabilization
                        } else if (isAirplaneModeOn) {
                            Log.w(TAG, "Airplane mode enabled - network unavailable")
                            hasNetworkConnection = false
                        }
                    }, 2000) // 2 second delay to let network stabilize
                }
            }
        }, airplaneModeFilter)
        Log.d(TAG, "Airplane mode monitoring registered")
    }

    private fun setupVpnBroadcastReceiver() {
        vpnBroadcastReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == ACTION_VPN_BANDWIDTH_UPDATE) {
                    vpnBytesReceived = intent.getLongExtra(EXTRA_VPN_RX_BYTES, 0L)
                    vpnBytesSent = intent.getLongExtra(EXTRA_VPN_TX_BYTES, 0L)
                    vpnActive = intent.getBooleanExtra(EXTRA_VPN_ACTIVE, false)

                    // Update notification with new VPN stats
                    if (torConnected) {
                        updateNotification("Connected to the Tor Network")
                    }
                }
            }
        }

        val filter = android.content.IntentFilter(ACTION_VPN_BANDWIDTH_UPDATE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnBroadcastReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnBroadcastReceiver, filter)
        }
        Log.d(TAG, "VPN broadcast receiver registered")
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

                // Ensure incoming listener is running when connected
                if (!isListenerRunning) {
                    Log.w(TAG, "Health check: Listener not running but Tor is connected - restarting listener")
                    startIncomingListener()
                }
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
     * Record a download failure and restart listeners if threshold reached
     */
    fun recordDownloadFailure() {
        val now = System.currentTimeMillis()

        // Start new tracking window if needed
        if (downloadFailureWindowStart == 0L || (now - downloadFailureWindowStart) > 300000L) {
            downloadFailureWindowStart = now
            downloadFailureCount = 1
            Log.w(TAG, "Download failure recorded (starting new 5-minute window)")
            return
        }

        // Increment count within window
        downloadFailureCount++
        Log.w(TAG, "Download failure recorded (count: $downloadFailureCount in ${(now - downloadFailureWindowStart) / 1000}s)")

        // If 3 failures within 5 minutes, restart listeners
        if (downloadFailureCount >= 3) {
            Log.e(TAG, "Multiple download failures detected ($downloadFailureCount in 5 minutes) - restarting listeners")
            restartListeners()
            // Reset counters
            downloadFailureCount = 0
            downloadFailureWindowStart = 0L
        }
    }

    /**
     * Restart incoming listeners to recover from broken state
     */
    private fun restartListeners() {
        Thread {
            try {
                Log.i(TAG, "Restarting all listeners...")
                updateNotification("Restarting listeners...")

                // Stop all listeners
                RustBridge.stopListeners()
                Thread.sleep(2000)  // Wait 2s for cleanup

                // Restart incoming listener
                Log.i(TAG, "Starting incoming listener...")
                startIncomingListener()

                Log.i(TAG, "✓ Listeners restarted successfully")
                updateNotification("Connected to Tor")

                // Show toast to user
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    com.securelegion.utils.ThemedToast.show(this, "Connection reset - please try again")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to restart listeners", e)
                updateNotification("Restart failed - check connection")
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

        // Cancel all protocol operations and clean up coroutine scope
        serviceScope.cancel()
        protocolDispatcher.close()

        // Clear instance
        instance = null

        // Cancel AlarmManager restart checks
        cancelServiceRestart()

        // Clean up handlers
        reconnectHandler.removeCallbacksAndMessages(null)
        bandwidthHandler.removeCallbacksAndMessages(null)

        // Unregister network callback
        try {
            networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Error unregistering network callback", e)
        }

        // Unregister VPN broadcast receiver
        try {
            vpnBroadcastReceiver?.let { unregisterReceiver(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Error unregistering VPN broadcast receiver", e)
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

    /**
     * Format payment amount for display
     * Converts lamports/zatoshis to human-readable format
     */
    private fun formatPaymentAmount(amount: Long, token: String): String {
        val decimals = when (token.uppercase()) {
            "SOL" -> 9
            "ZEC" -> 8
            "USDC", "USDT" -> 6
            else -> 9
        }
        val divisor = Math.pow(10.0, decimals.toDouble())
        val humanAmount = amount.toDouble() / divisor
        return String.format("%.4f %s", humanAmount, token)
    }

    /**
     * Execute blockchain transfer after payment acceptance
     * Called when we receive PAYMENT_ACCEPTED from recipient
     */
    private fun executePaymentTransfer(
        contact: com.securelegion.database.entities.Contact,
        amount: Long,
        token: String,
        recipientAddress: String,
        quoteId: String,
        originalMessageId: String
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.i(TAG, "╔════════════════════════════════════════")
                Log.i(TAG, "║ EXECUTING PAYMENT TRANSFER")
                Log.i(TAG, "║ Amount: ${formatPaymentAmount(amount, token)}")
                Log.i(TAG, "║ To: $recipientAddress")
                Log.i(TAG, "║ Token: $token")
                Log.i(TAG, "╚════════════════════════════════════════")

                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@TorService)
                val solanaService = SolanaService(this@TorService)
                val senderAddress = keyManager.getSolanaAddress()

                // Execute the transfer based on token type
                val result = when (token.uppercase()) {
                    "SOL" -> {
                        // Convert lamports to SOL (1 SOL = 1,000,000,000 lamports)
                        val amountSOL = amount.toDouble() / 1_000_000_000.0
                        solanaService.sendTransaction(
                            fromPublicKey = senderAddress,
                            toPublicKey = recipientAddress,
                            amountSOL = amountSOL,
                            keyManager = keyManager
                        )
                    }
                    "ZEC" -> {
                        // Convert zatoshis to ZEC (1 ZEC = 100,000,000 zatoshis)
                        val amountZEC = amount.toDouble() / 100_000_000.0
                        val zcashService = ZcashService.getInstance(this@TorService)
                        // Include NLx402 quote hash in memo for verification
                        val memo = "NLx402:$quoteId"
                        zcashService.sendTransaction(recipientAddress, amountZEC, memo)
                    }
                    else -> {
                        // TODO: Implement SPL token transfer
                        Result.failure(Exception("$token transfers not yet implemented"))
                    }
                }

                if (result.isSuccess) {
                    val txSignature = result.getOrNull() ?: ""
                    Log.i(TAG, "✓ Payment transfer successful! TX: $txSignature")

                    // Update the original request message status
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@TorService, dbPassphrase)

                    // Find and update original message
                    val originalMessage = database.messageDao().getMessageByMessageId(originalMessageId)
                    if (originalMessage != null) {
                        val updatedMessage = originalMessage.copy(
                            paymentStatus = com.securelegion.database.entities.Message.PAYMENT_STATUS_PAID,
                            txSignature = txSignature
                        )
                        database.messageDao().updateMessage(updatedMessage)
                        Log.i(TAG, "✓ Updated original request status to PAID")
                    }

                    // Send payment confirmation to recipient
                    val messageService = MessageService(this@TorService)
                    val currentTime = System.currentTimeMillis() / 1000
                    val quote = com.securelegion.crypto.NLx402Manager.PaymentQuote(
                        quoteId = quoteId,
                        recipient = recipientAddress,
                        amount = amount,
                        token = token,
                        description = null,
                        createdAt = currentTime,
                        expiresAt = currentTime + 86400, // 24 hours
                        senderHandle = null,
                        recipientHandle = null,
                        rawJson = """{"quote_id":"$quoteId","recipient":"$recipientAddress","amount":$amount,"token":"$token","created_at":$currentTime,"expires_at":${currentTime + 86400}}"""
                    )

                    messageService.sendPaymentConfirmation(
                        contactId = contact.id,
                        originalQuote = quote,
                        txSignature = txSignature
                    )
                    Log.i(TAG, "✓ Payment confirmation sent to ${contact.displayName}")

                    // Broadcast payment success
                    val intent = Intent("com.securelegion.PAYMENT_SUCCESS")
                    intent.setPackage(packageName)
                    intent.putExtra("CONTACT_ID", contact.id)
                    intent.putExtra("TX_SIGNATURE", txSignature)
                    intent.putExtra("AMOUNT", amount)
                    intent.putExtra("TOKEN", token)
                    sendBroadcast(intent)

                } else {
                    val error = result.exceptionOrNull()?.message ?: "Unknown error"
                    Log.e(TAG, "✗ Payment transfer failed: $error")

                    // Broadcast payment failure
                    val intent = Intent("com.securelegion.PAYMENT_FAILED")
                    intent.setPackage(packageName)
                    intent.putExtra("CONTACT_ID", contact.id)
                    intent.putExtra("ERROR", error)
                    sendBroadcast(intent)
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error executing payment transfer", e)
            }
        }
    }
}
