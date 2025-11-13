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
import android.widget.Toast
import androidx.core.app.NotificationCompat
import com.securelegion.ChatActivity
import com.securelegion.MainActivity
import com.securelegion.R
import com.securelegion.crypto.TorManager
import com.securelegion.crypto.RustBridge
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

    // Network monitoring
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var hasNetworkConnection = false

    // Reconnection state
    private var isReconnecting = false
    private var reconnectAttempts = 0
    private var lastReconnectTime = 0L
    private val reconnectHandler = Handler(Looper.getMainLooper())
    private val healthCheckHandler = Handler(Looper.getMainLooper())

    // Reconnection constants
    private val INITIAL_RETRY_DELAY = 5000L        // 5 seconds
    private val MAX_RETRY_DELAY = 60000L           // 60 seconds
    private val HEALTH_CHECK_INTERVAL = 30000L     // 30 seconds
    private val MIN_RETRY_INTERVAL = 3000L         // 3 seconds minimum between retries

    companion object {
        private const val TAG = "TorService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "tor_service_channel"
        private const val CHANNEL_NAME = "Tor Hidden Service"
        private const val AUTH_CHANNEL_ID = "message_auth_channel"
        private const val AUTH_CHANNEL_NAME = "Message Authentication"

        const val ACTION_START_TOR = "com.securelegion.action.START_TOR"
        const val ACTION_STOP_TOR = "com.securelegion.action.STOP_TOR"
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

        fun isRunning(): Boolean = running

        fun isTorConnected(): Boolean = torConnected

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

        // Setup network monitoring
        setupNetworkMonitoring()

        // Start health check monitoring
        startHealthCheckMonitoring()

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
            ACTION_ACCEPT_MESSAGE -> handleAcceptMessage(intent)
            ACTION_DECLINE_MESSAGE -> handleDeclineMessage(intent)
            else -> startTorService() // Default to starting
        }

        // Service should restart if killed by system
        return START_STICKY
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
            Toast.makeText(this, "Failed to accept message", Toast.LENGTH_SHORT).show()
            return
        }

        Log.i(TAG, "Created encrypted Pong: ${encryptedPong.size} bytes")

        // Send Pong back to sender
        RustBridge.sendPongBytes(connectionId, encryptedPong)

        Log.i(TAG, "Pong sent successfully! Waiting for incoming message...")
        Toast.makeText(this, "Accepting message from $senderName...", Toast.LENGTH_SHORT).show()

        // After sending Pong, wait for the encrypted message
        receiveIncomingMessage(connectionId, pingId, senderName)

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

        Toast.makeText(this, "Declined message from $senderName", Toast.LENGTH_SHORT).show()

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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            Log.d(TAG, "Using Android 14+ startForeground with service type")
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
            Log.i(TAG, "startForeground called successfully (Android 14+)")
        } else {
            Log.d(TAG, "Using legacy startForeground")
            startForeground(NOTIFICATION_ID, notification)
            Log.i(TAG, "startForeground called successfully (legacy)")
        }

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

                            // Reset reconnection state on success
                            isReconnecting = false
                            reconnectAttempts = 0
                            torConnected = true

                            // Start listening for incoming Ping tokens
                            startIncomingListener()

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

                    // Check if Tor is actually connected before attempting reconnect
                    if (!torConnected) {
                        Log.d(TAG, "Tor credentials exist but not connected - triggering reconnection")
                        updateNotification("Connecting to Tor...")
                        attemptReconnect()
                    } else {
                        Log.i(TAG, "Tor already connected - skipping reconnect")
                        updateNotification("Connected to Tor")

                        // Ensure listener is started (in case service was restarted)
                        startIncomingListener()
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

            // Get sender information from the Ping token
            val senderPublicKey = RustBridge.getPingSenderPublicKey(pingId)

            // Look up sender in contacts database
            val senderName = if (senderPublicKey != null) {
                lookupContactName(senderPublicKey)
            } else {
                "Unknown Contact"
            }

            Log.i(TAG, "Incoming message request from: $senderName")

            // Store pending Ping for user to download later
            storePendingPing(pingId, connectionId, senderPublicKey, senderName)

            // Show simple notification - no preview or accept/decline
            showNewMessageNotification()

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming Ping", e)
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
    private fun storePendingPing(pingId: String, connectionId: Long, senderPublicKey: ByteArray?, senderName: String) {
        try {
            val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = com.securelegion.database.SecureLegionDatabase.getInstance(this, dbPassphrase)

            // Find contact by public key
            if (senderPublicKey != null) {
                val publicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)
                val contact = database.contactDao().getContactByPublicKey(publicKeyBase64)

                if (contact != null) {
                    // Store pending Ping info in SharedPreferences (temporary storage)
                    val prefs = getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
                    prefs.edit().apply {
                        putString("ping_${contact.id}_id", pingId)
                        putLong("ping_${contact.id}_connection", connectionId)
                        putString("ping_${contact.id}_name", senderName)
                        apply()
                    }
                    Log.i(TAG, "Stored pending Ping for contact ${contact.id}: $senderName")
                } else {
                    Log.w(TAG, "Cannot store Ping - sender not in contacts: $senderName")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store pending Ping", e)
        }
    }

    /**
     * Show simple notification that a message is waiting
     */
    private fun showNewMessageNotification() {
        // Create intent to open app
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
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
    }

    /**
     * Receive encrypted message after sending Pong
     */
    private fun receiveIncomingMessage(connectionId: Long, pingId: String, senderName: String) {
        Thread {
            try {
                Log.d(TAG, "Waiting for message on connection $connectionId from $senderName...")

                // Receive message from sender (Rust code will handle reading from connection)
                val encryptedMessage = RustBridge.receiveIncomingMessage(connectionId)

                if (encryptedMessage != null && encryptedMessage.isNotEmpty()) {
                    Log.i(TAG, "Received encrypted message: ${encryptedMessage.size} bytes")

                    // Get sender's public key from the Ping token
                    val senderPublicKey = RustBridge.getPingSenderPublicKey(pingId)
                    if (senderPublicKey == null) {
                        Log.e(TAG, "Failed to get sender public key from Ping")
                        android.os.Handler(android.os.Looper.getMainLooper()).post {
                            Toast.makeText(this@TorService, "Failed to verify sender", Toast.LENGTH_SHORT).show()
                        }
                        return@Thread
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
                            Toast.makeText(this@TorService, "Message from unknown contact", Toast.LENGTH_SHORT).show()
                        }
                        return@Thread
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
                            Toast.makeText(this@TorService, "Failed to decrypt message", Toast.LENGTH_SHORT).show()
                        }
                        return@Thread
                    }

                    Log.i(TAG, "Message decrypted successfully: ${messageText.take(50)}...")

                    // Save message to database
                    kotlinx.coroutines.runBlocking {
                        val message = com.securelegion.database.entities.Message(
                            contactId = contact.id,
                            messageId = java.util.UUID.randomUUID().toString(),
                            encryptedContent = messageText,
                            isSentByMe = false,
                            timestamp = System.currentTimeMillis(),
                            status = com.securelegion.database.entities.Message.STATUS_DELIVERED,
                            signatureBase64 = "",
                            nonceBase64 = "",
                            isRead = false,
                            requiresReadReceipt = true,
                            selfDestructAt = null
                        )

                        val insertedMessage = database.messageDao().insertMessage(message)
                        Log.i(TAG, "Message saved to database with ID: $insertedMessage")

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

                } else {
                    Log.w(TAG, "No message received or empty message")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error receiving incoming message", e)
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    Toast.makeText(this@TorService, "Error receiving message: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }.start()
    }

    /**
     * Show notification for received message with preview and actions
     */
    private fun showMessageNotification(senderName: String, messageText: String, contactId: Long) {
        // Create intent to open chat when notification is tapped
        val openChatIntent = Intent(this, ChatActivity::class.java).apply {
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

        // Create reply action intent
        val replyIntent = Intent(this, ChatActivity::class.java).apply {
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
                val recipientPublicKey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                val encryptedReceipt = RustBridge.encryptMessage(receiptPayload, recipientPublicKey)

                // Send via Tor to contact's .onion address
                // TODO: Implement Tor send message protocol
                // For now, just log it - this will be implemented when we add outgoing message support
                Log.i(TAG, "Read receipt prepared (${encryptedReceipt.size} bytes) - waiting for outgoing protocol implementation")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send read receipt", e)
            }
        }.start()
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
            // Tor service channel (default priority so it shows in status bar)
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Keeps Tor hidden service running for incoming messages"
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
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
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

    private fun startHealthCheckMonitoring() {
        Log.d(TAG, "Starting health check monitoring (${HEALTH_CHECK_INTERVAL/1000}s interval)")

        val healthCheckRunnable = object : Runnable {
            override fun run() {
                checkTorHealth()
                // Schedule next check
                healthCheckHandler.postDelayed(this, HEALTH_CHECK_INTERVAL)
            }
        }

        // Start first check after initial delay
        healthCheckHandler.postDelayed(healthCheckRunnable, HEALTH_CHECK_INTERVAL)
    }

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
                if (!torConnected) {
                    Log.i(TAG, "Health check: Tor reconnected successfully")
                    torConnected = true
                    isReconnecting = false
                    reconnectAttempts = 0

                    updateNotification("Connected to Tor")
                }
            } else if (!hasNetworkConnection) {
                Log.d(TAG, "Health check: No network connection available")
                torConnected = false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error during health check", e)
        }
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
            Log.d(TAG, "Skipping reconnect attempt - too soon since last attempt (${(now - lastReconnectTime)/1000}s ago)")
            isReconnecting = false
            // Don't schedule another reconnect - one is already scheduled from previous attempt
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

                        // Restart listener
                        startIncomingListener()

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


    // ==================== LIFECYCLE ====================

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "TorService destroyed")

        running = false
        torConnected = false
        isServiceRunning = false

        // Clean up handlers
        reconnectHandler.removeCallbacksAndMessages(null)
        healthCheckHandler.removeCallbacksAndMessages(null)

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

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.d(TAG, "onTaskRemoved - App swiped away, keeping service running")
        // Service continues running even when app is swiped away
        // This is intentional for Ping-Pong protocol
    }
}
