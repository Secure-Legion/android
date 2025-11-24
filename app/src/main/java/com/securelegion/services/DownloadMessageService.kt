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
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securelegion.ChatActivity
import com.securelegion.LockActivity
import com.securelegion.R
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.TorManager
import com.securelegion.database.SecureLegionDatabase
import kotlinx.coroutines.*

class DownloadMessageService : Service() {

    companion object {
        private const val TAG = "DownloadMessageService"
        private const val NOTIFICATION_ID = 2002
        private const val CHANNEL_ID = "download_message_channel"

        const val EXTRA_CONTACT_ID = "EXTRA_CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "EXTRA_CONTACT_NAME"

        fun start(context: Context, contactId: Long, contactName: String) {
            val intent = Intent(context, DownloadMessageService::class.java).apply {
                putExtra(EXTRA_CONTACT_ID, contactId)
                putExtra(EXTRA_CONTACT_NAME, contactName)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var notificationManager: NotificationManager? = null

    override fun onCreate() {
        super.onCreate()
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val contactId = intent?.getLongExtra(EXTRA_CONTACT_ID, -1L) ?: -1L
        val contactName = intent?.getStringExtra(EXTRA_CONTACT_NAME) ?: "Unknown"

        if (contactId == -1L) {
            Log.e(TAG, "Invalid contact ID, stopping service")
            stopSelf()
            return START_NOT_STICKY
        }

        // Start foreground with initial notification
        startForeground(NOTIFICATION_ID, createNotification(contactName, "Preparing download..."))

        // Set download-in-progress flag to prevent notification spam
        val downloadStatusPrefs = getSharedPreferences("download_status", MODE_PRIVATE)
        downloadStatusPrefs.edit().putBoolean("downloading_$contactId", true).apply()
        Log.d(TAG, "Set download-in-progress flag for contact $contactId")

        // Launch download in background
        serviceScope.launch {
            try {
                downloadMessage(contactId, contactName)
            } catch (e: Exception) {
                Log.e(TAG, "Download failed", e)

                showFailureNotification(contactName, e.message ?: "Unknown error")

                // Broadcast download failure to ChatActivity
                val failureIntent = Intent("com.securelegion.DOWNLOAD_FAILED")
                failureIntent.setPackage(packageName)
                failureIntent.putExtra("CONTACT_ID", contactId)
                sendBroadcast(failureIntent)
                Log.d(TAG, "Sent DOWNLOAD_FAILED broadcast")
            } finally {
                // Clear download-in-progress flag
                downloadStatusPrefs.edit().putBoolean("downloading_$contactId", false).apply()
                Log.d(TAG, "Cleared download-in-progress flag for contact $contactId")
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    private var currentContactId: Long = -1L
    private var currentContactName: String = ""

    private suspend fun downloadMessage(contactId: Long, contactName: String) {
        currentContactId = contactId
        currentContactName = contactName

        Log.i(TAG, "========== DOWNLOAD INITIATED ==========")
        Log.i(TAG, "Contact: $contactName (ID: $contactId)")

        // START DOWNLOAD WATCHDOG - monitor for timeout
        val downloadStartTime = System.currentTimeMillis()
        val DOWNLOAD_TIMEOUT_MS = 45000L  // 45 seconds max
        var downloadCompleted = false

        val watchdogJob = serviceScope.launch {
            delay(DOWNLOAD_TIMEOUT_MS)
            if (!downloadCompleted) {
                val elapsed = System.currentTimeMillis() - downloadStartTime
                Log.e(TAG, "⚠️  DOWNLOAD TIMEOUT after ${elapsed}ms")
                Log.e(TAG, "Diagnostic info:")
                Log.e(TAG, "  Contact: $contactName (ID: $contactId)")

                try {
                    val torStatus = checkTorStatus()
                    Log.e(TAG, "  Tor Status: $torStatus")
                } catch (e: Exception) {
                    Log.e(TAG, "  Tor Status: Error - ${e.message}")
                }

                showFailureNotification(contactName, "Download timed out (45s). Check connection.")

                // Don't cancel service here - let the main download timeout handle it
            }
        }

        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
        val pingId = prefs.getString("ping_${contactId}_id", null)

        if (pingId == null) {
            downloadCompleted = true
            watchdogJob.cancel()
            showFailureNotification(contactName, "No pending message")
            return
        }

        // No download lock needed - ACK-based system prevents duplicates via DB checks

        try {

        // PRE-FLIGHT HEALTH CHECKS
        Log.i(TAG, "========== PRE-FLIGHT HEALTH CHECKS ==========")
        updateNotification(contactName, "Checking connection...")

        // Check 1: Tor bootstrap status
        val bootstrapStatus = withContext(Dispatchers.IO) {
            try {
                com.securelegion.crypto.RustBridge.getBootstrapStatus()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check bootstrap status", e)
                -1
            }
        }

        if (bootstrapStatus < 100) {
            val errorMsg = if (bootstrapStatus >= 0) {
                "Tor not ready ($bootstrapStatus%). Please wait."
            } else {
                "Cannot check Tor status"
            }
            Log.e(TAG, "Pre-flight check failed: $errorMsg")
            downloadCompleted = true
            watchdogJob.cancel()
            showFailureNotification(contactName, errorMsg)
            return
        }
        Log.i(TAG, "  ✓ Tor bootstrap: 100%")

        // Check 2: SOCKS proxy running
        val socksRunning = withContext(Dispatchers.IO) {
            try {
                com.securelegion.crypto.RustBridge.isSocksProxyRunning()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check SOCKS status", e)
                false
            }
        }

        if (!socksRunning) {
            val errorMsg = "SOCKS proxy not running"
            Log.e(TAG, "Pre-flight check failed: $errorMsg")
            downloadCompleted = true
            watchdogJob.cancel()
            showFailureNotification(contactName, errorMsg)
            return
        }
        Log.i(TAG, "  ✓ SOCKS proxy: running")

        // Check 3: Test SOCKS connectivity (non-critical, just warn)
        val socksWorking = withContext(Dispatchers.IO) {
            try {
                com.securelegion.crypto.RustBridge.testSocksConnectivity()
            } catch (e: Exception) {
                Log.w(TAG, "SOCKS connectivity test failed", e)
                false
            }
        }

        if (!socksWorking) {
            Log.w(TAG, "  ⚠ SOCKS connectivity: test failed (non-critical)")
        } else {
            Log.i(TAG, "  ✓ SOCKS connectivity: working")
        }

        Log.i(TAG, "✓ All critical pre-flight checks passed")

        // STAGE 1: Preparing download
        updateNotification(contactName, "[1/4] Preparing download...")
        Log.i(TAG, "========== STAGE 1/4: PREPARING ==========")

        // Restore Ping from SharedPreferences
        val encryptedPingBase64 = prefs.getString("ping_${contactId}_data", null)
        if (encryptedPingBase64 != null) {
            try {
                Log.d(TAG, "Restoring Ping from SharedPreferences")
                val encryptedPingWire = android.util.Base64.decode(encryptedPingBase64, android.util.Base64.NO_WRAP)

                val restoredPingId = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.decryptIncomingPing(encryptedPingWire)
                }

                if (restoredPingId != null && restoredPingId == pingId) {
                    Log.i(TAG, "Successfully restored Ping: $pingId")
                } else {
                    Log.w(TAG, "Restored Ping ID mismatch or failed: expected=$pingId, got=$restoredPingId")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to restore Ping from SharedPreferences", e)
            }
        }

        // Get sender's .onion address
        val senderOnion = prefs.getString("ping_${contactId}_onion", null)
        if (senderOnion == null) {
            Log.e(TAG, "No sender .onion address found")
            showFailureNotification(contactName, "Missing sender address")
            return
        }

        // Get connection ID (may not exist for very old pings)
        val connectionId = prefs.getLong("ping_${contactId}_connection", -1L)

        Log.i(TAG, "Ping ID: $pingId")
        Log.i(TAG, "Sender: $senderOnion")
        Log.i(TAG, "Connection ID: ${if (connectionId != -1L) connectionId else "not available"}")

        // STAGE 2: Creating response
        updateNotification(contactName, "[2/4] Creating response...")
        Log.i(TAG, "========== STAGE 2/4: CREATING PONG ==========")

        // Create Pong response
        val pongBytes = withContext(Dispatchers.IO) {
            val torManager = TorManager.getInstance(this@DownloadMessageService)
            torManager.respondToPing(pingId, authenticated = true)
        }

        if (pongBytes == null) {
            Log.e(TAG, "Failed to create Pong")
            showFailureNotification(contactName, "Failed to create response")
            return
        }

        Log.i(TAG, "✓ Pong created: ${pongBytes.size} bytes")

        // STAGE 3: Sending response and waiting for message
        Log.i(TAG, "========== STAGE 3/4: DOWNLOADING MESSAGE ==========")

        // DUAL-PATH APPROACH: Try instant reply first, then fall back to listener
        var pongSent = false
        var instantMessageReceived = false

        // PATH 1: Try sending Pong on original connection (instant messaging)
        // But only if connection is fresh (< 30 seconds old) AND still alive - stale/broken connections will timeout
        if (connectionId != -1L) {
            val pingTimestamp = prefs.getLong("ping_${contactId}_timestamp", 0L)
            val connectionAge = System.currentTimeMillis() - pingTimestamp

            // Check 1: Connection age (< 30s)
            val isFresh = connectionAge < 30000

            // Check 2: Connection still alive (validate with Rust)
            var isAlive = false
            if (isFresh) {
                isAlive = withContext(Dispatchers.IO) {
                    try {
                        com.securelegion.crypto.RustBridge.isConnectionAlive(connectionId)
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to check connection status (assuming dead): ${e.message}")
                        false
                    }
                }
            }

            if (isFresh && isAlive) {
                Log.d(TAG, "Connection is valid (age=${connectionAge}ms, alive=true), attempting instant Pong on connection $connectionId...")
                updateNotification(contactName, "[3/4] Downloading... (fast path)")
                pongSent = withContext(Dispatchers.IO) {
                try {
                    val messageBytes = com.securelegion.crypto.RustBridge.sendPongBytes(connectionId, pongBytes)
                    if (messageBytes != null) {
                        Log.i(TAG, "✓ Pong sent on original connection! Received message blob: ${messageBytes.size} bytes")
                        // Message blob arrived immediately! Process it now
                        handleInstantMessageBlob(messageBytes, contactId, contactName, pingId, connectionId)
                        instantMessageReceived = true
                        true
                    } else {
                        Log.w(TAG, "✗ sendPongBytes returned null (connection likely closed)")
                        false
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "✗ Instant Pong reply failed (connection closed): ${e.message}")
                    false
                }
            }
            } else {
                // Connection validation failed - log reason
                if (!isFresh) {
                    Log.d(TAG, "Connection is stale (${connectionAge}ms old), skipping instant path - will use listener")
                } else if (!isAlive) {
                    Log.d(TAG, "Connection is dead (not responding), skipping instant path - will use listener")
                }
                updateNotification(contactName, "[3/4] Downloading... (slower path)")
            }
        }

        // PATH 2: If instant path failed, fall back to listener (delayed messaging)
        if (!pongSent) {
            Log.d(TAG, "Falling back to listener-based Pong delivery (delayed download)...")
            updateNotification(contactName, "[3/4] Downloading... (may take 30s)")
            pongSent = withContext(Dispatchers.IO) {
                try {
                    com.securelegion.crypto.RustBridge.sendPongToListener(senderOnion, pongBytes)
                } catch (e: Exception) {
                    Log.e(TAG, "✗ Failed to send Pong to listener", e)
                    // Note: Peer connection failures are normal when peer is offline
                    // Don't report as Tor failure - only restart Tor when Tor daemon itself is broken
                    false
                }
            }
        }

        if (!pongSent) {
            Log.e(TAG, "✗ Pong send failed")
            showFailureNotification(contactName, "Failed to send response")
            return
        }

        // Clean up Rust Ping session immediately after successful Pong send to prevent memory leak
        try {
            com.securelegion.crypto.RustBridge.removePingSession(pingId)
            Log.d(TAG, "✓ Cleaned up Rust Ping session for pingId: $pingId")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to clean up Ping session (non-critical)", e)
        }

        // If instant message was received, skip polling entirely
        var messageReceived = instantMessageReceived

        if (instantMessageReceived) {
            Log.i(TAG, "✓ Message received instantly - skipping polling phase")
        } else {
            Log.i(TAG, "✓ Pong sent! Now waiting for message payload...")

            // Update notification
            updateNotification(contactName, "Waiting for message...")

            // Get current message count BEFORE polling
            val initialMessageCount = withContext(Dispatchers.IO) {
                val keyManager = KeyManager.getInstance(this@DownloadMessageService)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@DownloadMessageService, dbPassphrase)
                database.messageDao().getMessagesForContact(contactId).size
            }
            Log.d(TAG, "Current message count before polling: $initialMessageCount")

            // Poll for incoming message
            val maxAttempts = 60 // 60 seconds total (more attempts, shorter delay)

            for (attempt in 1..maxAttempts) {
                Log.d(TAG, "Polling attempt $attempt/$maxAttempts...")
                updateNotification(contactName, "Downloading... ($attempt/$maxAttempts)")

                delay(1000)  // Reduced from 2000ms to 1000ms for faster response

                val currentMessageCount = withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@DownloadMessageService)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@DownloadMessageService, dbPassphrase)
                    database.messageDao().getMessagesForContact(contactId).size
                }

                if (currentMessageCount > initialMessageCount) {
                    Log.i(TAG, "✓ NEW message found in database! ($initialMessageCount → $currentMessageCount)")
                    messageReceived = true
                    break
                } else {
                    Log.d(TAG, "No new messages yet (count still $currentMessageCount)")
                }
            }

            if (!messageReceived) {
                Log.w(TAG, "✗ Timeout waiting for message")
                showFailureNotification(contactName, "Message delivery timed out")
                return
            }

            Log.i(TAG, "✓ Message received successfully!")
        }

        // Send MESSAGE_ACK to sender after successfully receiving the message
        // connectionId not available here (polling path), so pass -1L
        sendMessageAck(contactId, contactName, -1L)

        // Dismiss the pending message notification
        val notificationManager = getSystemService(android.app.NotificationManager::class.java)
        val notificationId = contactId.toInt() + 20000
        notificationManager?.cancel(notificationId)
        Log.i(TAG, "Dismissed pending message notification (ID: $notificationId)")

        // Clear the pending Ping data
        prefs.edit()
            .remove("ping_${contactId}_id")
            .remove("ping_${contactId}_sender")
            .remove("ping_${contactId}_timestamp")
            .remove("ping_${contactId}_data")
            .remove("ping_${contactId}_onion")
            .remove("ping_${contactId}_connection")
            .remove("ping_${contactId}_name")
            .apply()  // Use apply() instead of commit() for async/non-blocking

        // Small delay to ensure SharedPreferences write completes
        delay(100)  // Reduced from 300ms since apply() is faster

        // Broadcast to ChatActivity to refresh (ChatActivity will notify MainActivity if needed)
        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
        intent.setPackage(packageName)
        intent.putExtra("CONTACT_ID", contactId)
        sendBroadcast(intent)

        Log.i(TAG, "✓ Broadcast sent to refresh UI")

        // Show success notification
        showSuccessNotification(contactName)

        // Cancel watchdog - download completed successfully
        downloadCompleted = true
        watchdogJob.cancel()
        Log.d(TAG, "✓ Download completed in ${System.currentTimeMillis() - downloadStartTime}ms")

        } catch (e: Exception) {
            // Cancel watchdog on error
            downloadCompleted = true
            watchdogJob.cancel()
            throw e  // Re-throw to be caught by outer try-catch
        }
    }

    private fun checkTorStatus(): String {
        return try {
            val bootstrap = com.securelegion.crypto.RustBridge.getBootstrapStatus()
            val socks = com.securelegion.crypto.RustBridge.isSocksProxyRunning()
            "Bootstrap=$bootstrap%, SOCKS=$socks"
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Message Downloads",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress when downloading messages"
                setShowBadge(false)
            }
            notificationManager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(contactName: String, message: String): Notification {
        // Launch via LockActivity to prevent showing chat before authentication
        // Open ChatActivity if we have a valid contactId, otherwise MainActivity
        val intent = Intent(this, LockActivity::class.java).apply {
            if (currentContactId != -1L) {
                putExtra("TARGET_ACTIVITY", "ChatActivity")
                putExtra(ChatActivity.EXTRA_CONTACT_ID, currentContactId)
                putExtra(ChatActivity.EXTRA_CONTACT_NAME, currentContactName)
            } else {
                putExtra("TARGET_ACTIVITY", "MainActivity")
            }
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, currentContactId.toInt(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Downloading message from $contactName")
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_lock)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun updateNotification(contactName: String, message: String) {
        notificationManager?.notify(NOTIFICATION_ID, createNotification(contactName, message))
    }

    private fun showSuccessNotification(contactName: String) {
        // Launch via LockActivity to prevent showing chat before authentication
        // Open ChatActivity with the contactId
        val intent = Intent(this, LockActivity::class.java).apply {
            if (currentContactId != -1L) {
                putExtra("TARGET_ACTIVITY", "ChatActivity")
                putExtra(ChatActivity.EXTRA_CONTACT_ID, currentContactId)
                putExtra(ChatActivity.EXTRA_CONTACT_NAME, currentContactName)
            } else {
                putExtra("TARGET_ACTIVITY", "MainActivity")
            }
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, currentContactId.toInt(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Message received")
            .setContentText("New message from $contactName")
            .setSmallIcon(R.drawable.ic_lock)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        notificationManager?.notify(NOTIFICATION_ID, notification)
    }

    private fun showFailureNotification(contactName: String, error: String) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Download failed")
            .setContentText("Failed to download message from $contactName: $error")
            .setSmallIcon(R.drawable.ic_lock)
            .setAutoCancel(true)
            .build()

        notificationManager?.notify(NOTIFICATION_ID, notification)
    }

    /**
     * Handle message blob that arrived immediately via instant path (sendPongBytes)
     */
    private suspend fun handleInstantMessageBlob(messageBytes: ByteArray, contactId: Long, contactName: String, pingId: String, connectionId: Long) {
        try {
            // STAGE 4: Processing message
            updateNotification(contactName, "[4/4] Processing message...")
            Log.i(TAG, "========== STAGE 4/4: PROCESSING MESSAGE ==========")
            Log.i(TAG, "Processing instant message blob: ${messageBytes.size} bytes")

            // Message blob format differs by type:
            // TEXT (0x03): [Type - 1 byte][Sender X25519 - 32 bytes][Encrypted Text]
            // VOICE (0x04): [Type - 1 byte][0x01 - 1 byte][Duration - 4 bytes][Sender X25519 - 32 bytes][Encrypted Audio]
            if (messageBytes.size < 33) {
                Log.e(TAG, "Message blob too small: ${messageBytes.size} bytes")
                return
            }

            // Extract type byte (first byte)
            val typeByte = messageBytes[0]
            Log.d(TAG, "Message type byte: 0x${String.format("%02X", typeByte)}")

            // Extract fields based on message type
            val senderX25519PublicKey: ByteArray
            val encryptedPayload: ByteArray
            val voiceDuration: Int?

            when (typeByte.toInt()) {
                0x03 -> {
                    // TEXT message: [0x03][X25519 32 bytes][Encrypted Text]
                    senderX25519PublicKey = messageBytes.copyOfRange(1, 33)
                    encryptedPayload = messageBytes.copyOfRange(33, messageBytes.size)
                    voiceDuration = null
                }
                0x04 -> {
                    // VOICE message: [0x04][0x01][Duration 4 bytes][X25519 32 bytes][Encrypted Audio]
                    if (messageBytes.size < 38) {
                        Log.e(TAG, "VOICE message blob too small: ${messageBytes.size} bytes (need at least 38)")
                        return
                    }
                    // Skip byte 1 (internal type 0x01), extract duration from bytes 2-5
                    val durationBytes = messageBytes.copyOfRange(2, 6)
                    voiceDuration = (
                        ((durationBytes[0].toInt() and 0xFF) shl 24) or
                        ((durationBytes[1].toInt() and 0xFF) shl 16) or
                        ((durationBytes[2].toInt() and 0xFF) shl 8) or
                        (durationBytes[3].toInt() and 0xFF)
                    )
                    // Extract X25519 key from bytes 6-37 (32 bytes)
                    senderX25519PublicKey = messageBytes.copyOfRange(6, 38)
                    // Extract encrypted audio from byte 38 onward
                    encryptedPayload = messageBytes.copyOfRange(38, messageBytes.size)
                    Log.d(TAG, "Voice duration: ${voiceDuration}s")
                }
                else -> {
                    Log.e(TAG, "Unknown message type: 0x${String.format("%02X", typeByte)}")
                    return
                }
            }

            Log.d(TAG, "Sender X25519 key: ${android.util.Base64.encodeToString(senderX25519PublicKey, android.util.Base64.NO_WRAP).take(16)}...")
            Log.d(TAG, "Encrypted payload: ${encryptedPayload.size} bytes")

            // Get database
            val keyManager = KeyManager.getInstance(this@DownloadMessageService)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@DownloadMessageService, dbPassphrase)

            // Get contact info
            val contact = database.contactDao().getContactById(contactId)
            if (contact == null) {
                Log.e(TAG, "Contact not found for ID: $contactId")
                return
            }

            // Get sender's Ed25519 public key for decryption
            val senderPublicKey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)

            // Decrypt message using Ed25519 key
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            when (typeByte.toInt()) {
                0x03 -> {
                    // TEXT message (MSG_TYPE_TEXT = 0x03)
                    Log.d(TAG, "Processing TEXT message...")

                    // Save to database via MessageService
                    val messageService = MessageService(this@DownloadMessageService)
                    // Reconstruct encrypted wire for database storage (NO type byte)
                    // Format: [X25519 32 bytes][Encrypted data]
                    val encryptedWire = senderX25519PublicKey + encryptedPayload
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedWire, android.util.Base64.NO_WRAP)

                    val result = messageService.receiveMessage(
                        encryptedData = encryptedBase64,
                        senderPublicKey = senderPublicKey,
                        senderOnionAddress = contact.torOnionAddress,
                        pingId = pingId
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "✓ TEXT message saved to database")

                        // Dismiss notification immediately - message is already saved

                        // Send MESSAGE_ACK in background (fire-and-forget, don't block UI)

                        CoroutineScope(Dispatchers.IO).launch {
                            try {
                                sendMessageAck(contactId, contactName, connectionId)
                            } catch (e: Exception) {
                                Log.w(TAG, "MESSAGE_ACK failed (non-critical): ${e.message}")
                            }
                        }

                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            // Message was already downloaded, so clear the notification and send ACK
                            sendMessageAck(contactId, contactName, connectionId)
                            val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                            notificationManager?.cancel(contactId.toInt() + 20000)
                        } else {
                            Log.e(TAG, "Failed to save TEXT message: $errorMessage")
                        }
                    }
                }

                0x04 -> {
                    // VOICE message (MSG_TYPE_VOICE = 0x04)
                    Log.d(TAG, "Processing VOICE message...")

                    // Save to database via MessageService
                    val messageService = MessageService(this@DownloadMessageService)
                    // Reconstruct encrypted wire for database storage (NO type byte)
                    // Format: [X25519 32 bytes][Encrypted audio data]
                    val encryptedWire = senderX25519PublicKey + encryptedPayload
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedWire, android.util.Base64.NO_WRAP)

                    val result = messageService.receiveMessage(
                        encryptedData = encryptedBase64,
                        senderPublicKey = senderPublicKey,
                        senderOnionAddress = contact.torOnionAddress,
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE,
                        voiceDuration = voiceDuration!!,  // Already extracted above
                        pingId = pingId
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "✓ VOICE message saved to database")
                        // Send MESSAGE_ACK to sender
                        sendMessageAck(contactId, contactName, connectionId)
                        // Dismiss the pending message notification
                        val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                        notificationManager?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            // Message was already downloaded, so clear the notification and send ACK
                            sendMessageAck(contactId, contactName, connectionId)
                            val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                            notificationManager?.cancel(contactId.toInt() + 20000)
                        } else {
                            Log.e(TAG, "Failed to save VOICE message: $errorMessage")
                        }
                    }
                }

                else -> {
                    Log.w(TAG, "Unknown message type: 0x${String.format("%02X", typeByte)}")
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error processing instant message blob", e)
        }
    }

    /**
     * Send MESSAGE_ACK to sender after successfully downloading message
     * @param connectionId Connection ID for instant ACK (or -1L if not available)
     */
    private suspend fun sendMessageAck(contactId: Long, contactName: String, connectionId: Long) {
        try {
            val keyManager = KeyManager.getInstance(this@DownloadMessageService)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@DownloadMessageService, dbPassphrase)

            // Get contact info
            val contact = database.contactDao().getContactById(contactId)
            if (contact == null) {
                Log.e(TAG, "Could not find contact with ID $contactId to send MESSAGE_ACK")
                return
            }

            // Get the most recent message from this contact (just received)
            val messages = database.messageDao().getMessagesForContact(contactId)
            if (messages.isEmpty()) {
                Log.w(TAG, "No messages found for contact $contactId - cannot send MESSAGE_ACK")
                return
            }

            // Get the most recent message
            val latestMessage = messages.maxByOrNull { it.timestamp }
            if (latestMessage == null) {
                Log.w(TAG, "Could not determine latest message for contact $contactId")
                return
            }

            // Use pingId instead of messageId because pingId is the same on both sender and receiver
            val pingId = latestMessage.pingId
            if (pingId == null) {
                Log.w(TAG, "Message ${latestMessage.messageId} has no pingId - cannot send MESSAGE_ACK")
                return
            }

            Log.d(TAG, "Sending MESSAGE_ACK with retry for pingId=$pingId (messageId=${latestMessage.messageId}) to $contactName")

            val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)
            val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)

            // Retry logic with exponential backoff (3 attempts: 1s, 2s delays)
            val maxRetries = 3
            var delayMs = 1000L
            var attempt = 0

            while (attempt < maxRetries) {
                try {
                    var ackSuccess = false

                    // PATH 1: Try sending ACK on existing connection (instant, avoids SOCKS5 issues)
                    if (connectionId >= 0) {
                        ackSuccess = withContext(Dispatchers.IO) {
                            com.securelegion.crypto.RustBridge.sendAckOnConnection(
                                connectionId,
                                pingId,
                                "MESSAGE_ACK",
                                senderX25519Pubkey
                            )
                        }

                        if (ackSuccess) {
                            Log.i(TAG, "✓ MESSAGE_ACK sent successfully on existing connection for messageId=${latestMessage.messageId} (attempt ${attempt + 1})")
                            return // Success!
                        }

                        Log.d(TAG, "Connection closed, falling back to new connection for MESSAGE_ACK (attempt ${attempt + 1})")
                    }

                    // PATH 2: Connection closed or not available, fall back to opening new connection
                    ackSuccess = withContext(Dispatchers.IO) {
                        com.securelegion.crypto.RustBridge.sendDeliveryAck(
                            pingId,
                            "MESSAGE_ACK",
                            senderEd25519Pubkey,
                            senderX25519Pubkey,
                            contact.torOnionAddress
                        )
                    }

                    if (ackSuccess) {
                        Log.i(TAG, "✓ MESSAGE_ACK sent successfully via new connection for messageId=${latestMessage.messageId} (attempt ${attempt + 1})")
                        return // Success!
                    }

                    // Both paths failed
                    attempt++
                    if (attempt < maxRetries) {
                        Log.w(TAG, "⚠️ MESSAGE_ACK send failed (attempt $attempt/$maxRetries), retrying in ${delayMs}ms...")
                        kotlinx.coroutines.delay(delayMs)
                        delayMs *= 2 // Exponential backoff: 1s, 2s, 4s
                    } else {
                        Log.e(TAG, "✗ MESSAGE_ACK send FAILED after $maxRetries attempts for messageId=${latestMessage.messageId}")
                        Log.e(TAG, "→ Sender will retry MESSAGE, which is acceptable")
                    }

                } catch (e: Exception) {
                    Log.e(TAG, "Exception during MESSAGE_ACK send (attempt ${attempt + 1}/$maxRetries)", e)
                    attempt++
                    if (attempt < maxRetries) {
                        kotlinx.coroutines.delay(delayMs)
                        delayMs *= 2
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending MESSAGE_ACK", e)
        }
    }
}
