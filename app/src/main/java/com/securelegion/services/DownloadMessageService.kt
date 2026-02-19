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
import androidx.room.withTransaction

class DownloadMessageService : Service() {

    companion object {
        private const val TAG = "DownloadMessageService"
        private const val NOTIFICATION_ID = 2002
        private const val CHANNEL_ID = "download_message_channel"

        const val EXTRA_CONTACT_ID = "EXTRA_CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "EXTRA_CONTACT_NAME"
        const val EXTRA_PING_ID = "EXTRA_PING_ID"
        const val EXTRA_CONNECTION_ID = "EXTRA_CONNECTION_ID"

        private const val DOWNLOAD_TIMEOUT_MS = 45_000L

        fun start(context: Context, contactId: Long, contactName: String, pingId: String, connectionId: Long = -1L) {
            val intent = Intent(context, DownloadMessageService::class.java).apply {
                putExtra(EXTRA_CONTACT_ID, contactId)
                putExtra(EXTRA_CONTACT_NAME, contactName)
                putExtra(EXTRA_PING_ID, pingId)
                putExtra(EXTRA_CONNECTION_ID, connectionId)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    // Queue for handling multiple downloads sequentially (not in parallel)
    private data class DownloadRequest(val contactId: Long, val contactName: String, val pingId: String, val connectionId: Long)
    private val downloadQueue = mutableListOf<DownloadRequest>()
    private var isProcessingQueue = false

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var notificationManager: NotificationManager? = null

    override fun onCreate() {
        super.onCreate()
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val contactId = intent?.getLongExtra(EXTRA_CONTACT_ID, -1L) ?: -1L
        val contactName = intent?.getStringExtra(EXTRA_CONTACT_NAME) ?: "Unknown"
        val pingId = intent?.getStringExtra(EXTRA_PING_ID) ?: ""
        val connectionId = intent?.getLongExtra(EXTRA_CONNECTION_ID, -1L) ?: -1L

        if (contactId == -1L || pingId.isEmpty()) {
            Log.e(TAG, "Invalid contact ID or ping ID, stopping service")
            stopSelf()
            return START_NOT_STICKY
        }

        // Start foreground with initial notification
        startForeground(NOTIFICATION_ID, createNotification(contactName, "Preparing download..."))

        // Queue the download (will process sequentially)
        synchronized(downloadQueue) {
            downloadQueue.add(DownloadRequest(contactId, contactName, pingId, connectionId))
            Log.d(TAG, "Queued download: $contactName (pingId=${pingId.take(8)}...) connId=$connectionId - Queue size: ${downloadQueue.size}")

            // If not already processing, start processing the queue
            if (!isProcessingQueue) {
                processDownloadQueue()
            }
        }

        return START_NOT_STICKY
    }

    /**
     * Process download queue sequentially (one download at a time)
     */
    private fun processDownloadQueue() {
        isProcessingQueue = true
        serviceScope.launch {
            while (true) {
                val request = synchronized(downloadQueue) {
                    if (downloadQueue.isEmpty()) {
                        isProcessingQueue = false
                        Log.d(TAG, "Download queue empty - stopping service")
                        stopSelf()
                        return@launch
                    }
                    downloadQueue.removeAt(0)
                }

                // Set download-in-progress flag
                val downloadStatusPrefs = getSharedPreferences("download_status", MODE_PRIVATE)
                downloadStatusPrefs.edit()
                    .putBoolean("downloading_${request.contactId}", true)
                    .putLong("download_start_time_${request.contactId}", System.currentTimeMillis())
                    .apply()
                Log.d(TAG, "Processing download from queue: ${request.contactName} (pingId=${request.pingId.take(8)}...) connId=${request.connectionId} - Remaining: ${synchronized(downloadQueue) { downloadQueue.size }}")

                try {
                    downloadMessage(request.contactId, request.contactName, request.pingId, request.connectionId)
                } catch (e: Exception) {
                    Log.e(TAG, "Download failed", e)
                    showFailureNotification(request.contactName, e.message ?: "Unknown error", request.pingId, request.contactId)

                    // Broadcast download failure to ChatActivity
                    val failureIntent = Intent("com.securelegion.DOWNLOAD_FAILED")
                    failureIntent.setPackage(packageName)
                    failureIntent.putExtra("CONTACT_ID", request.contactId)
                    sendBroadcast(failureIntent)
                    Log.d(TAG, "Sent DOWNLOAD_FAILED broadcast")
                } finally {
                    // Clear download-in-progress flag
                    downloadStatusPrefs.edit()
                        .putBoolean("downloading_${request.contactId}", false)
                        .remove("download_start_time_${request.contactId}")
                        .apply()
                    Log.d(TAG, "Cleared download-in-progress flag for contact ${request.contactId}")
                }
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    // 
    // Download state (shared between watchdog + poll loop)
    // 

    private var currentContactId: Long = -1L
    private var currentContactName: String = ""
    @Volatile private var downloadCompleted = false
    @Volatile private var lastReceivedWireType: Int = -1 // Wire type byte from message blob (0x03=TEXT, 0x04=VOICE, 0x09=IMAGE, 0x0F=PROFILE_UPDATE etc.)
    private var watchdogJob: Job? = null

    /**
     * Context bag for a single download operation.
     * Passed to extracted methods to reduce parameter lists.
     */
    private class DownloadCtx(
        val contactId: Long,
        val contactName: String,
        val pingId: String,
        val database: SecureLegionDatabase,
        val senderOnion: String,
        val pingWireBytesNormalized: String,
        val pingTimestamp: Long,
        val connectionId: Long,
        val startTime: Long,
    )

    // 
    // Main download orchestrator (split into phases for instruction limit)
    // 

    private suspend fun downloadMessage(contactId: Long, contactName: String, pingId: String, connectionId: Long = -1L) {
        currentContactId = contactId
        currentContactName = contactName
        downloadCompleted = false
        lastReceivedWireType = -1
        val startTime = System.currentTimeMillis()

        Log.i(TAG, "========== DOWNLOAD INITIATED ==========")
        Log.i(TAG, "Contact: $contactName (ID: $contactId)")
        Log.i(TAG, "Ping ID: $pingId")

        val keyManager = KeyManager.getInstance(this@DownloadMessageService)
        val dbPassphrase = keyManager.getDatabasePassphrase()
        val database = SecureLegionDatabase.getInstance(this@DownloadMessageService, dbPassphrase)

        // Phase 1: Load and validate ping data (before watchdog starts)
        val ctx = loadAndValidatePing(contactId, contactName, pingId, database, startTime, connectionId) ?: return

        // Start watchdog (single timeout owner — sets flag to stop poll loop)
        watchdogJob = serviceScope.launch {
            delay(DOWNLOAD_TIMEOUT_MS)
            if (!downloadCompleted) {
                onWatchdogTimeout(ctx)
            }
        }

        try {
            // Phase 2: Pre-flight health checks
            if (!runPreFlightChecks(ctx)) return

            // Phase 3: Restore ping session + expiry check
            if (!restorePingSession(ctx)) return

            // Phase 4: Send PONG (instant or listener path)
            val instantReceived = sendPongAndGetMessage(ctx)
            if (instantReceived == null) return // pong failed, already notified

            // Phase 5: Poll for message (skip if received instantly)
            if (!instantReceived) {
                if (!pollForMessage(ctx)) return // timeout already handled
            }

            // Phase 6: Success
            onDownloadSuccess(ctx)
        } finally {
            downloadCompleted = true
            watchdogJob?.cancel()
        }
    }

    // 
    // Phase 1: Load and validate ping data
    // 

    private suspend fun loadAndValidatePing(
        contactId: Long,
        contactName: String,
        pingId: String,
        database: SecureLegionDatabase,
        startTime: Long,
        liveConnectionId: Long = -1L,
    ): DownloadCtx? {
        // Load wire bytes from DB (single source of truth)
        val pingWireBytesFromDb = withContext(Dispatchers.IO) {
            database.pingInboxDao().getPingWireBytes(pingId)
        }

        if (pingWireBytesFromDb != null) {
            Log.i(TAG, "Found ping wire bytes in ping_inbox for pingId=$pingId (${pingWireBytesFromDb.length} chars)")
        } else {
            Log.w(TAG, "Ping wire bytes NOT FOUND in ping_inbox for pingId=$pingId")
        }

        val contact = withContext(Dispatchers.IO) {
            database.contactDao().getContactById(contactId)
        }

        if (contact == null) {
            Log.e(TAG, "Contact $contactId not found in database")
            showFailureNotification(contactName, "Contact not found", pingId, contactId)
            return null
        }

        val senderOnion: String = contact.messagingOnion ?: ""
        Log.i(TAG, "Connection ID from caller: $liveConnectionId (${if (liveConnectionId != -1L) "live TCP connection" else "no live connection"})")

        if (pingWireBytesFromDb == null) {
            Log.e(TAG, "Ping $pingId not found in ping_inbox for contact $contactId")
            showFailureNotification(contactName, "Message not found", pingId, contactId)
            return null
        }

        // Normalize wire bytes (legacy format migration)
        val raw = android.util.Base64.decode(pingWireBytesFromDb, android.util.Base64.NO_WRAP)

        if (raw.size < 33) {
            Log.e(TAG, "Invalid ping wire bytes too short (${raw.size} bytes, need >= 33) pingId=${pingId.take(8)}")
            showFailureNotification(contactName, "Corrupted message data", pingId, contactId)
            return null
        }

        val normalized = com.securelegion.crypto.RustBridge.normalizeWireBytes(0x01, raw)

        if (normalized.size != raw.size) {
            Log.i(TAG, "Normalized ping wire bytes: ${raw.size} → ${normalized.size} bytes (pingId=${pingId.take(8)})")
        }

        val typeByte = normalized[0].toInt() and 0xFF
        if (typeByte != 0x01) {
            Log.e(TAG, "Normalized wire has wrong type: 0x${typeByte.toString(16)} expected 0x01 pingId=${pingId.take(8)}")
            showFailureNotification(contactName, "Invalid message format", pingId, contactId)
            return null
        }

        val pingWireBytesNormalized = android.util.Base64.encodeToString(normalized, android.util.Base64.NO_WRAP)
        Log.i(TAG, "Ping metadata loaded successfully for contact $contactName")

        return DownloadCtx(
            contactId = contactId,
            contactName = contactName,
            pingId = pingId,
            database = database,
            senderOnion = senderOnion,
            pingWireBytesNormalized = pingWireBytesNormalized,
            pingTimestamp = System.currentTimeMillis(),
            connectionId = liveConnectionId,
            startTime = startTime,
        )
    }

    // 
    // Phase 2: Pre-flight health checks
    // 

    private suspend fun runPreFlightChecks(ctx: DownloadCtx): Boolean {
        Log.i(TAG, "========== PRE-FLIGHT HEALTH CHECKS ==========")
        updateNotification(ctx.contactName, "Checking connection...")

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
            showFailureNotification(ctx.contactName, errorMsg, ctx.pingId, ctx.contactId)
            return false
        }
        Log.i(TAG, "Tor bootstrap: 100%")

        val socksRunning = withContext(Dispatchers.IO) {
            try {
                com.securelegion.crypto.RustBridge.isSocksProxyRunning()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check SOCKS status", e)
                false
            }
        }

        if (!socksRunning) {
            Log.e(TAG, "Pre-flight check failed: SOCKS proxy not running")
            showFailureNotification(ctx.contactName, "SOCKS proxy not running", ctx.pingId, ctx.contactId)
            return false
        }
        Log.i(TAG, "SOCKS proxy: running")

        // Check circuit status from the already-authenticated event listener (no raw control-port probe)
        val circuitsEstablished = com.securelegion.crypto.RustBridge.getCircuitEstablished() >= 1

        if (!circuitsEstablished) {
            Log.w(TAG, "Circuits not established yet (non-critical)")
        } else {
            Log.i(TAG, "Circuits established")
        }

        Log.i(TAG, "All critical pre-flight checks passed")
        return true
    }

    // 
    // Phase 3: Restore ping session + expiry check
    // 

    private suspend fun restorePingSession(ctx: DownloadCtx): Boolean {
        updateNotification(ctx.contactName, "[1/4] Preparing download...")
        Log.i(TAG, "========== STAGE 1/4: PREPARING ==========")

        val restoredPingId = try {
            Log.d(TAG, "Restoring Ping from wire bytes (pingId=${ctx.pingId})")
            val encryptedPingWire = android.util.Base64.decode(ctx.pingWireBytesNormalized, android.util.Base64.NO_WRAP)

            withContext(Dispatchers.IO) {
                com.securelegion.crypto.RustBridge.decryptIncomingPing(encryptedPingWire)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restore Ping - Ping session is unrecoverable", e)

            withContext(Dispatchers.IO) {
                try {
                    ctx.database.pingInboxDao().delete(ctx.pingId)
                    Log.d(TAG, "Deleted unrecoverable ping from ping_inbox")
                } catch (cleanupError: Exception) {
                    Log.w(TAG, "Failed to clean up ping_inbox (non-critical)", cleanupError)
                }
            }

            showFailureNotification(ctx.contactName, "Message expired. Ask sender to resend.", ctx.pingId, ctx.contactId)
            return false
        }

        if (restoredPingId == null || restoredPingId != ctx.pingId) {
            Log.e(TAG, "Ping restoration failed or ID mismatch: expected=${ctx.pingId}, got=$restoredPingId")

            withContext(Dispatchers.IO) {
                try {
                    ctx.database.pingInboxDao().delete(ctx.pingId)
                    Log.d(TAG, "Deleted corrupted ping from ping_inbox")
                } catch (cleanupError: Exception) {
                    Log.w(TAG, "Failed to clean up ping_inbox (non-critical)", cleanupError)
                }
            }

            showFailureNotification(ctx.contactName, "Message corrupted. Ask sender to resend.", ctx.pingId, ctx.contactId)
            return false
        }

        Log.i(TAG, "Successfully restored Ping: ${ctx.pingId}")
        Log.i(TAG, "Sender onion: ${ctx.senderOnion}")
        Log.i(TAG, "Connection ID: ${if (ctx.connectionId != -1L) ctx.connectionId else "not available (using new connection)"}")
        Log.i(TAG, "Ping timestamp: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date(ctx.pingTimestamp))}")

        // FIX #5: PING Expiration Check - reject PINGs older than 7 days
        val pingAge = System.currentTimeMillis() - ctx.pingTimestamp
        val PING_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000L // 7 days (allows offline messaging)

        if (pingAge > PING_EXPIRY_MS) {
            val ageHours = pingAge / (60 * 60 * 1000)
            val ageDays = ageHours / 24
            Log.w(TAG, "Rejecting expired PING from ${ctx.contactName} (age: ${ageDays}d ${ageHours % 24}h, limit: 7 days)")

            withContext(Dispatchers.IO) {
                try {
                    ctx.database.pingInboxDao().delete(ctx.pingId)
                    Log.d(TAG, "Deleted expired ping from ping_inbox")
                } catch (cleanupError: Exception) {
                    Log.w(TAG, "Failed to clean up expired ping from ping_inbox (non-critical)", cleanupError)
                }
            }

            showFailureNotification(ctx.contactName, "Message expired (older than 7 days). Ask sender to resend.", ctx.pingId, ctx.contactId)
            return false
        }

        Log.i(TAG, "PING age check passed (age: ${pingAge / 1000}s, limit: ${PING_EXPIRY_MS / 1000}s)")
        return true
    }

    // 
    // Phase 4: Send PONG (instant or listener path)
    // 

    /**
     * Returns: true = instant message received, false = go to polling, null = fatal pong failure
     */
    private suspend fun sendPongAndGetMessage(ctx: DownloadCtx): Boolean? {
        updateNotification(ctx.contactName, "[2/4] Creating response...")
        Log.i(TAG, "========== STAGE 2/4: CREATING PONG ==========")

        val pongBytes = withContext(Dispatchers.IO) {
            val torManager = TorManager.getInstance(this@DownloadMessageService)
            torManager.respondToPing(ctx.pingId, authenticated = true)
        }

        if (pongBytes == null) {
            Log.e(TAG, "Failed to create Pong")
            showFailureNotification(ctx.contactName, "Failed to create response", ctx.pingId, ctx.contactId)
            return null
        }

        Log.i(TAG, "Pong created: ${pongBytes.size} bytes")
        Log.i(TAG, "========== STAGE 3/4: DOWNLOADING MESSAGE ==========")

        // DEDUPLICATION GUARD: Check if PONG was already sent for this pingId
        // Only skip if state is exactly PONG_SENT(1) or MSG_STORED(2).
        // States 10/11/12 (DOWNLOAD_QUEUED/FAILED_TEMP/MANUAL_REQUIRED) mean PONG was NOT sent yet.
        val alreadySentPong = withContext(Dispatchers.IO) {
            try {
                val pingInbox = ctx.database.pingInboxDao().getByPingId(ctx.pingId)
                val state = pingInbox?.state
                state == com.securelegion.database.entities.PingInbox.STATE_PONG_SENT ||
                    state == com.securelegion.database.entities.PingInbox.STATE_MSG_STORED
            } catch (e: Exception) {
                Log.w(TAG, "Failed to check if PONG already sent (proceeding with send anyway): ${e.message}")
                false
            }
        }

        if (alreadySentPong) {
            Log.i(TAG, "⊘ PONG already sent for pingId=${ctx.pingId.take(8)}... (deduplication guard) - skipping send, proceeding to polling")
        }

        // DB state is PONG_SENT during download — UI reads from ping_inbox
        broadcastStateUpdate(ctx.contactId)

        // DUAL-PATH APPROACH: Try instant reply first, then fall back to listener
        var pongSent = alreadySentPong // Pre-set to true if already sent
        var instantMessageReceived = false

        if (!alreadySentPong) {
            // Only attempt to send PONG if not already sent

            // PATH 1: Try sending Pong on original connection (instant messaging)
            // Check if connection is still alive (TCP-level check, clock-independent)
            // NOTE: Don't use pingTimestamp for freshness — clock skew between devices
            // causes false staleness. isConnectionAlive is the reliable check.
            if (ctx.connectionId != -1L) {
                val isAlive = withContext(Dispatchers.IO) {
                    try {
                        com.securelegion.crypto.RustBridge.isConnectionAlive(ctx.connectionId)
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to check connection status (assuming dead): ${e.message}")
                        false
                    }
                }

                if (isAlive) {
                    Log.d(TAG, "Connection is alive, attempting instant Pong on connection ${ctx.connectionId}...")
                    updateNotification(ctx.contactName, "[3/4] Downloading... (fast path)")
                    pongSent = withContext(Dispatchers.IO) {
                        try {
                            val messageBytes = com.securelegion.crypto.RustBridge.sendPongBytes(ctx.connectionId, pongBytes)
                            if (messageBytes != null) {
                                Log.i(TAG, "Pong sent on original connection! Received message blob: ${messageBytes.size} bytes")
                                handleInstantMessageBlob(messageBytes, ctx.contactId, ctx.contactName, ctx.pingId, ctx.connectionId)
                                instantMessageReceived = true
                                true
                            } else {
                                Log.w(TAG, "sendPongBytes returned null (connection likely closed)")
                                false
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Instant Pong reply failed (connection closed): ${e.message}")
                            false
                        }
                    }
                } else {
                    Log.d(TAG, "Connection is dead (not responding), skipping instant path - will use listener")
                    updateNotification(ctx.contactName, "[3/4] Downloading... (slower path)")
                }
            }

            // PATH 2: If instant path failed, fall back to listener with retry
            // Tor circuits are flaky — retry with exponential backoff capped at 10s
            if (!pongSent) {
                Log.d(TAG, "Falling back to listener-based Pong delivery (with retry)...")
                val maxPongRetries = 5
                var pongDelay = 2000L
                for (pongAttempt in 1..maxPongRetries) {
                    if (downloadCompleted) {
                        Log.w(TAG, "Watchdog fired during PONG retry — aborting")
                        break
                    }
                    updateNotification(ctx.contactName, "[3/4] Sending response... ($pongAttempt/$maxPongRetries)")
                    pongSent = withContext(Dispatchers.IO) {
                        try {
                            com.securelegion.crypto.RustBridge.sendPongToListener(ctx.senderOnion, pongBytes)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to send Pong to listener (attempt $pongAttempt/$maxPongRetries)", e)
                            false
                        }
                    }
                    if (pongSent) {
                        Log.i(TAG, "Pong sent via listener (attempt $pongAttempt/$maxPongRetries)")
                        break
                    }
                    if (pongAttempt < maxPongRetries) {
                        Log.w(TAG, "Pong send failed (attempt $pongAttempt/$maxPongRetries), retrying in ${pongDelay}ms...")
                        delay(pongDelay)
                        pongDelay = (pongDelay * 2).coerceAtMost(10_000L)
                    } else {
                        Log.e(TAG, "Pong send FAILED after $maxPongRetries attempts")
                    }
                }
            }
        } // Close if (!alreadySentPong) block

        if (!pongSent) {
            Log.e(TAG, "Pong send failed")
            showFailureNotification(ctx.contactName, "Failed to send response", ctx.pingId, ctx.contactId)
            return null
        }

        // Transition DB: DOWNLOAD_QUEUED(10) → PONG_SENT(1)
        // This MUST happen after pong is actually sent so TorService can find the active download
        if (!alreadySentPong) {
            withContext(Dispatchers.IO) {
                val transitioned = ctx.database.pingInboxDao().transitionToPongSent(ctx.pingId, System.currentTimeMillis())
                Log.d(TAG, "DB transition to PONG_SENT: result=$transitioned for pingId=${ctx.pingId.take(8)}")
            }
        }

        return instantMessageReceived
    }

    // 
    // Phase 5: Poll for message
    // 

    private suspend fun pollForMessage(ctx: DownloadCtx): Boolean {
        Log.i(TAG, "Pong sent! Now waiting for message payload...")

        // DB state PONG_SENT tracks active download — TorService reads ping_inbox directly
        Log.d(TAG, "Active download tracked via ping_inbox (state=PONG_SENT): pingId=${ctx.pingId.take(8)}")

        updateNotification(ctx.contactName, "Waiting for message...")

        // Get current message count BEFORE polling
        val initialMessageCount = withContext(Dispatchers.IO) {
            ctx.database.messageDao().getMessagesForContact(ctx.contactId).size
        }
        Log.d(TAG, "Current message count before polling: $initialMessageCount")

        // Hard-gated poll loop: watchdog is the ONLY timeout authority.
        // This loop just polls. It does NOT handle timeouts.
        var attempt = 0
        while (kotlin.coroutines.coroutineContext[Job]?.isActive != false && !downloadCompleted) {
            attempt++
            Log.d(TAG, "Polling attempt $attempt...")
            updateNotification(ctx.contactName, "Downloading... (${attempt}s)")

            delay(1000) // 1s per poll

            val currentMessageCount = withContext(Dispatchers.IO) {
                ctx.database.messageDao().getMessagesForContact(ctx.contactId).size
            }

            if (currentMessageCount > initialMessageCount) {
                Log.i(TAG, "NEW message found in database! ($initialMessageCount → $currentMessageCount)")
                return true
            } else {
                Log.d(TAG, "No new messages yet (count still $currentMessageCount)")
            }
        }

        // Loop exited because watchdog set downloadCompleted or scope cancelled
        Log.d(TAG, "Poll loop ended — watchdog timeout or scope cancelled (attempt $attempt, downloadCompleted=$downloadCompleted)")
        return false
    }

    // 
    // Phase 6: Download success
    // 

    private suspend fun onDownloadSuccess(ctx: DownloadCtx) {
        // Transition ping_inbox to MSG_STORED
        withContext(Dispatchers.IO) {
            Log.i(TAG, "→ Transitioning pingId=${ctx.pingId} to MSG_STORED (listener path)")
            val now = System.currentTimeMillis()
            ctx.database.pingInboxDao().transitionToMsgStored(ctx.pingId, now)
            ctx.database.pingInboxDao().clearPingWireBytes(ctx.pingId, now) // Free up DB space
        }

        // Send MESSAGE_ACK to sender after successfully receiving the message
        // connectionId not available here (polling path), so pass -1L
        sendMessageAck(ctx.contactId, ctx.contactName, -1L, ctx.pingId)

        // Dismiss the pending message notification
        val notifManager = getSystemService(android.app.NotificationManager::class.java)
        val notificationId = ctx.contactId.toInt() + 20000
        notifManager?.cancel(notificationId)
        Log.i(TAG, "Dismissed pending message notification (ID: $notificationId)")

        // Broadcast to ChatActivity to refresh
        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
        intent.setPackage(packageName)
        intent.putExtra("CONTACT_ID", ctx.contactId)
        sendBroadcast(intent)
        Log.i(TAG, "Broadcast sent to refresh UI")

        // For the polling path, determine wire type from the last received message
        if (lastReceivedWireType == -1) {
            val lastMsg = withContext(Dispatchers.IO) {
                ctx.database.messageDao().getLastMessage(ctx.contactId)
            }
            if (lastMsg != null) {
                lastReceivedWireType = when (lastMsg.messageType) {
                    com.securelegion.database.entities.Message.MESSAGE_TYPE_TEXT -> 0x03
                    com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE -> 0x04
                    com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE -> 0x09
                    else -> 0x03 // Default to text
                }
            }
        }

        // showSuccessNotification is type-aware — returns early for 0x0F (profile update)
        showSuccessNotification(ctx.contactName)
        Log.d(TAG, "Download completed in ${System.currentTimeMillis() - ctx.startTime}ms")
    }

    // 
    // Timeout handlers
    // 

    private suspend fun onWatchdogTimeout(ctx: DownloadCtx) {
        val elapsed = System.currentTimeMillis() - ctx.startTime
        Log.e(TAG, "WATCHDOG TIMEOUT after ${elapsed}ms")
        Log.e(TAG, "Contact: ${ctx.contactName} (ID: ${ctx.contactId})")
        Log.e(TAG, "Ping ID: ${ctx.pingId}")

        try {
            val torStatus = checkTorStatus()
            Log.e(TAG, "Tor Status: $torStatus")
        } catch (e: Exception) {
            Log.e(TAG, "Tor Status: Error - ${e.message}")
        }

        // Mark completed FIRST to stop poll loop
        downloadCompleted = true

        // Transition DB (NonCancellable so it runs even if scope is cancelled)
        withContext(NonCancellable + Dispatchers.IO) {
            try {
                val now = System.currentTimeMillis()
                val failed = ctx.database.pingInboxDao().failAutoDownload(
                    pingId = ctx.pingId,
                    now = now,
                    maxRetries = 1
                )
                Log.w(TAG, "Watchdog → failAutoDownload result=$failed for pingId=${ctx.pingId.take(8)}")
            } catch (e: Exception) {
                Log.w(TAG, "Watchdog DB transition failed: ${e.message}")
            }
        }

        // Broadcast DOWNLOAD_FAILED so ChatActivity clears downloadingPingIds
        val failIntent = Intent("com.securelegion.DOWNLOAD_FAILED")
        failIntent.setPackage(packageName)
        failIntent.putExtra("CONTACT_ID", ctx.contactId)
        sendBroadcast(failIntent)

        showFailureNotification(ctx.contactName, "Download timed out (${DOWNLOAD_TIMEOUT_MS / 1000}s). Check connection.", ctx.pingId, ctx.contactId)
    }


    // 
    // Helper methods
    // 

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
        // Use SINGLE_TOP to prevent restarting LockActivity if it's already running
        val intent = Intent(this, LockActivity::class.java).apply {
            if (currentContactId != -1L) {
                putExtra("TARGET_ACTIVITY", "ChatActivity")
                putExtra(ChatActivity.EXTRA_CONTACT_ID, currentContactId)
                putExtra(ChatActivity.EXTRA_CONTACT_NAME, currentContactName)
            } else {
                putExtra("TARGET_ACTIVITY", "MainActivity")
            }
            // Use SINGLE_TOP instead of CLEAR_TOP to avoid restarting the activity
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
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
        // Type-specific notification text based on wire format
        val (title, text) = when (lastReceivedWireType) {
            0x03 -> "New message" to "New message from $contactName"
            0x04 -> "New voice clip" to "New voice clip from $contactName"
            0x09 -> "New image" to "New image from $contactName"
            0x0A -> "Payment request" to "New payment request from $contactName"
            0x0B -> "Payment received" to "Payment sent by $contactName"
            0x0C -> "Payment accepted" to "Payment accepted by $contactName"
            0x0F -> return // Profile update — no notification
            else -> "New message" to "New message from $contactName"
        }

        // Launch via LockActivity to prevent showing chat before authentication
        val intent = Intent(this, LockActivity::class.java).apply {
            if (currentContactId != -1L) {
                putExtra("TARGET_ACTIVITY", "ChatActivity")
                putExtra(ChatActivity.EXTRA_CONTACT_ID, currentContactId)
                putExtra(ChatActivity.EXTRA_CONTACT_NAME, currentContactName)
            } else {
                putExtra("TARGET_ACTIVITY", "MainActivity")
            }
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, currentContactId.toInt(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_lock)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        notificationManager?.notify(NOTIFICATION_ID, notification)
    }

    private fun showFailureNotification(contactName: String, error: String, pingId: String? = null, contactId: Long = -1L) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Download failed")
            .setContentText("Failed to download message from $contactName: $error")
            .setSmallIcon(R.drawable.ic_lock)
            .setAutoCancel(true)
            .build()

        notificationManager?.notify(NOTIFICATION_ID, notification)

        // Transition DB state so lock icon reappears for retry (idempotent — safe to call multiple times)
        if (pingId != null && contactId > 0) {
            serviceScope.launch(NonCancellable + Dispatchers.IO) {
                try {
                    val keyManager = KeyManager.getInstance(this@DownloadMessageService)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@DownloadMessageService, dbPassphrase)
                    val now = System.currentTimeMillis()

                    // Transition DOWNLOAD_QUEUED/PONG_SENT → MANUAL_REQUIRED
                    val failed = database.pingInboxDao().failAutoDownload(
                        pingId = pingId,
                        now = now,
                        maxRetries = 1
                    )
                    Log.d(TAG, "showFailureNotification → failAutoDownload result=$failed for pingId=${pingId.take(8)}")

                    // Broadcast DOWNLOAD_FAILED so ChatActivity clears downloadingPingIds
                    val failIntent = Intent("com.securelegion.DOWNLOAD_FAILED")
                    failIntent.setPackage(packageName)
                    failIntent.putExtra("CONTACT_ID", contactId)
                    sendBroadcast(failIntent)
                    Log.d(TAG, "DOWNLOAD_FAILED broadcast sent for pingId=${pingId.take(8)}")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to transition ping state on download failure: ${e.message}")
                }
            }
        }
    }

    /**
     * Broadcast state update to ChatActivity to refresh UI
     */
    private fun broadcastStateUpdate(contactId: Long) {
        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
        intent.setPackage(packageName)
        intent.putExtra("CONTACT_ID", contactId)
        sendBroadcast(intent)
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
            lastReceivedWireType = typeByte.toInt() and 0xFF
            Log.d(TAG, "Message type byte: 0x${String.format("%02X", typeByte)}")

            // Extract fields based on message type
            val senderX25519PublicKey: ByteArray
            val encryptedPayload: ByteArray
            val voiceDuration: Int?

            when (typeByte.toInt()) {
                0x03 -> {
                    // TEXT message: [0x03][X25519 32 bytes][Encrypted Text]
                    // Minimum: 1 (type) + 32 (X25519) + 1 (version) + 8 (seq) + 24 (nonce) + 16 (tag) = 82 bytes
                    if (messageBytes.size < 82) {
                        Log.e(TAG, "TEXT message blob too small: ${messageBytes.size} bytes (need at least 82)")
                        return
                    }
                    senderX25519PublicKey = messageBytes.copyOfRange(1, 33)
                    encryptedPayload = messageBytes.copyOfRange(33, messageBytes.size)
                    voiceDuration = null
                }
                0x04 -> {
                    // VOICE message: [0x04][X25519 32 bytes][Encrypted(0x01+duration+audio)]
                    // Same wire format as TEXT — duration is INSIDE the encrypted payload
                    // Minimum: 1 (type) + 32 (X25519) + 1 (version) + 8 (seq) + 24 (nonce) + 16 (tag) = 82 bytes
                    if (messageBytes.size < 82) {
                        Log.e(TAG, "VOICE message blob too small: ${messageBytes.size} bytes (need at least 82)")
                        return
                    }
                    senderX25519PublicKey = messageBytes.copyOfRange(1, 33)
                    encryptedPayload = messageBytes.copyOfRange(33, messageBytes.size)
                    voiceDuration = null // extracted from decrypted payload by receiveMessage
                }
                0x09 -> {
                    // IMAGE message: [0x09][X25519 32 bytes][Encrypted Image]
                    // Minimum: 1 (type) + 32 (X25519) + 1 (version) + 8 (seq) + 24 (nonce) + 16 (tag) = 82 bytes
                    if (messageBytes.size < 82) {
                        Log.e(TAG, "IMAGE message blob too small: ${messageBytes.size} bytes (need at least 82)")
                        return
                    }
                    senderX25519PublicKey = messageBytes.copyOfRange(1, 33)
                    encryptedPayload = messageBytes.copyOfRange(33, messageBytes.size)
                    voiceDuration = null
                }
                0x0A, 0x0B, 0x0C -> {
                    // PAYMENT messages: [0x0A/0x0B/0x0C][X25519 32 bytes][Encrypted Payment Data]
                    // 0x0A = PAYMENT_REQUEST, 0x0B = PAYMENT_SENT, 0x0C = PAYMENT_ACCEPTED
                    // Minimum: 1 (type) + 32 (X25519) + 1 (version) + 8 (seq) + 24 (nonce) + 16 (tag) = 82 bytes
                    if (messageBytes.size < 82) {
                        Log.e(TAG, "PAYMENT message blob too small: ${messageBytes.size} bytes (need at least 82)")
                        return
                    }
                    senderX25519PublicKey = messageBytes.copyOfRange(1, 33)
                    encryptedPayload = messageBytes.copyOfRange(33, messageBytes.size)
                    voiceDuration = null
                    Log.d(TAG, "Payment message type: 0x${String.format("%02X", typeByte)}")
                }
                0x0F -> {
                    // PROFILE_UPDATE: [0x0F][X25519 32 bytes][Encrypted Photo]
                    // Same wire format as IMAGE/TEXT
                    if (messageBytes.size < 82) {
                        Log.e(TAG, "PROFILE_UPDATE message blob too small: ${messageBytes.size} bytes (need at least 82)")
                        return
                    }
                    senderX25519PublicKey = messageBytes.copyOfRange(1, 33)
                    encryptedPayload = messageBytes.copyOfRange(33, messageBytes.size)
                    voiceDuration = null
                    Log.d(TAG, "Profile update message received")
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

            // PING INBOX STATE CHECK: Verify state and transition to PONG_SENT
            Log.d(TAG, "PING INBOX CHECK: pingId=$pingId ")
            val pingInbox = database.pingInboxDao().getByPingId(pingId)

            if (pingInbox == null) {
                Log.w(TAG, "Ping $pingId not in ping_inbox - this shouldn't happen")
                // Fallback: check messages DB
                val existingMessage = database.messageDao().getMessageByPingId(pingId)
                if (existingMessage != null) {
                    Log.i(TAG, "Message $pingId found in DB (fallback check)")

                    // Send MESSAGE_ACK
                    sendMessageAck(contactId, contactName, connectionId, pingId)

                    // Broadcast to refresh UI
                    val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                    intent.setPackage(packageName)
                    intent.putExtra("CONTACT_ID", contactId)
                    sendBroadcast(intent)

                    return
                }
                // Continue with download if not in DB
            } else if (pingInbox.state == com.securelegion.database.entities.PingInbox.STATE_MSG_STORED) {
                // Already stored - send MESSAGE_ACK and skip
                Log.i(TAG, "Message $pingId already stored (state=MSG_STORED)")

                // Send MESSAGE_ACK (idempotent)
                sendMessageAck(contactId, contactName, connectionId, pingId)

                // Broadcast to refresh UI
                val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                intent.setPackage(packageName)
                intent.putExtra("CONTACT_ID", contactId)
                sendBroadcast(intent)

                return
            } else {
                // Transition to PONG_SENT if currently PING_SEEN
                if (pingInbox.state == com.securelegion.database.entities.PingInbox.STATE_PING_SEEN) {
                    Log.i(TAG, "→ Transitioning pingId=$pingId to PONG_SENT")
                    database.pingInboxDao().transitionToPongSent(pingId, System.currentTimeMillis())
                }
            }

            Log.i(TAG, "Message $pingId not yet stored - proceeding with download")

            // Get sender's Ed25519 public key for decryption
            val senderPublicKey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)

            // Decrypt message using Ed25519 key
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // DB state is PONG_SENT during decryption — UI reads from ping_inbox
            broadcastStateUpdate(contactId)

            when (typeByte.toInt()) {
                0x03 -> {
                    // TEXT message (MSG_TYPE_TEXT = 0x03)
                    Log.d(TAG, "Processing TEXT message...")

                    // Save to database via MessageService
                    val messageService = MessageService(this@DownloadMessageService)
                    // Pass encrypted payload directly - it's already in the correct wire format
                    // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
                    // DON'T prepend X25519 key - that's not part of the key chain evolution format
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    // ATOMIC TRANSACTION: Check duplicate + Insert message + update ping_inbox state
                    val result = kotlin.runCatching {
                        database.withTransaction {
                            // Check if message already exists by pingId (BEFORE attempting insert)
                            // This prevents SQL exception from UNIQUE constraint and ensures state transition
                            val existingMessage = database.messageDao().getMessageByPingId(pingId)

                            if (existingMessage != null) {
                                // Duplicate detected - message already in DB
                                Log.i(TAG, "Message $pingId already in DB (duplicate insert via multipath/retry)")

                                // CRITICAL: Still transition ping_inbox to MSG_STORED (idempotent, monotonic guard)
                                // This ensures duplicates don't get stuck in PONG_SENT state
                                val now = System.currentTimeMillis()
                                database.pingInboxDao().transitionToMsgStored(pingId, now)
                                database.pingInboxDao().clearPingWireBytes(pingId, now) // Free up DB space

                                // Return success with existing message (not a failure!)
                                Result.success(existingMessage)
                            } else {
                                // New message - insert it
                                val insertResult = messageService.receiveMessage(
                                    encryptedData = encryptedBase64,
                                    senderPublicKey = senderPublicKey,
                                    senderOnionAddress = contact.messagingOnion ?: "",
                                    pingId = pingId
                                )

                                if (insertResult.isSuccess) {
                                    // Transition ping_inbox to MSG_STORED (monotonic guard prevents regression)
                                    Log.i(TAG, "→ Transitioning pingId=$pingId to MSG_STORED (atomic)")
                                    val now = System.currentTimeMillis()
                                    database.pingInboxDao().transitionToMsgStored(pingId, now)
                                    database.pingInboxDao().clearPingWireBytes(pingId, now) // Free up DB space
                                }

                                insertResult
                            }
                        }
                    }

                    if (result.isSuccess && result.getOrNull()?.isSuccess == true) {
                        Log.i(TAG, "TEXT message saved to database (atomic transaction)")

                        // Broadcast to refresh UI
                        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                        intent.setPackage(packageName)
                        intent.putExtra("CONTACT_ID", contactId)
                        sendBroadcast(intent)
                        Log.i(TAG, "Broadcast sent to refresh UI")

                        // Send MESSAGE_ACK ("I stored the message")
                        serviceScope.launch(Dispatchers.IO) {
                            try {
                                sendMessageAck(contactId, contactName, connectionId, pingId)
                                Log.i(TAG, "MESSAGE_ACK sent")

                                // Clean up Rust Ping session AFTER MESSAGE_ACK sent successfully
                                // This prevents orphaned messages if there's a delay between Pong and MESSAGE
                                try {
                                    com.securelegion.crypto.RustBridge.removePingSession(pingId)
                                    Log.d(TAG, "Cleaned up Rust Ping session for pingId: $pingId")
                                } catch (cleanupError: Exception) {
                                    Log.w(TAG, "Failed to clean up Ping session (non-critical)", cleanupError)
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "MESSAGE_ACK failed (non-critical): ${e.message}")
                            }
                        }

                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            // Message was already downloaded, so clear the notification and send ACK
                            sendMessageAck(contactId, contactName, connectionId, pingId)
                            val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                            notifMgr?.cancel(contactId.toInt() + 20000)
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
                    // Pass encrypted payload directly - it's already in the correct wire format
                    // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
                    // DON'T prepend X25519 key - that's not part of the key chain evolution format
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    // ATOMIC TRANSACTION: Check duplicate + Insert message + update ping_inbox state
                    val result = kotlin.runCatching {
                        database.withTransaction {
                            // Check if message already exists by pingId (BEFORE attempting insert)
                            val existingMessage = database.messageDao().getMessageByPingId(pingId)

                            if (existingMessage != null) {
                                // Duplicate detected - message already in DB
                                Log.i(TAG, "VOICE message $pingId already in DB (duplicate insert via multipath/retry)")

                                // CRITICAL: Still transition ping_inbox to MSG_STORED (idempotent, monotonic guard)
                                val now = System.currentTimeMillis()
                                database.pingInboxDao().transitionToMsgStored(pingId, now)
                                database.pingInboxDao().clearPingWireBytes(pingId, now) // Free up DB space

                                // Return success with existing message (not a failure!)
                                Result.success(existingMessage)
                            } else {
                                // New message - insert it
                                val insertResult = messageService.receiveMessage(
                                    encryptedData = encryptedBase64,
                                    senderPublicKey = senderPublicKey,
                                    senderOnionAddress = contact.messagingOnion ?: "",
                                    messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE,
                                    voiceDuration = voiceDuration ?: 0, // Safe default instead of crash
                                    pingId = pingId
                                )

                                if (insertResult.isSuccess) {
                                    Log.i(TAG, "→ Transitioning pingId=$pingId to MSG_STORED (atomic)")
                                    val now = System.currentTimeMillis()
                                    database.pingInboxDao().transitionToMsgStored(pingId, now)
                                    database.pingInboxDao().clearPingWireBytes(pingId, now) // Free up DB space
                                }

                                insertResult
                            }
                        }
                    }

                    if (result.isSuccess && result.getOrNull()?.isSuccess == true) {
                        Log.i(TAG, "VOICE message saved to database (atomic transaction)")

                        // Broadcast to refresh UI
                        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                        intent.setPackage(packageName)
                        intent.putExtra("CONTACT_ID", contactId)
                        sendBroadcast(intent)
                        Log.i(TAG, "Broadcast sent to refresh UI")

                        // Send MESSAGE_ACK to sender
                        sendMessageAck(contactId, contactName, connectionId, pingId)
                        // Dismiss the pending message notification
                        val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                        notifMgr?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            // Message was already downloaded, so clear the notification and send ACK
                            sendMessageAck(contactId, contactName, connectionId, pingId)
                            val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                            notifMgr?.cancel(contactId.toInt() + 20000)
                        } else {
                            Log.e(TAG, "Failed to save VOICE message: $errorMessage")
                        }
                    }
                }

                0x09 -> {
                    // IMAGE message (MSG_TYPE_IMAGE = 0x09)
                    Log.d(TAG, "Processing IMAGE message...")

                    // Save to database via MessageService
                    val messageService = MessageService(this@DownloadMessageService)
                    // Pass encrypted payload directly - it's already in the correct wire format
                    // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
                    // DON'T prepend X25519 key - that's not part of the key chain evolution format
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    // ATOMIC TRANSACTION: Check duplicate + Insert message + update ping_inbox state
                    val result = kotlin.runCatching {
                        database.withTransaction {
                            // Check if message already exists by pingId (BEFORE attempting insert)
                            val existingMessage = database.messageDao().getMessageByPingId(pingId)

                            if (existingMessage != null) {
                                // Duplicate detected - message already in DB
                                Log.i(TAG, "IMAGE message $pingId already in DB (duplicate insert via multipath/retry)")

                                // CRITICAL: Still transition ping_inbox to MSG_STORED (idempotent, monotonic guard)
                                val now = System.currentTimeMillis()
                                database.pingInboxDao().transitionToMsgStored(pingId, now)
                                database.pingInboxDao().clearPingWireBytes(pingId, now) // Free up DB space

                                // Return success with existing message (not a failure!)
                                Result.success(existingMessage)
                            } else {
                                // New message - insert it
                                val insertResult = messageService.receiveMessage(
                                    encryptedData = encryptedBase64,
                                    senderPublicKey = senderPublicKey,
                                    senderOnionAddress = contact.messagingOnion ?: "",
                                    messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE,
                                    pingId = pingId
                                )

                                if (insertResult.isSuccess) {
                                    Log.i(TAG, "→ Transitioning pingId=$pingId to MSG_STORED (atomic)")
                                    val now = System.currentTimeMillis()
                                    database.pingInboxDao().transitionToMsgStored(pingId, now)
                                    database.pingInboxDao().clearPingWireBytes(pingId, now) // Free up DB space
                                }

                                insertResult
                            }
                        }
                    }

                    if (result.isSuccess && result.getOrNull()?.isSuccess == true) {
                        Log.i(TAG, "IMAGE message saved to database (atomic transaction)")

                        // Broadcast to refresh UI
                        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                        intent.setPackage(packageName)
                        intent.putExtra("CONTACT_ID", contactId)
                        sendBroadcast(intent)
                        Log.i(TAG, "Broadcast sent to refresh UI")

                        // Send MESSAGE_ACK to sender
                        sendMessageAck(contactId, contactName, connectionId, pingId)
                        // Dismiss the pending message notification
                        val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                        notifMgr?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            // Message was already downloaded, so clear the notification and send ACK
                            sendMessageAck(contactId, contactName, connectionId, pingId)
                            val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                            notifMgr?.cancel(contactId.toInt() + 20000)
                        } else {
                            Log.e(TAG, "Failed to save IMAGE message: $errorMessage")
                        }
                    }
                }

                0x0A -> {
                    // PAYMENT_REQUEST message (MSG_TYPE_PAYMENT_REQUEST = 0x0A)
                    Log.d(TAG, "Processing PAYMENT_REQUEST message...")

                    val messageService = MessageService(this@DownloadMessageService)
                    // Pass encrypted payload directly - it's already in the correct wire format
                    // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
                    // DON'T prepend X25519 key - that's not part of the key chain evolution format
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    val result = messageService.receiveMessage(
                        encryptedData = encryptedBase64,
                        senderPublicKey = senderPublicKey,
                        senderOnionAddress = contact.messagingOnion ?: "",
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST,
                        pingId = pingId
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "PAYMENT_REQUEST message saved to database")

                        // Broadcast to trigger ChatActivity refresh
                        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                        intent.setPackage(packageName)
                        intent.putExtra("CONTACT_ID", contactId)
                        sendBroadcast(intent)
                        Log.i(TAG, "Broadcast sent to refresh UI")

                        sendMessageAck(contactId, contactName, connectionId, pingId)
                        val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                        notifMgr?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            sendMessageAck(contactId, contactName, connectionId, pingId)
                            val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                            notifMgr?.cancel(contactId.toInt() + 20000)
                        } else {
                            Log.e(TAG, "Failed to save PAYMENT_REQUEST message: $errorMessage")
                        }
                    }
                }

                0x0B -> {
                    // PAYMENT_SENT message (MSG_TYPE_PAYMENT_SENT = 0x0B)
                    Log.d(TAG, "Processing PAYMENT_SENT message...")

                    val messageService = MessageService(this@DownloadMessageService)
                    // Pass encrypted payload directly - DON'T prepend X25519 key
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    val result = messageService.receiveMessage(
                        encryptedData = encryptedBase64,
                        senderPublicKey = senderPublicKey,
                        senderOnionAddress = contact.messagingOnion ?: "",
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT,
                        pingId = pingId
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "PAYMENT_SENT message saved to database")

                        // Broadcast to trigger ChatActivity refresh
                        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                        intent.setPackage(packageName)
                        intent.putExtra("CONTACT_ID", contactId)
                        sendBroadcast(intent)
                        Log.i(TAG, "Broadcast sent to refresh UI")

                        sendMessageAck(contactId, contactName, connectionId, pingId)
                        val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                        notifMgr?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            sendMessageAck(contactId, contactName, connectionId, pingId)
                            val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                            notifMgr?.cancel(contactId.toInt() + 20000)
                        } else {
                            Log.e(TAG, "Failed to save PAYMENT_SENT message: $errorMessage")
                        }
                    }
                }

                0x0C -> {
                    // PAYMENT_ACCEPTED message (MSG_TYPE_PAYMENT_ACCEPTED = 0x0C)
                    Log.d(TAG, "Processing PAYMENT_ACCEPTED message...")

                    val messageService = MessageService(this@DownloadMessageService)
                    // Pass encrypted payload directly - DON'T prepend X25519 key
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    val result = messageService.receiveMessage(
                        encryptedData = encryptedBase64,
                        senderPublicKey = senderPublicKey,
                        senderOnionAddress = contact.messagingOnion ?: "",
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED,
                        pingId = pingId
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "PAYMENT_ACCEPTED message saved to database")

                        // Broadcast to trigger ChatActivity refresh
                        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                        intent.setPackage(packageName)
                        intent.putExtra("CONTACT_ID", contactId)
                        sendBroadcast(intent)
                        Log.i(TAG, "Broadcast sent to refresh UI")

                        sendMessageAck(contactId, contactName, connectionId, pingId)
                        val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                        notifMgr?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            sendMessageAck(contactId, contactName, connectionId, pingId)
                            val notifMgr = getSystemService(android.app.NotificationManager::class.java)
                            notifMgr?.cancel(contactId.toInt() + 20000)
                        } else {
                            Log.e(TAG, "Failed to save PAYMENT_ACCEPTED message: $errorMessage")
                        }
                    }
                }

                0x0F -> {
                    // PROFILE_UPDATE - process via receiveMessage which handles decryption + contact update
                    Log.d(TAG, "Processing PROFILE_UPDATE message...")
                    val messageService = MessageService(this@DownloadMessageService)
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedPayload, android.util.Base64.NO_WRAP)

                    val result = kotlin.runCatching {
                        database.withTransaction {
                            messageService.receiveMessage(
                                encryptedData = encryptedBase64,
                                senderPublicKey = senderPublicKey,
                                senderOnionAddress = contact.messagingOnion ?: "",
                                messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_PROFILE_UPDATE,
                                pingId = pingId
                            )
                        }
                    }

                    // Profile update is handled inside receiveMessage (returns failure with "Profile update processed")
                    // Always send ACK and transition state
                    val now = System.currentTimeMillis()
                    database.pingInboxDao().transitionToMsgStored(pingId, now)
                    database.pingInboxDao().clearPingWireBytes(pingId, now)

                    serviceScope.launch(Dispatchers.IO) {
                        try {
                            sendMessageAck(contactId, contactName, connectionId, pingId)
                            Log.i(TAG, "PROFILE_UPDATE MESSAGE_ACK sent")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to send MESSAGE_ACK for profile update", e)
                        }
                    }

                    // Suppress "new message" notification — profile updates are invisible background syncs
                    val notifManager = getSystemService(android.app.NotificationManager::class.java)
                    val remainingPending = withContext(Dispatchers.IO) {
                        database.pingInboxDao().countGlobalPending()
                    }
                    if (remainingPending == 0) {
                        notifManager?.cancel(999) // Cancel global pending message notification
                        Log.d(TAG, "Cancelled notification 999 (no more pending pings after profile update)")
                    } else {
                        Log.d(TAG, "Keeping notification 999 ($remainingPending other pending pings remain)")
                    }

                    // Broadcast to refresh UI (profile photo + clear pending ping indicator)
                    val refreshIntent = Intent("com.securelegion.PROFILE_UPDATED")
                    refreshIntent.setPackage(packageName)
                    refreshIntent.putExtra("CONTACT_ID", contactId)
                    sendBroadcast(refreshIntent)

                    // Also send MESSAGE_RECEIVED to refresh chat list and clear pending ping from UI
                    val msgReceivedIntent = Intent("com.securelegion.MESSAGE_RECEIVED")
                    msgReceivedIntent.setPackage(packageName)
                    msgReceivedIntent.putExtra("CONTACT_ID", contactId)
                    sendBroadcast(msgReceivedIntent)

                    Log.i(TAG, "Profile update processed for ${contactName} (silent, no notification)")
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
     * @param pingId The actual pingId to ACK (must match the downloaded message)
     */
    private suspend fun sendMessageAck(contactId: Long, contactName: String, connectionId: Long, pingId: String) {
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

            // Use the pingId parameter directly (no DB query needed - prevents ACKing wrong message)
            Log.d(TAG, "Sending MESSAGE_ACK with retry for pingId=$pingId to $contactName")

            // Validate onion address is not empty
            val onionAddress = contact.messagingOnion
            if (onionAddress.isNullOrBlank()) {
                Log.e(TAG, "No onion address for contactId=$contactId; cannot send MESSAGE_ACK")
                return
            }

            val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)
            val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)

            // Retry logic with exponential backoff (3 attempts: 1s, 2s delays)
            val maxRetries = 3
            var delayMs = 1000L
            var attempt = 0

            while (attempt < maxRetries) {
                try {
                    var ackSuccess = false

                    // ARCHITECTURAL DECISION: All ACKs MUST go to peer's messaging .onion, NOT on incoming connection.
                    // Connection reuse optimization is disabled because:
                    // 1. Incoming connections are ephemeral (closed after message received)
                    // 2. Reusing non-existent connections fails with "Connection not found"
                    // 3. Sending ACKs as new outgoing messages to peer's .onion is reliable
                    // 4. Clean architecture > micro-optimization
                    //
                    // Connection reuse code preserved but disabled:
                    if (false && connectionId >= 0) {
                        ackSuccess = withContext(Dispatchers.IO) {
                            com.securelegion.crypto.RustBridge.sendAckOnConnection(
                                connectionId,
                                pingId,
                                "MESSAGE_ACK",
                                senderX25519Pubkey
                            )
                        }

                        if (ackSuccess) {
                            Log.i(TAG, "MESSAGE_ACK sent successfully on existing connection for pingId=$pingId (attempt ${attempt + 1})")
                            return // Success!
                        }

                        Log.d(TAG, "Connection closed, falling back to new connection for MESSAGE_ACK (attempt ${attempt + 1})")
                    }

                    // All ACKs now use peer's messaging .onion
                    Log.d(TAG, "Sending MESSAGE_ACK via new connection to peer's messaging .onion (connection reuse disabled)")

                    // PATH 2 (always used): Open new connection to peer's messaging .onion
                    ackSuccess = withContext(Dispatchers.IO) {
                        com.securelegion.crypto.RustBridge.sendDeliveryAck(
                            pingId,
                            "MESSAGE_ACK",
                            senderEd25519Pubkey,
                            senderX25519Pubkey,
                            contact.messagingOnion ?: ""
                        )
                    }

                    if (ackSuccess) {
                        Log.i(TAG, "MESSAGE_ACK sent successfully via new connection for pingId=$pingId (attempt ${attempt + 1})")
                        return // Success!
                    }

                    // Both paths failed
                    attempt++
                    if (attempt < maxRetries) {
                        Log.w(TAG, "MESSAGE_ACK send failed (attempt $attempt/$maxRetries), retrying in ${delayMs}ms...")
                        kotlinx.coroutines.delay(delayMs)
                        delayMs *= 2 // Exponential backoff: 1s, 2s, 4s
                    } else {
                        Log.e(TAG, "MESSAGE_ACK send FAILED after $maxRetries attempts for pingId=$pingId")
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
