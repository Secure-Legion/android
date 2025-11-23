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

        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
        val pingId = prefs.getString("ping_${contactId}_id", null)

        if (pingId == null) {
            showFailureNotification(contactName, "No pending message")
            return
        }

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

        // Update notification
        updateNotification(contactName, "Creating response...")

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

        // Update notification
        updateNotification(contactName, "Sending response...")

        // DUAL-PATH APPROACH: Try instant reply first, then fall back to listener
        var pongSent = false
        var instantMessageReceived = false

        // PATH 1: Try sending Pong on original connection (instant messaging)
        if (connectionId != -1L) {
            Log.d(TAG, "Attempting instant Pong reply on connection $connectionId...")
            pongSent = withContext(Dispatchers.IO) {
                try {
                    val messageBytes = com.securelegion.crypto.RustBridge.sendPongBytes(connectionId, pongBytes)
                    if (messageBytes != null) {
                        Log.i(TAG, "✓ Pong sent on original connection! Received message blob: ${messageBytes.size} bytes")
                        // Message blob arrived immediately! Process it now
                        handleInstantMessageBlob(messageBytes, contactId, contactName)
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
        }

        // PATH 2: If instant path failed, fall back to listener (delayed messaging)
        if (!pongSent) {
            Log.d(TAG, "Falling back to listener-based Pong delivery (delayed download)...")
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
            val maxAttempts = 30 // 60 seconds total

            for (attempt in 1..maxAttempts) {
                Log.d(TAG, "Polling attempt $attempt/$maxAttempts...")
                updateNotification(contactName, "Downloading... ($attempt/$maxAttempts)")

                delay(2000)

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
        sendMessageAck(contactId, contactName)

        // Dismiss the pending message notification
        val notificationManager = getSystemService(android.app.NotificationManager::class.java)
        val notificationId = contactId.toInt() + 20000
        notificationManager?.cancel(notificationId)
        Log.i(TAG, "Dismissed pending message notification (ID: $notificationId)")

        // Clear the pending Ping
        prefs.edit()
            .remove("ping_${contactId}_id")
            .remove("ping_${contactId}_sender")
            .remove("ping_${contactId}_timestamp")
            .remove("ping_${contactId}_data")
            .remove("ping_${contactId}_onion")
            .remove("ping_${contactId}_connection")
            .remove("ping_${contactId}_name")
            .commit()

        // Small delay to ensure database write completes
        delay(300)

        // Broadcast to ChatActivity to refresh (ChatActivity will notify MainActivity if needed)
        val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
        intent.setPackage(packageName)
        intent.putExtra("CONTACT_ID", contactId)
        sendBroadcast(intent)

        Log.i(TAG, "✓ Broadcast sent to refresh UI")

        // Show success notification
        showSuccessNotification(contactName)
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
    private suspend fun handleInstantMessageBlob(messageBytes: ByteArray, contactId: Long, contactName: String) {
        try {
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
                        senderOnionAddress = contact.torOnionAddress
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "✓ TEXT message saved to database")
                        // Send MESSAGE_ACK to sender
                        sendMessageAck(contactId, contactName)
                        // Dismiss the pending message notification
                        val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                        notificationManager?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            // Message was already downloaded, so clear the notification and send ACK
                            sendMessageAck(contactId, contactName)
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
                        voiceDuration = voiceDuration!!  // Already extracted above
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "✓ VOICE message saved to database")
                        // Send MESSAGE_ACK to sender
                        sendMessageAck(contactId, contactName)
                        // Dismiss the pending message notification
                        val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                        notificationManager?.cancel(contactId.toInt() + 20000)
                    } else {
                        val errorMessage = result.exceptionOrNull()?.message
                        if (errorMessage?.contains("Duplicate message") == true) {
                            Log.w(TAG, "Message already downloaded - treating as success")
                            // Message was already downloaded, so clear the notification and send ACK
                            sendMessageAck(contactId, contactName)
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
     */
    private suspend fun sendMessageAck(contactId: Long, contactName: String) {
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

            Log.d(TAG, "Sending MESSAGE_ACK for pingId=$pingId (messageId=${latestMessage.messageId}) to $contactName")

            val senderEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
            val senderX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP)

            val ackSuccess = withContext(Dispatchers.IO) {
                com.securelegion.crypto.RustBridge.sendDeliveryAck(
                    pingId,  // Use pingId instead of messageId
                    "MESSAGE_ACK",
                    senderEd25519Pubkey,
                    senderX25519Pubkey,
                    contact.torOnionAddress
                )
            }

            if (ackSuccess) {
                Log.i(TAG, "✓ MESSAGE_ACK sent successfully for messageId=${latestMessage.messageId}")
            } else {
                Log.e(TAG, "✗ Failed to send MESSAGE_ACK for messageId=${latestMessage.messageId}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending MESSAGE_ACK", e)
        }
    }
}
