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

    private suspend fun downloadMessage(contactId: Long, contactName: String) {
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
                    // Report SOCKS failure if this is a connectivity issue
                    if (e.message?.contains("SOCKS", ignoreCase = true) == true) {
                        TorService.reportSocksFailure(this@DownloadMessageService)
                    }
                    false
                }
            }
        }

        if (!pongSent) {
            Log.e(TAG, "✗ Pong send failed")
            showFailureNotification(contactName, "Failed to send response")
            return
        }

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
        var messageReceived = false
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
        val intent = Intent(this, ChatActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
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
        val intent = Intent(this, ChatActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
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

            // Message blob format: [Sender X25519 Public Key - 32 bytes][Encrypted Message]
            if (messageBytes.size < 32) {
                Log.e(TAG, "Message blob too small: ${messageBytes.size} bytes")
                return
            }

            // Extract sender's X25519 public key (first 32 bytes)
            val senderX25519PublicKey = messageBytes.copyOfRange(0, 32)

            // Extract encrypted message (rest of bytes)
            val encryptedMessageWire = messageBytes.copyOfRange(32, messageBytes.size)

            Log.d(TAG, "Sender X25519 key: ${android.util.Base64.encodeToString(senderX25519PublicKey, android.util.Base64.NO_WRAP).take(16)}...")
            Log.d(TAG, "Encrypted message: ${encryptedMessageWire.size} bytes")

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

            // Extract type byte and payload
            val typeByte = encryptedMessageWire[0]
            val encryptedPayload = encryptedMessageWire.copyOfRange(1, encryptedMessageWire.size)

            Log.d(TAG, "Message type byte: 0x${String.format("%02X", typeByte)}")

            when (typeByte.toInt()) {
                0x00 -> {
                    // TEXT message
                    Log.d(TAG, "Decrypting TEXT message...")
                    val plaintext = com.securelegion.crypto.RustBridge.decryptMessage(
                        encryptedPayload,
                        senderPublicKey,
                        ourPrivateKey
                    )

                    if (plaintext != null) {
                        Log.i(TAG, "✓ Message decrypted: ${plaintext.length} chars")

                        // Save to database via MessageService
                        val messageService = MessageService(this@DownloadMessageService)
                        val encryptedBase64 = android.util.Base64.encodeToString(encryptedMessageWire, android.util.Base64.NO_WRAP)

                        val result = messageService.receiveMessage(
                            encryptedData = encryptedBase64,
                            senderPublicKey = senderPublicKey,
                            senderOnionAddress = contact.torOnionAddress
                        )

                        if (result.isSuccess) {
                            Log.i(TAG, "✓ Message saved to database")
                        } else {
                            Log.e(TAG, "Failed to save message: ${result.exceptionOrNull()?.message}")
                        }
                    } else {
                        Log.e(TAG, "Failed to decrypt message")
                    }
                }

                0x01 -> {
                    // VOICE message
                    Log.d(TAG, "Processing VOICE message...")

                    // Extract duration (4 bytes, big-endian)
                    val durationBytes = encryptedPayload.copyOfRange(0, 4)
                    val duration = (
                        (durationBytes[0].toInt() and 0xFF shl 24) or
                        (durationBytes[1].toInt() and 0xFF shl 16) or
                        (durationBytes[2].toInt() and 0xFF shl 8) or
                        (durationBytes[3].toInt() and 0xFF)
                    )

                    val encryptedVoicePayload = encryptedPayload.copyOfRange(4, encryptedPayload.size)

                    Log.d(TAG, "Voice duration: ${duration}s")
                    Log.d(TAG, "Decrypting voice message...")

                    // Save to database via MessageService
                    val messageService = MessageService(this@DownloadMessageService)
                    val encryptedBase64 = android.util.Base64.encodeToString(encryptedMessageWire, android.util.Base64.NO_WRAP)

                    val result = messageService.receiveMessage(
                        encryptedData = encryptedBase64,
                        senderPublicKey = senderPublicKey,
                        senderOnionAddress = contact.torOnionAddress,
                        messageType = com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE,
                        voiceDuration = duration
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "✓ Voice message saved to database")
                    } else {
                        Log.e(TAG, "Failed to save voice message: ${result.exceptionOrNull()?.message}")
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
}
