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

        Log.i(TAG, "Ping ID: $pingId")
        Log.i(TAG, "Sender: $senderOnion")

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

        // Send Pong
        val pongSent = withContext(Dispatchers.IO) {
            try {
                com.securelegion.crypto.RustBridge.sendPongToNewConnection(senderOnion, pongBytes)
            } catch (e: Exception) {
                Log.e(TAG, "✗ Failed to send Pong", e)
                // Report SOCKS failure if this is a connectivity issue
                if (e.message?.contains("SOCKS", ignoreCase = true) == true) {
                    TorService.reportSocksFailure(this@DownloadMessageService)
                }
                false
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
}
