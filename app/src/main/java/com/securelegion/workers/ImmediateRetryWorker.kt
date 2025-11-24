package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.services.MessageService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit
import kotlin.math.min
import kotlin.math.pow

/**
 * Immediate retry worker for fast message delivery
 *
 * This worker handles aggressive retries for freshly sent messages:
 * - Runs as OneTimeWorkRequest (no 15-minute minimum)
 * - Retries: 5s → 10s → 20s → 40s → 80s → 160s
 * - Chains itself for continuous retries within the first ~5 minutes
 * - After max fast retries, lets PeriodicWorker take over
 *
 * Scheduled immediately when a message is sent for fast delivery.
 */
class ImmediateRetryWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "ImmediateRetryWorker"
        private const val WORK_NAME_PREFIX = "immediate_retry_"

        // Fast retry configuration
        private const val MAX_FAST_RETRIES = 6  // 5s, 10s, 20s, 40s, 80s, 160s
        private const val INITIAL_DELAY_SECONDS = 5L

        /**
         * Schedule immediate retry for a specific message
         */
        fun scheduleForMessage(context: Context, messageId: String) {
            val workName = "$WORK_NAME_PREFIX$messageId"

            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val retryWork = OneTimeWorkRequestBuilder<ImmediateRetryWorker>()
                .setConstraints(constraints)
                .setInputData(
                    workDataOf("MESSAGE_ID" to messageId)
                )
                .setInitialDelay(INITIAL_DELAY_SECONDS, TimeUnit.SECONDS)
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                workName,
                ExistingWorkPolicy.REPLACE,
                retryWork
            )

            Log.i(TAG, "Scheduled immediate retry for message $messageId in ${INITIAL_DELAY_SECONDS}s")
        }

        /**
         * Cancel immediate retry for a message (when it's delivered)
         */
        fun cancelForMessage(context: Context, messageId: String) {
            val workName = "$WORK_NAME_PREFIX$messageId"
            WorkManager.getInstance(context).cancelUniqueWork(workName)
            Log.d(TAG, "Cancelled immediate retry for message $messageId")
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val messageId = inputData.getString("MESSAGE_ID")
            if (messageId == null) {
                Log.e(TAG, "No message ID provided")
                return@withContext Result.failure()
            }

            Log.d(TAG, "Starting immediate retry for message $messageId")

            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)
            val messageService = MessageService(applicationContext)

            // Get the specific message
            val message = database.messageDao().getMessageByMessageId(messageId)
            if (message == null) {
                Log.w(TAG, "Message $messageId not found in database")
                return@withContext Result.failure()
            }

            // Check if message is still pending
            if (message.status != Message.STATUS_PING_SENT) {
                Log.i(TAG, "Message $messageId is no longer pending (status=${message.status})")
                return@withContext Result.success()
            }

            // ============ ACK-BASED FLOW CONTROL ============
            // Check ACKs in reverse order (final to initial) to determine what action to take

            // PHASE 4: MESSAGE_ACK received → Fully delivered, STOP all retries
            if (message.messageDelivered) {
                Log.i(TAG, "✓ MESSAGE_ACK received - message fully delivered to ${message.messageId}")
                return@withContext Result.success()
            }

            // PHASE 3: PONG_ACK received → Receiver is downloading, wait for MESSAGE_ACK
            if (message.pongDelivered) {
                Log.d(TAG, "✓ PONG_ACK received - receiver downloading message ${message.messageId}")
                Log.d(TAG, "→ Waiting for MESSAGE_ACK, no action needed")
                // Schedule next check to monitor MESSAGE_ACK
                if (message.retryCount < MAX_FAST_RETRIES) {
                    scheduleNextRetry(messageId, message.retryCount)
                }
                return@withContext Result.success()
            }

            // PHASE 2: PING_ACK received → Receiver got notification, check for Pong
            if (message.pingDelivered) {
                Log.d(TAG, "✓ PING_ACK received - checking if receiver sent Pong for ${message.messageId}")
                // Poll for Pong (receiver may have TAP'd and sent Pong)
                val pongResult = messageService.pollForPongsAndSendMessages()
                if (pongResult.isSuccess) {
                    val sentCount = pongResult.getOrNull() ?: 0
                    if (sentCount > 0) {
                        Log.i(TAG, "✓ Pong received and message blob sent!")
                        return@withContext Result.success()
                    }
                }
                // No Pong yet - receiver hasn't requested download
                Log.d(TAG, "→ No Pong yet, checking again later...")
                if (message.retryCount < MAX_FAST_RETRIES) {
                    scheduleNextRetry(messageId, message.retryCount)
                }
                return@withContext Result.success()
            }

            // PHASE 1: No PING_ACK → Retry Ping (receiver may be offline or Ping was lost)
            // ANTI-FLOOD: Don't retry if we sent Ping recently (within 30 seconds)
            val currentTime = System.currentTimeMillis()
            val timeSinceLastRetry = if ((message.lastRetryTimestamp ?: 0) > 0) {
                currentTime - (message.lastRetryTimestamp ?: 0)
            } else {
                // No previous retry, check time since message creation
                currentTime - (message.timestamp ?: 0)
            }

            if (timeSinceLastRetry < 30000) {  // Less than 30 seconds
                Log.d(TAG, "⏱ Ping sent ${timeSinceLastRetry/1000}s ago - waiting for PING_ACK...")
                Log.d(TAG, "→ Anti-flood: Not retrying yet, giving receiver time to ACK")
                // Schedule next retry and return - don't flood the network
                if (message.retryCount < MAX_FAST_RETRIES) {
                    scheduleNextRetry(messageId, message.retryCount)
                }
                return@withContext Result.success()
            }

            // No PING_ACK after 30+ seconds → Retry Ping
            Log.d(TAG, "Retrying Ping for message $messageId (attempt ${message.retryCount + 1})")

            // Use stored wire bytes to prevent generating new Ping ID (ghost ping fix)
            val contact = database.contactDao().getContactById(message.contactId)
            val retrySuccess = if (message.pingWireBytes != null && contact != null) {
                Log.i(TAG, "Resending Ping with stored wire bytes (same Ping ID: ${message.pingId})")
                try {
                    com.securelegion.crypto.RustBridge.resendPingWithWireBytes(
                        message.pingWireBytes!!,
                        contact.torOnionAddress
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to resend Ping with wire bytes", e)
                    false
                }
            } else {
                // Fallback: No wire bytes stored (old message), regenerate Ping
                Log.w(TAG, "No wire bytes stored, falling back to sendPingForMessage (may create ghost ping)")
                val result = messageService.sendPingForMessage(message)
                result.isSuccess
            }

            if (retrySuccess) {
                // Update retry counter
                val updatedMessage = message.copy(
                    retryCount = message.retryCount + 1,
                    lastRetryTimestamp = currentTime
                )
                database.messageDao().updateMessage(updatedMessage)

                Log.d(TAG, "✓ Ping retry successful for message $messageId (same Ping ID, no ghost ping)")

                // Schedule next retry if we haven't exceeded max fast retries
                if (updatedMessage.retryCount < MAX_FAST_RETRIES) {
                    scheduleNextRetry(messageId, updatedMessage.retryCount)
                } else {
                    Log.i(TAG, "Max fast retries reached for $messageId - periodic worker will take over")
                }

                return@withContext Result.success()
            } else {
                Log.w(TAG, "Ping retry failed for message $messageId")

                // Update retry counter even on failure
                val updatedMessage = message.copy(
                    retryCount = message.retryCount + 1,
                    lastRetryTimestamp = currentTime
                )
                database.messageDao().updateMessage(updatedMessage)

                // Schedule next retry if we haven't exceeded max fast retries
                if (updatedMessage.retryCount < MAX_FAST_RETRIES) {
                    scheduleNextRetry(messageId, updatedMessage.retryCount)
                    return@withContext Result.success()
                } else {
                    Log.i(TAG, "Max fast retries reached for $messageId - periodic worker will take over")
                    return@withContext Result.failure()
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Immediate retry worker failed", e)
            Result.retry()
        }
    }

    /**
     * Schedule the next retry with exponential backoff
     */
    private fun scheduleNextRetry(messageId: String, currentRetryCount: Int) {
        // Calculate delay: 5s * (2 ^ retryCount)
        // Retry 1: 5s, Retry 2: 10s, Retry 3: 20s, etc.
        val delaySeconds = (INITIAL_DELAY_SECONDS *
            Message.RETRY_BACKOFF_MULTIPLIER.pow(currentRetryCount.toDouble())).toLong()

        val workName = "$WORK_NAME_PREFIX$messageId"

        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val retryWork = OneTimeWorkRequestBuilder<ImmediateRetryWorker>()
            .setConstraints(constraints)
            .setInputData(
                workDataOf("MESSAGE_ID" to messageId)
            )
            .setInitialDelay(delaySeconds, TimeUnit.SECONDS)
            .build()

        WorkManager.getInstance(applicationContext).enqueueUniqueWork(
            workName,
            ExistingWorkPolicy.REPLACE,
            retryWork
        )

        Log.d(TAG, "Scheduled next retry for $messageId in ${delaySeconds}s (attempt ${currentRetryCount + 1})")
    }
}
