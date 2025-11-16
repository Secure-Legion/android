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
 * Background worker for retrying pending messages with exponential backoff
 *
 * This worker:
 * 1. Checks for messages with STATUS_PING_SENT
 * 2. Calculates next retry time using exponential backoff
 * 3. Retries sending Pings for messages that are due
 * 4. Polls for Pongs and sends message blobs when Pongs arrive
 *
 * Runs every 5 minutes in the background
 */
class MessageRetryWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "MessageRetryWorker"
        private const val WORK_NAME = "message_retry_work"

        // Worker runs every 5 minutes
        private const val REPEAT_INTERVAL_MINUTES = 5L

        /**
         * Schedule the periodic retry worker
         */
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val retryWork = PeriodicWorkRequestBuilder<MessageRetryWorker>(
                REPEAT_INTERVAL_MINUTES,
                TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    WorkRequest.MIN_BACKOFF_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                retryWork
            )

            Log.i(TAG, "Scheduled periodic message retry worker (every $REPEAT_INTERVAL_MINUTES minutes)")
        }

        /**
         * Cancel the retry worker
         */
        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            Log.i(TAG, "Cancelled message retry worker")
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting message retry cycle")

            val messageService = MessageService(applicationContext)

            // Step 1: Poll for Pongs and send message blobs
            Log.d(TAG, "Polling for Pongs...")
            val pongResult = messageService.pollForPongsAndSendMessages()
            if (pongResult.isSuccess) {
                val sentCount = pongResult.getOrNull() ?: 0
                if (sentCount > 0) {
                    Log.i(TAG, "Sent $sentCount message blobs after receiving Pongs")
                }
            } else {
                Log.e(TAG, "Failed to poll for Pongs: ${pongResult.exceptionOrNull()?.message}")
            }

            // Step 2: Retry sending Pings for messages that are due
            Log.d(TAG, "Checking for messages to retry...")
            val retriedCount = retryPendingPings()
            if (retriedCount > 0) {
                Log.i(TAG, "Retried $retriedCount Ping(s)")
            }

            Log.d(TAG, "Message retry cycle complete")
            Result.success()

        } catch (e: Exception) {
            Log.e(TAG, "Message retry worker failed", e)
            Result.retry()
        }
    }

    /**
     * Retry sending Pings for messages that are due based on exponential backoff
     * @return Number of Pings retried
     */
    private suspend fun retryPendingPings(): Int = withContext(Dispatchers.IO) {
        try {
            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)
            val messageService = MessageService(applicationContext)

            // Get all messages waiting for Pong
            val pendingMessages = database.messageDao().getMessagesAwaitingPong()

            if (pendingMessages.isEmpty()) {
                Log.d(TAG, "No pending messages to retry")
                return@withContext 0
            }

            Log.d(TAG, "Found ${pendingMessages.size} pending message(s)")

            val currentTime = System.currentTimeMillis()
            var retriedCount = 0

            for (message in pendingMessages) {
                // Calculate next retry time using exponential backoff
                val nextRetryTime = calculateNextRetryTime(message)

                if (currentTime >= nextRetryTime) {
                    // Time to retry!
                    Log.d(TAG, "Retrying Ping for message ${message.messageId} (attempt ${message.retryCount + 1})")

                    val result = messageService.sendPingForMessage(message)

                    if (result.isSuccess) {
                        // Update retry counter and timestamp
                        val updatedMessage = message.copy(
                            retryCount = message.retryCount + 1,
                            lastRetryTimestamp = currentTime
                        )
                        database.messageDao().updateMessage(updatedMessage)
                        retriedCount++
                        Log.d(TAG, "Ping retry successful for message ${message.messageId}")
                    } else {
                        Log.w(TAG, "Ping retry failed for message ${message.messageId}: ${result.exceptionOrNull()?.message}")
                        // Update retry counter even on failure
                        val updatedMessage = message.copy(
                            retryCount = message.retryCount + 1,
                            lastRetryTimestamp = currentTime
                        )
                        database.messageDao().updateMessage(updatedMessage)
                    }
                } else {
                    val waitTime = (nextRetryTime - currentTime) / 1000
                    Log.d(TAG, "Message ${message.messageId} not due yet (retry in ${waitTime}s)")
                }
            }

            retriedCount

        } catch (e: Exception) {
            Log.e(TAG, "Failed to retry pending Pings", e)
            0
        }
    }

    /**
     * Calculate next retry time using exponential backoff
     * Formula: initial_delay * (multiplier ^ retry_count)
     * Capped at MAX_RETRY_DELAY_MS
     */
    private fun calculateNextRetryTime(message: Message): Long {
        val lastRetry = message.lastRetryTimestamp ?: message.timestamp
        val retryCount = message.retryCount

        // Calculate delay using exponential backoff
        val delay = (Message.INITIAL_RETRY_DELAY_MS *
            Message.RETRY_BACKOFF_MULTIPLIER.pow(retryCount.toDouble())).toLong()

        // Cap at maximum delay
        val cappedDelay = min(delay, Message.MAX_RETRY_DELAY_MS)

        return lastRetry + cappedDelay
    }
}
