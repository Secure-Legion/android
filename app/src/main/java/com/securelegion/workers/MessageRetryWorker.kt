package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.MessageService
import com.securelegion.models.AckState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * MessageRetryWorker
 *
 * RESPONSIBILITY (STRICT):
 * - Retry sending PING packets ONLY
 *
 * THIS WORKER DOES NOT:
 * - Poll for PONGs
 * - Send message blobs
 * - Advance protocol stages
 * - Act as Wake logic
 *
 * Wake/TAP triggers scheduling.
 * Protocol advancement happens elsewhere.
 */
class MessageRetryWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "MessageRetryWorker"
        private const val WORK_NAME = "message_retry_work"
        private const val REPEAT_INTERVAL_MINUTES = 15L

        /**
         * Periodic background retry (long-term recovery)
         */
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val work = PeriodicWorkRequestBuilder<MessageRetryWorker>(
                REPEAT_INTERVAL_MINUTES,
                TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                work
            )

            Log.i(TAG, "Scheduled periodic MessageRetryWorker")
        }

        /**
         * Immediate retry for a specific contact (triggered by TAP)
         */
        fun scheduleForContact(context: Context, contactId: Long) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val data = workDataOf("CONTACT_ID" to contactId)

            val work = OneTimeWorkRequestBuilder<MessageRetryWorker>()
                .setInputData(data)
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                "message_retry_contact_$contactId",
                ExistingWorkPolicy.REPLACE,
                work
            )

            Log.i(TAG, "Scheduled MessageRetryWorker for contact $contactId")
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            Log.i(TAG, "Cancelled MessageRetryWorker")
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val contactId = inputData.getLong("CONTACT_ID", -1L)
            val isContactSpecific = contactId != -1L

            Log.d(
                TAG,
                "Starting MessageRetryWorker (contactSpecific=$isContactSpecific)"
            )

            val retried = if (isContactSpecific) {
                retryPendingPingsForContact(contactId)
            } else {
                retryPendingPings()
            }

            if (retried > 0) {
                Log.i(TAG, "Retried $retried PING(s)")
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "MessageRetryWorker failed", e)
            Result.retry()
        }
    }

    /**
     * Retry pending messages (phase-aware)
     *
     * CRITICAL: Bug #7 - Phase-Aware Retry Logic
     * Different retry actions based on ACK state:
     * - NONE: Retry PING packet
     * - PING_ACKED: Poll for PONG reply
     * - PONG_ACKED: Send message blob (sender only)
     * - MESSAGE_ACKED: Skip (already delivered)
     */
    private suspend fun retryPendingPings(): Int = withContext(Dispatchers.IO) {
        val keyManager = KeyManager.getInstance(applicationContext)
        val dbPassphrase = keyManager.getDatabasePassphrase()
        val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)
        val messageService = MessageService(applicationContext)
        val ackTracker = MessageService.getAckTracker()

        val now = System.currentTimeMillis()

        // HARD GATE:
        // - Message not fully delivered
        // - Retry time elapsed
        // - Give up after 7 days
        val messages = database.messageDao().getMessagesNeedingRetry(
            currentTimeMs = now,
            giveupAfterDays = 7
        ).filter { !it.messageDelivered }  // Changed from !pingDelivered to !messageDelivered

        var retriedCount = 0

        for (message in messages) {
            val contact = database.contactDao().getContactById(message.contactId) ?: continue

            // Check current ACK state to determine what phase needs retry
            val ackState = ackTracker.getState(message.messageId)

            Log.d(TAG, "Retrying message ${message.messageId} (phase: $ackState)")

            val success = try {
                when (ackState) {
                    AckState.NONE, AckState.PING_ACKED -> {
                        // Phase 1: PING not received or not acknowledged - retry PING packet
                        Log.d(TAG, "  → Retrying PING for ${message.messageId}")
                        if (message.pingWireBytes != null) {
                            com.securelegion.crypto.RustBridge.resendPingWithWireBytes(
                                message.pingWireBytes!!,
                                contact.messagingOnion ?: contact.torOnionAddress ?: ""
                            )
                        } else {
                            messageService.sendPingForMessage(message).isSuccess
                        }
                    }
                    AckState.PONG_ACKED -> {
                        // Phase 2: PONG received but message blob not sent - poll for PONG and advance
                        Log.d(TAG, "  → PONG received, polling for message download ${message.messageId}")
                        messageService.pollForPongsAndSendMessages()
                        true  // Assume poll was scheduled successfully
                    }
                    AckState.MESSAGE_ACKED -> {
                        // Phase 3: Message fully delivered - skip retry
                        Log.d(TAG, "  → Message already delivered, skipping ${message.messageId}")
                        true  // Skip, don't count as retry
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to retry message ${message.messageId} in phase $ackState", e)
                false
            }

            // Always schedule next retry (even on failure)
            MessageService.scheduleRetry(database, message)

            if (success) {
                retriedCount++
                Log.d(TAG, "✓ Retry sent for ${message.messageId} (phase: $ackState)")
            }
        }

        retriedCount
    }

    /**
     * Retry messages for a specific contact (TAP-triggered, phase-aware)
     *
     * CRITICAL: Bug #7 - Phase-Aware Retry Logic
     * When TAP ACK is received, we retry all pending messages for that contact,
     * but only retry the missing phase based on ACK state.
     */
    private suspend fun retryPendingPingsForContact(contactId: Long): Int =
        withContext(Dispatchers.IO) {

            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)
            val messageService = MessageService(applicationContext)
            val ackTracker = MessageService.getAckTracker()

            val now = System.currentTimeMillis()

            val messages = database.messageDao().getMessagesNeedingRetry(
                currentTimeMs = now,
                giveupAfterDays = 7
            ).filter {
                it.contactId == contactId && !it.messageDelivered  // Changed from !pingDelivered
            }

            var retriedCount = 0

            for (message in messages) {
                val contact = database.contactDao().getContactById(message.contactId) ?: continue

                // Check current ACK state to determine what phase needs retry
                val ackState = ackTracker.getState(message.messageId)

                Log.d(TAG, "Retrying message ${message.messageId} for contact $contactId (phase: $ackState)")

                val success = try {
                    when (ackState) {
                        AckState.NONE, AckState.PING_ACKED -> {
                            // Phase 1: PING not received - retry PING packet
                            Log.d(TAG, "  → Retrying PING for ${message.messageId}")
                            if (message.pingWireBytes != null) {
                                com.securelegion.crypto.RustBridge.resendPingWithWireBytes(
                                    message.pingWireBytes!!,
                                    contact.messagingOnion ?: contact.torOnionAddress ?: ""
                                )
                            } else {
                                messageService.sendPingForMessage(message).isSuccess
                            }
                        }
                        AckState.PONG_ACKED -> {
                            // Phase 2: PONG received - poll for PONG and send message
                            Log.d(TAG, "  → TAP triggered, polling for message download ${message.messageId}")
                            messageService.pollForPongsAndSendMessages()
                            true
                        }
                        AckState.MESSAGE_ACKED -> {
                            // Phase 3: Message fully delivered - skip retry
                            Log.d(TAG, "  → Message already delivered, skipping ${message.messageId}")
                            true
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to retry message ${message.messageId} in phase $ackState", e)
                    false
                }

                MessageService.scheduleRetry(database, message)

                if (success) {
                    retriedCount++
                    Log.d(TAG, "✓ Retry sent for ${message.messageId} (phase: $ackState)")
                }
            }

            retriedCount
        }
}
