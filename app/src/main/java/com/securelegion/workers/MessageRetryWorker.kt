package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.MessageService
import com.securelegion.services.TorService
import com.securelegion.models.AckState
import com.securelegion.utils.TorHealthHelper
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
        private const val REPEAT_INTERVAL_MINUTES = 3L // Retry every 3 minutes (was 15)

        /**
         * Periodic background retry (long-term recovery)
         */
        fun schedule(context: Context) {
            // NO CONSTRAINTS - TorService is always running, so network is always available
            // NetworkType.CONNECTED was blocking execution (VPN, battery saver, etc.)
            val work = PeriodicWorkRequestBuilder<MessageRetryWorker>(
                REPEAT_INTERVAL_MINUTES,
                TimeUnit.MINUTES
            )
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.REPLACE, // REPLACE old schedule (was KEEP - prevented interval change)
                work
            )

            Log.w(TAG, "========== SCHEDULED PERIODIC MessageRetryWorker (every ${REPEAT_INTERVAL_MINUTES} minutes) ==========")
        }

        /**
         * Immediate retry for a specific contact (triggered by TAP)
         */
        fun scheduleForContact(context: Context, contactId: Long) {
            // NO CONSTRAINTS - TorService is always running
            val data = workDataOf("CONTACT_ID" to contactId)

            val work = OneTimeWorkRequestBuilder<MessageRetryWorker>()
                .setInputData(data)
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
            // Wait for transport gate (quick timeout — worker runs periodically, will retry next cycle)
            Log.d(TAG, "Message retry: waiting for transport gate to open...")
            TorService.getTransportGate()?.awaitOpen(com.securelegion.network.TransportGate.TIMEOUT_QUICK_MS)
            Log.d(TAG, "Message retry: transport gate check done, proceeding with retries")

            val contactId = inputData.getLong("CONTACT_ID", -1L)
            val isContactSpecific = contactId != -1L

            Log.w(
                TAG,
                "========== MESSAGE RETRY WORKER RUNNING (contactSpecific=$isContactSpecific) =========="
            )

            val retried = if (isContactSpecific) {
                retryPendingPingsForContact(contactId)
            } else {
                retryPendingPings()
            }

            if (retried > 0) {
                Log.w(TAG, "========== RETRY WORKER COMPLETE: Retried $retried PING(s) ==========")
            } else {
                Log.w(TAG, "========== RETRY WORKER COMPLETE: No messages needed retry ==========")
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "MessageRetryWorker failed", e)
            Result.retry()
        }
    }

    /**
     * Retry pending messages (phase-aware, Tor-health-aware)
     *
     * CRITICAL: Bug #7 - Phase-Aware Retry Logic
     * Different retry actions based on ACK state:
     * - NONE: Retry PING packet
     * - PING_ACKED: Poll for PONG reply
     * - PONG_ACKED: Send message blob (sender only)
     * - MESSAGE_ACKED: Skip (already delivered)
     *
     * NEVER DELETES messages - just updates error and schedules next retry
     * with exponential backoff: 2s, 5s, 10s, 20s, 40s, 2m, 5m, 10m (cap)
     */
    private suspend fun retryPendingPings(): Int = withContext(Dispatchers.IO) {
        val keyManager = KeyManager.getInstance(applicationContext)
        val dbPassphrase = keyManager.getDatabasePassphrase()
        val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)
        val messageService = MessageService(applicationContext)
        val ackTracker = MessageService.getAckTracker()

        val now = System.currentTimeMillis()

        // SOFT GATE: Check Tor health AND circuits before attempting retries
        // CRITICAL: SOCKS status 1 (general failure) usually means no circuits available
        val torUnavailable = TorHealthHelper.isTorUnavailable(applicationContext)
        val bootstrapPercent = com.securelegion.crypto.RustBridge.getBootstrapStatus()
        val circuitsEstablished = com.securelegion.crypto.RustBridge.getCircuitEstablished()

        if (torUnavailable) {
            val status = TorHealthHelper.getStatusString(applicationContext)
            Log.w(TAG, "Tor unavailable ($status), skipping retry (will retry when healthy)")
            return@withContext 0 // Exit early, don't attempt sends
        }

        if (circuitsEstablished < 1) {
            Log.w(TAG, "Tor bootstrap ${bootstrapPercent}% but NO CIRCUITS ESTABLISHED - skipping retry (SOCKS would fail with status 1)")
            Log.w(TAG, "This is why you see 'SOCKS5 status 1 (general SOCKS server failure)'")
            Log.w(TAG, "Waiting for circuits... (will retry in ${REPEAT_INTERVAL_MINUTES} minutes)")
            return@withContext 0 // Exit early, circuits not ready yet
        }

        Log.i(TAG, "Tor healthy: bootstrap=${bootstrapPercent}%, circuits=${circuitsEstablished}, proceeding with retries")

        // HARD GATE:
        // - Message not fully delivered
        // - Retry time elapsed
        // - Keep retrying indefinitely (no 7-day limit)
        val messages = database.messageDao().getMessagesNeedingRetry(
            currentTimeMs = now,
            giveupAfterDays = 365 // Extended from 7 days to 1 year (indefinite for practical purposes)
        ).filter { !it.messageDelivered }

        var retriedCount = 0

        for (message in messages) {
            val contact = database.contactDao().getContactById(message.contactId) ?: continue

            // Check current ACK state to determine what phase needs retry
            val ackState = ackTracker.getState(message.messageId)

            Log.d(TAG, "Retrying message ${message.messageId} (phase: $ackState, retryCount=${message.retryCount})")

            val success = try {
                when (ackState) {
                    AckState.NONE, AckState.PING_ACKED -> {
                        // Phase 1: PING not received or not acknowledged - retry PING packet
                        Log.d(TAG, "→ Retrying PING for ${message.messageId}")
                        if (message.pingWireBytes != null) {
                            com.securelegion.crypto.RustBridge.resendPingWithWireBytes(
                                message.pingWireBytes!!,
                                contact.messagingOnion ?: ""
                            )
                        } else {
                            messageService.sendPingForMessage(message).isSuccess
                        }
                    }
                    AckState.PONG_ACKED -> {
                        // Phase 2: PONG received but message blob not sent - poll for PONG and advance
                        Log.d(TAG, "→ PONG received, polling for message download ${message.messageId}")
                        messageService.pollForPongsAndSendMessages()
                        true // Assume poll was scheduled successfully
                    }
                    AckState.MESSAGE_ACKED -> {
                        // Phase 3: Message fully delivered - skip retry
                        Log.d(TAG, "→ Message already delivered, skipping ${message.messageId}")
                        true // Skip, don't count as retry
                    }
                }
            } catch (e: Exception) {
                val errorMsg = e.message?.take(256) ?: "Unknown error"
                Log.e(TAG, "Failed to retry message ${message.messageId} in phase $ackState: $errorMsg", e)
                false
            }

            if (success) {
                retriedCount++
                Log.d(TAG, "Retry sent for ${message.messageId} (phase: $ackState)")
            } else {
                // On failure: update message with error and schedule next retry with exponential backoff
                val nextRetryMs = calculateNextRetryTime(message.retryCount, now)
                val errorMsg = "Retry attempt ${message.retryCount + 1} failed (phase: $ackState)"
                updateMessageRetryState(database, message, errorMsg, nextRetryMs)
            }

            // Always schedule next retry (even on success, for indefinite retries)
            MessageService.scheduleRetry(database, message)
        }

        retriedCount
    }

    /**
     * Retry messages for a specific contact (TAP-triggered, phase-aware, Tor-health-aware)
     *
     * CRITICAL: Bug #7 - Phase-Aware Retry Logic
     * When TAP ACK is received, we retry all pending messages for that contact,
     * but only retry the missing phase based on ACK state.
     *
     * Never deletes messages - updates with error and next retry time
     */
    private suspend fun retryPendingPingsForContact(contactId: Long): Int =
        withContext(Dispatchers.IO) {

            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)
            val messageService = MessageService(applicationContext)
            val ackTracker = MessageService.getAckTracker()

            val now = System.currentTimeMillis()

            // SOFT GATE: Check Tor health but still attempt retries (SOCKS health monitor will auto-restart)
            if (TorHealthHelper.isTorUnavailable(applicationContext)) {
                val status = TorHealthHelper.getStatusString(applicationContext)
                Log.w(TAG, "Tor unavailable ($status), attempting contact retry for $contactId anyway (SOCKS auto-restart enabled)")
            }

            val messages = database.messageDao().getMessagesNeedingRetry(
                currentTimeMs = now,
                giveupAfterDays = 365 // Extended from 7 days to 1 year (indefinite for practical purposes)
            ).filter {
                it.contactId == contactId && !it.messageDelivered
            }

            var retriedCount = 0

            for (message in messages) {
                val contact = database.contactDao().getContactById(message.contactId) ?: continue

                // Check current ACK state to determine what phase needs retry
                val ackState = ackTracker.getState(message.messageId)

                Log.d(TAG, "Retrying message ${message.messageId} for contact $contactId (phase: $ackState, retryCount=${message.retryCount})")

                val success = try {
                    when (ackState) {
                        AckState.NONE, AckState.PING_ACKED -> {
                            // Phase 1: PING not received - retry PING packet
                            Log.d(TAG, "→ Retrying PING for ${message.messageId}")
                            if (message.pingWireBytes != null) {
                                com.securelegion.crypto.RustBridge.resendPingWithWireBytes(
                                    message.pingWireBytes!!,
                                    contact.messagingOnion ?: ""
                                )
                            } else {
                                messageService.sendPingForMessage(message).isSuccess
                            }
                        }
                        AckState.PONG_ACKED -> {
                            // Phase 2: PONG received - poll for PONG and send message
                            Log.d(TAG, "→ TAP triggered, polling for message download ${message.messageId}")
                            messageService.pollForPongsAndSendMessages()
                            true
                        }
                        AckState.MESSAGE_ACKED -> {
                            // Phase 3: Message fully delivered - skip retry
                            Log.d(TAG, "→ Message already delivered, skipping ${message.messageId}")
                            true
                        }
                    }
                } catch (e: Exception) {
                    val errorMsg = e.message?.take(256) ?: "Unknown error"
                    Log.e(TAG, "Failed to retry message ${message.messageId} in phase $ackState: $errorMsg", e)
                    false
                }

                if (success) {
                    retriedCount++
                    Log.d(TAG, "Retry sent for ${message.messageId} (phase: $ackState)")
                } else {
                    // On failure: update message with error and schedule next retry with exponential backoff
                    val nextRetryMs = calculateNextRetryTime(message.retryCount, now)
                    val errorMsg = "Contact retry attempt ${message.retryCount + 1} failed (phase: $ackState)"
                    updateMessageRetryState(database, message, errorMsg, nextRetryMs)
                }

                MessageService.scheduleRetry(database, message)
            }

            retriedCount
        }

    /**
     * Calculate next retry time with exponential backoff
     * Schedule: 2s, 5s, 10s, 20s, 40s, 2m, 5m, 10m (cap)
     */
    private fun calculateNextRetryTime(retryCount: Int, nowMs: Long): Long {
        val delayMs = when (retryCount) {
            0 -> 2000L // First retry: 2 seconds
            1 -> 5000L // Second: 5 seconds
            2 -> 10000L // Third: 10 seconds
            3 -> 20000L // Fourth: 20 seconds
            4 -> 40000L // Fifth: 40 seconds
            5 -> 120000L // Sixth: 2 minutes
            6 -> 300000L // Seventh: 5 minutes
            else -> 600000L // Eighth+: 10 minutes (cap)
        }
        return nowMs + delayMs
    }

    /**
     * Update message retry state without deleting it
     * Stores error message and schedules next retry time
     */
    private suspend fun updateMessageRetryState(
        database: SecureLegionDatabase,
        message: com.securelegion.database.entities.Message,
        errorMsg: String,
        nextRetryMs: Long
    ) = withContext(Dispatchers.IO) {
        try {
            val sanitizedError = errorMsg
                .replace("\n", " ")
                .replace("\r", " ")
                .take(256)

            val newRetryCount = message.retryCount + 1
            // CRITICAL: Use partial update to avoid overwriting delivery status
            // (fixes race where MESSAGE_ACK sets delivered=true between read and write)
            database.messageDao().updateRetryStateWithError(
                message.id,
                newRetryCount,
                System.currentTimeMillis(),
                nextRetryMs,
                sanitizedError
            )
            Log.d(TAG, "Updated message ${message.messageId} retry state: attempt $newRetryCount, next retry at $nextRetryMs")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update message retry state: ${e.message}", e)
        }
    }
}
