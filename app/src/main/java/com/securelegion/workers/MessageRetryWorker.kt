package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.MessageService
import com.securelegion.services.TorService
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
        private const val REPEAT_INTERVAL_MINUTES = 15L
        private const val RECEIVED_IDS_TTL_MS = 30L * 24 * 60 * 60 * 1000 // 30 days
        private const val RECEIVED_IDS_CLEANUP_INTERVAL_MS = 24L * 60 * 60 * 1000
        private const val ACK_TIMEOUT_MS = 2 * 60 * 1000L
        private const val FAST_ACK_TIMEOUT_MS = 30 * 1000L

        /**
         * Periodic background retry (long-term recovery)
         */
        fun schedule(context: Context) {
            val wm = WorkManager.getInstance(context)
            val work = PeriodicWorkRequestBuilder<MessageRetryWorker>(
                REPEAT_INTERVAL_MINUTES,
                TimeUnit.MINUTES
            ).setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            ).build()
            wm.enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,
                work
            )

            Log.i(TAG, "Scheduled 15-minute message retry safety net")
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
            val contactId = inputData.getLong("CONTACT_ID", -1L)
            val isContactSpecific = contactId != -1L

            // TorService owns fast retry while its transport is healthy. The periodic worker is
            // only a process-death/doze safety net, so do not duplicate DB scans and circuits.
            val healthyForegroundService = !isContactSpecific && TorService.isRunning() &&
                runCatching {
                    com.securelegion.crypto.RustBridge.getBootstrapStatus() >= 100 &&
                        com.securelegion.crypto.RustBridge.isSocksProxyRunning()
                }.getOrDefault(false)
            if (healthyForegroundService) {
                cleanupReceivedIds()
                Log.d(TAG, "Healthy TorService owns retries; periodic safety net is a no-op")
                return@withContext Result.success()
            }

            if (TorService.isTransportQuarantined()) {
                val remainingMs = TorService.getTransportQuarantineRemainingMs()
                Log.w(TAG, "MessageRetryWorker: transport quarantine active (${remainingMs}ms remaining) - skipping run")
                return@withContext Result.success()
            }
            // Wait for transport gate (quick timeout — worker runs periodically, will retry next cycle)
            Log.d(TAG, "Message retry: waiting for transport gate to open...")
            TorService.getTransportGate()?.awaitOpen(com.securelegion.network.TransportGate.TIMEOUT_QUICK_MS)
            Log.d(TAG, "Message retry: transport gate check done, proceeding with retries")

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

            // Periodic received_ids cleanup (30-day TTL, runs at most once per day)
            if (!isContactSpecific) {
                cleanupReceivedIds()
            }

            // Process profile photo retry queue (iOS parity)
            try {
                com.securelegion.services.MessageService(applicationContext).processProfilePhotoQueue()
            } catch (e: Exception) {
                Log.w(TAG, "Profile photo queue processing failed: ${e.message}")
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "MessageRetryWorker failed", e)
            Result.retry()
        }
    }

    /**
     * Prune received_ids older than 30 days.
     * Runs at most once per day even if WorkManager invokes the safety net more often.
     */
    private suspend fun cleanupReceivedIds() {
        try {
            val prefs = applicationContext.getSharedPreferences("worker_maintenance", Context.MODE_PRIVATE)
            val now = System.currentTimeMillis()
            if (now - prefs.getLong("received_ids_cleanup_ms", 0L) < RECEIVED_IDS_CLEANUP_INTERVAL_MS) {
                return
            }
            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)
            val cutoff = System.currentTimeMillis() - RECEIVED_IDS_TTL_MS
            val deleted = database.receivedIdDao().deleteOldIds(cutoff)
            if (deleted > 0) {
                Log.i(TAG, "Pruned $deleted expired received_ids (older than 30 days)")
            }
            prefs.edit().putLong("received_ids_cleanup_ms", now).apply()
        } catch (e: Exception) {
            Log.e(TAG, "received_ids cleanup failed", e)
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

        val now = System.currentTimeMillis()

        // SOFT GATE: Check live Tor status AND cached health snapshot before attempting retries
        // CRITICAL: SOCKS status 1 (general failure) usually means no circuits available
        val bootstrapPercent = com.securelegion.crypto.RustBridge.getBootstrapStatus()
        val circuitsEstablished = com.securelegion.crypto.RustBridge.getCircuitEstablished()
        val torUnavailable = TorHealthHelper.isTorUnavailable(applicationContext)

        // Live checks first (avoid stale snapshot blocking retries)
        if (bootstrapPercent < 100) {
            Log.w(TAG, "Tor bootstrapping (${bootstrapPercent}%) - skipping retry (will retry when healthy)")
            return@withContext 0
        }

        if (circuitsEstablished < 1) {
            Log.w(TAG, "Tor bootstrap ${bootstrapPercent}% but NO CIRCUITS ESTABLISHED - scheduling fast retry in 5s")
            // Tor circuits typically come up within seconds of bootstrap completing.
            // Re-check aggressively (5s) so a freshly-restarted Tor doesn't leave
            // queued messages waiting a full 30s+ for their first attempt.
            val fastRetry = OneTimeWorkRequestBuilder<MessageRetryWorker>()
                .setInitialDelay(5, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(applicationContext).enqueueUniqueWork(
                "message_retry_circuits_wait",
                ExistingWorkPolicy.REPLACE,
                fastRetry
            )
            return@withContext 0
        }

        if (torUnavailable) {
            val status = TorHealthHelper.getStatusString(applicationContext)
            Log.w(TAG, "Tor health snapshot unavailable ($status) but live checks OK; proceeding with retries")
        } else {
            Log.i(TAG, "Tor healthy: bootstrap=${bootstrapPercent}%, circuits=${circuitsEstablished}, proceeding with retries")
        }

        val falseDeliveredCutoff = now - 5_000L
        val unstuckFalseDelivered = database.messageDao().unstickFalseDeliveredMessages(falseDeliveredCutoff)
        if (unstuckFalseDelivered > 0) {
            Log.w(TAG, "Recovered $unstuckFalseDelivered false-delivered message(s) back to retryable state")
        }

        // Revert STATUS_SENT messages that never received MESSAGE_ACK after 2 minutes.
        // Over Tor, a successful write_all() doesn't guarantee delivery — the circuit can
        // drop after send but before the receiver processes the data.
        val cutoff = now - ACK_TIMEOUT_MS
        val reverted = database.messageDao().revertStaleSentMessages(cutoff)
        if (reverted > 0) {
            Log.i(TAG, "Reverted $reverted stale SENT messages to PONG_RECEIVED for re-send")
        }

        val phaseResult = messageService.retryAllPendingMessages(reason = "worker-periodic")
        if (phaseResult.isSuccess) {
            return@withContext phaseResult.getOrNull() ?: 0
        }
        Log.w(TAG, "Phase-aware worker retry failed, falling back to legacy worker loop: ${phaseResult.exceptionOrNull()?.message}")

        // HARD GATE:
        // - Message not fully delivered
        // - Retry time elapsed (respect nextRetryAtMs backoff)
        // - Keep retrying indefinitely (no 7-day limit)
        // - Backpressure: max 10 messages per worker cycle (oldest first)
        val messages = database.messageDao().getMessagesNeedingRetry(
            currentTimeMs = now,
            giveupAfterDays = 2 // 48-hour expiry
        ).filter { !it.messageDelivered && (it.nextRetryAtMs == null || it.nextRetryAtMs <= now) }
            .take(10) // Backpressure: cap per cycle to prevent retry storm

        // Batch-fetch all contacts for these messages (fixes N+1 getContactById per message)
        val contactIds = messages.map { it.contactId }.distinct()
        val contactMap = if (contactIds.isNotEmpty()) {
            database.contactDao().getContactsByIds(contactIds).associateBy { it.id }
        } else emptyMap()

        var retriedCount = 0

        for (message in messages) {
            val contact = contactMap[message.contactId] ?: continue

            // 48-HOUR EXPIRY: Terminal — stop retrying this message
            if (now - message.timestamp > com.securelegion.database.entities.Message.MESSAGE_EXPIRY_MS) {
                database.messageDao().updateMessageStatus(message.id, com.securelegion.database.entities.Message.STATUS_EXPIRED)
                Log.w(TAG, "Message expired (48h): ${message.messageId}")
                continue
            }

            // Use DB status as source of truth — NOT in-memory AckStateTracker.
            // AckStateTracker is ephemeral (lost on restart) and not hydrated from DB,
            // so after restart it returns NONE for everything, causing re-PINGs for
            // messages that are already PONG_RECEIVED → ghost typing on receiver.
            val dbStatus = message.status

            Log.d(TAG, "Retrying message ${message.messageId} (dbStatus=$dbStatus, retryCount=${message.retryCount})")

            if (dbStatus == com.securelegion.database.entities.Message.STATUS_SENT) {
                val recovered = recoverStaleSentMessage(database, messageService, message, now)
                if (recovered) {
                    retriedCount++
                    Log.d(TAG, "Recovered stale STATUS_SENT for ${message.messageId}")
                    continue
                }
            }

            val success = try {
                when (dbStatus) {
                    com.securelegion.database.entities.Message.STATUS_PONG_RECEIVED,
                    com.securelegion.database.entities.Message.STATUS_FAILED -> {
                        // PONG received or previous blob send failed — send blob
                        Log.d(TAG, "→ Sending blob for ${message.messageId} (status=$dbStatus)")
                        messageService.sendPendingMessagesForContact(message.contactId)
                        true
                    }
                    com.securelegion.database.entities.Message.STATUS_SENT -> {
                        // Blob was sent but no MESSAGE_ACK yet — revertStaleSentMessages
                        // handles transitioning these back to PONG_RECEIVED after timeout.
                        // Skip here — don't re-PING a message that was already sent.
                        Log.d(TAG, "→ STATUS_SENT, waiting for ACK (skipping) ${message.messageId}")
                        true
                    }
                    com.securelegion.database.entities.Message.STATUS_DELIVERED -> {
                        Log.d(TAG, "→ Already delivered, skipping ${message.messageId}")
                        true
                    }
                    else -> {
                        // STATUS_PENDING, STATUS_PING_SENT, or unknown — retry PING
                        Log.d(TAG, "→ Retrying PING for ${message.messageId} (status=$dbStatus)")
                        messageService.sendPingForMessage(message).isSuccess
                    }
                }
            } catch (e: Exception) {
                val errorMsg = e.message?.take(256) ?: "Unknown error"
                Log.e(TAG, "Failed to retry message ${message.messageId} (status=$dbStatus): $errorMsg", e)
                false
            }

            if (success) {
                retriedCount++
                Log.d(TAG, "Retry handled for ${message.messageId} (status=$dbStatus)")
                if (dbStatus != com.securelegion.database.entities.Message.STATUS_DELIVERED &&
                    dbStatus != com.securelegion.database.entities.Message.STATUS_PONG_RECEIVED &&
                    dbStatus != com.securelegion.database.entities.Message.STATUS_FAILED &&
                    dbStatus != com.securelegion.database.entities.Message.STATUS_SENT) {
                    MessageService.scheduleRetry(database, message)
                }
            } else {
                // On failure: update message with error and schedule next retry with exponential backoff
                val nextRetryMs = calculateNextRetryTime(message.retryCount, now)
                val errorMsg = "Retry attempt ${message.retryCount + 1} failed (status: $dbStatus)"
                updateMessageRetryState(database, message, errorMsg, nextRetryMs)
            }
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

            val now = System.currentTimeMillis()

            // Gate contact retries the same way as periodic retries to avoid failure churn,
            // but do not let a stale cached health snapshot block live-good Tor.
            val bootstrapPercent = com.securelegion.crypto.RustBridge.getBootstrapStatus()
            val circuitsEstablished = com.securelegion.crypto.RustBridge.getCircuitEstablished()
            val torUnavailable = TorHealthHelper.isTorUnavailable(applicationContext)
            if (bootstrapPercent < 100) {
                Log.w(TAG, "Contact retry for $contactId: Tor bootstrapping (${bootstrapPercent}%)")
                return@withContext 0
            }
            if (circuitsEstablished < 1) {
                Log.w(TAG, "Contact retry for $contactId: no circuits yet, scheduling fast retry in 5s")
                val fastRetry = OneTimeWorkRequestBuilder<MessageRetryWorker>()
                    .setInputData(workDataOf("CONTACT_ID" to contactId))
                    .setInitialDelay(5, TimeUnit.SECONDS)
                    .build()
                WorkManager.getInstance(applicationContext).enqueueUniqueWork(
                    "message_retry_contact_${contactId}",
                    ExistingWorkPolicy.REPLACE,
                    fastRetry
                )
                return@withContext 0
            }
            if (torUnavailable) {
                val status = TorHealthHelper.getStatusString(applicationContext)
                Log.w(TAG, "Tor health snapshot unavailable ($status) but live checks OK; proceeding with contact retry for $contactId")
            }

            val falseDeliveredCutoff = now - 5_000L
            val unstuckFalseDelivered = database.messageDao().unstickFalseDeliveredMessages(falseDeliveredCutoff)
            if (unstuckFalseDelivered > 0) {
                Log.w(TAG, "Contact retry: recovered $unstuckFalseDelivered false-delivered message(s) back to retryable state")
            }

            val cutoff = now - ACK_TIMEOUT_MS
            val reverted = database.messageDao().revertStaleSentMessages(cutoff)
            if (reverted > 0) {
                Log.i(TAG, "Contact retry: reverted $reverted stale SENT messages to PONG_RECEIVED for re-send")
            }

            val fastFlushResult = messageService.fastFlushForContact(contactId, "worker-contact")
            if (fastFlushResult.isSuccess) {
                val flushed = fastFlushResult.getOrNull() ?: 0
                if (flushed > 0) {
                    return@withContext flushed
                }
                Log.d(TAG, "Contact fast flush found no stored payload rows; falling back to legacy contact loop")
            } else {
                Log.w(TAG, "Contact fast flush failed, falling back to legacy contact loop: ${fastFlushResult.exceptionOrNull()?.message}")
            }

            val messages = database.messageDao().getMessagesNeedingRetry(
                currentTimeMs = now,
                giveupAfterDays = 2 // 48-hour expiry
            ).filter {
                it.contactId == contactId && !it.messageDelivered
                    && (it.nextRetryAtMs == null || it.nextRetryAtMs <= now)
            }.take(10) // Backpressure: cap per contact per cycle

            // Single lookup for the target contact (all messages share the same contactId)
            val contact = database.contactDao().getContactById(contactId)
            if (contact == null) {
                Log.w(TAG, "Contact $contactId not found, skipping retry")
                return@withContext 0
            }

            var retriedCount = 0

            for (message in messages) {
                // 48-HOUR EXPIRY: Terminal — stop retrying this message
                if (now - message.timestamp > com.securelegion.database.entities.Message.MESSAGE_EXPIRY_MS) {
                    database.messageDao().updateMessageStatus(message.id, com.securelegion.database.entities.Message.STATUS_EXPIRED)
                    Log.w(TAG, "Message expired (48h): ${message.messageId}")
                    continue
                }

                // Use DB status as source of truth (same as periodic path)
                val dbStatus = message.status

                Log.d(TAG, "Retrying message ${message.messageId} for contact $contactId (dbStatus=$dbStatus, retryCount=${message.retryCount})")

                if (dbStatus == com.securelegion.database.entities.Message.STATUS_SENT) {
                    val recovered = recoverStaleSentMessage(database, messageService, message, now)
                    if (recovered) {
                        retriedCount++
                        Log.d(TAG, "Recovered stale STATUS_SENT for ${message.messageId} via contact retry")
                        continue
                    }
                }

                val success = try {
                    when (dbStatus) {
                        com.securelegion.database.entities.Message.STATUS_PONG_RECEIVED,
                        com.securelegion.database.entities.Message.STATUS_FAILED -> {
                            Log.d(TAG, "→ TAP triggered, sending blob for ${message.messageId} (status=$dbStatus)")
                            messageService.sendPendingMessagesForContact(message.contactId)
                            true
                        }
                        com.securelegion.database.entities.Message.STATUS_SENT -> {
                            Log.d(TAG, "→ STATUS_SENT, waiting for ACK (skipping) ${message.messageId}")
                            true
                        }
                        com.securelegion.database.entities.Message.STATUS_DELIVERED -> {
                            Log.d(TAG, "→ Already delivered, skipping ${message.messageId}")
                            true
                        }
                        else -> {
                            Log.d(TAG, "→ Retrying PING for ${message.messageId} (status=$dbStatus)")
                            messageService.sendPingForMessage(message).isSuccess
                        }
                    }
                } catch (e: Exception) {
                    val errorMsg = e.message?.take(256) ?: "Unknown error"
                    Log.e(TAG, "Failed to retry message ${message.messageId} (status=$dbStatus): $errorMsg", e)
                    false
                }

                if (success) {
                    retriedCount++
                    Log.d(TAG, "Retry handled for ${message.messageId} (status=$dbStatus)")
                    if (dbStatus != com.securelegion.database.entities.Message.STATUS_DELIVERED &&
                        dbStatus != com.securelegion.database.entities.Message.STATUS_PONG_RECEIVED &&
                        dbStatus != com.securelegion.database.entities.Message.STATUS_FAILED &&
                        dbStatus != com.securelegion.database.entities.Message.STATUS_SENT) {
                        MessageService.scheduleRetry(database, message)
                    }
                } else {
                    // On failure: update message with error and schedule next retry with exponential backoff
                    val nextRetryMs = calculateNextRetryTime(message.retryCount, now)
                    val errorMsg = "Contact retry attempt ${message.retryCount + 1} failed (status: $dbStatus)"
                    updateMessageRetryState(database, message, errorMsg, nextRetryMs)
                }
            }

            retriedCount
        }

    /**
     * Recover a stale STATUS_SENT row by reopening blob-send once the ACK timeout has elapsed.
     * This mirrors TorService fast-retry behavior so WorkManager can rescue undelivered rows
     * even when the service-side loop is not the one that notices them first.
     */
    private suspend fun recoverStaleSentMessage(
        database: SecureLegionDatabase,
        messageService: MessageService,
        message: com.securelegion.database.entities.Message,
        now: Long
    ): Boolean = withContext(Dispatchers.IO) {
        if (message.messageDelivered) {
            return@withContext false
        }

        val ageMs = now - message.timestamp
        val isFastMode = message.correlationId?.startsWith("blob_") == true
        val timeoutMs = if (isFastMode) FAST_ACK_TIMEOUT_MS else ACK_TIMEOUT_MS
        if (ageMs < timeoutMs) {
            return@withContext false
        }

        database.messageDao().updateMessageStatus(
            message.id,
            com.securelegion.database.entities.Message.STATUS_PONG_RECEIVED
        )
        database.messageDao().updateLastError(
            message.id,
            "MESSAGE_ACK timeout after ${ageMs / 1000}s; reopening blob send"
        )
        Log.i(
            TAG,
            "Recovered stale STATUS_SENT (${ageMs / 1000}s, fastMode=$isFastMode) for ${message.messageId}"
        )

        messageService.sendPendingMessagesForContact(message.contactId)
        true
    }

    /**
     * Calculate next retry time with exponential backoff
     * Schedule: 5s, 15s, 1m, 5m, 15m, 30m (cap)
     */
    private fun calculateNextRetryTime(retryCount: Int, nowMs: Long): Long {
        val delayMs = when (retryCount) {
            0 -> 5_000L        // First retry: 5 seconds
            1 -> 15_000L       // Second: 15 seconds
            2 -> 60_000L       // Third: 1 minute
            3 -> 300_000L      // Fourth: 5 minutes
            4 -> 900_000L      // Fifth: 15 minutes
            else -> 1_800_000L // Sixth+: 30 minutes (cap)
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
