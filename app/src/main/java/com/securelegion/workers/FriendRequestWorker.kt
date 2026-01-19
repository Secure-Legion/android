package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.PendingFriendRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Background worker for retrying pending friend requests
 *
 * This worker:
 * 1. Queries friend requests with needsRetry = true
 * 2. Retries sending Phase 1/2/3 based on phase field
 * 3. Updates retry count and nextRetryAt (exponential backoff)
 * 4. Marks as completed when Phase 3 ACK confirmed
 *
 * Triggered by:
 * - App start (mark all pending as needsRetry)
 * - Tor reconnection (mark all pending as needsRetry)
 * - Manual retry from UI
 * - Periodic background sweep (every 30 minutes)
 */
class FriendRequestWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "FriendRequestWorker"
        private const val PERIODIC_WORK_NAME = "friend_request_retry_work"

        /**
         * Schedule immediate retry for a specific friend request
         */
        fun scheduleForRequest(context: Context, requestId: Long) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val workData = workDataOf("REQUEST_ID" to requestId)

            val retryWork = OneTimeWorkRequestBuilder<FriendRequestWorker>()
                .setInputData(workData)
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    WorkRequest.MIN_BACKOFF_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                "friend_request_retry_$requestId",
                ExistingWorkPolicy.REPLACE,
                retryWork
            )

            Log.i(TAG, "Scheduled immediate retry for friend request $requestId")
        }

        /**
         * Schedule periodic friend request retry sweep (every 30 minutes)
         */
        fun schedulePeriodicSweep(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val sweepWork = PeriodicWorkRequestBuilder<FriendRequestWorker>(
                30, TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                PERIODIC_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                sweepWork
            )

            Log.i(TAG, "Scheduled periodic friend request retry (every 30 minutes)")
        }

        /**
         * Mark all pending friend requests as needing retry
         * Called on app start and Tor reconnection
         */
        suspend fun markAllPendingNeedRetry(context: Context) {
            withContext(Dispatchers.IO) {
                try {
                    val keyManager = KeyManager.getInstance(context)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

                    val markedCount = database.pendingFriendRequestDao().markAllPendingNeedRetry()

                    if (markedCount > 0) {
                        Log.i(TAG, "Marked $markedCount pending friend request(s) for retry")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to mark friend requests for retry", e)
                }
            }
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val requestId = inputData.getLong("REQUEST_ID", -1L)
            val isRequestSpecific = requestId != -1L

            if (isRequestSpecific) {
                Log.d(TAG, "Starting retry for friend request $requestId")
            } else {
                Log.d(TAG, "Starting periodic friend request retry sweep")
            }

            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)

            // DATABASE-AUTHORITATIVE QUERY: Get friend requests needing retry
            val requestsNeedingRetry = if (isRequestSpecific) {
                val request = database.pendingFriendRequestDao().getById(requestId)
                if (request != null && request.needsRetry) listOf(request) else emptyList()
            } else {
                database.pendingFriendRequestDao().getFriendRequestsNeedingRetry()
            }

            if (requestsNeedingRetry.isEmpty()) {
                Log.d(TAG, "No friend requests need retry at this time")
                return@withContext Result.success()
            }

            Log.i(TAG, "Retrying ${requestsNeedingRetry.size} friend request(s)")

            var successCount = 0
            var failureCount = 0

            for (request in requestsNeedingRetry) {
                try {
                    val success = when (request.phase) {
                        PendingFriendRequest.PHASE_1_SENT -> retryPhase1(database, request)
                        PendingFriendRequest.PHASE_2_SENT -> retryPhase2(database, request)
                        PendingFriendRequest.PHASE_3_SENT -> retryPhase3Ack(database, request)
                        else -> {
                            Log.e(TAG, "Unknown phase ${request.phase} for request ${request.id}")
                            false
                        }
                    }

                    if (success) {
                        successCount++
                    } else {
                        failureCount++
                    }

                    // Delay between retries
                    if (request != requestsNeedingRetry.last()) {
                        kotlinx.coroutines.delay(500)
                    }

                } catch (e: Exception) {
                    Log.e(TAG, "Error retrying friend request ${request.id}", e)
                    failureCount++
                }
            }

            Log.i(TAG, "Friend request retry complete: $successCount success, $failureCount failed")

            Result.success()

        } catch (e: Exception) {
            Log.e(TAG, "Friend request worker failed", e)
            Result.retry()
        }
    }

    /**
     * Retry Phase 1 (PIN-encrypted friend request)
     */
    private suspend fun retryPhase1(
        database: SecureLegionDatabase,
        request: PendingFriendRequest
    ): Boolean {
        if (request.phase1PayloadJson == null || request.recipientPin == null) {
            Log.e(TAG, "Cannot retry Phase 1: missing payload or PIN")
            database.pendingFriendRequestDao().markFailed(request.id)
            return false
        }

        Log.d(TAG, "Retrying Phase 1 to ${request.recipientOnion}")

        // Re-encrypt Phase 1 with PIN
        val cardManager = com.securelegion.services.ContactCardManager(applicationContext)
        val encryptedPhase1 = try {
            cardManager.encryptWithPin(request.phase1PayloadJson, request.recipientPin)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt Phase 1", e)
            return false
        }

        // Send Phase 1
        val success = try {
            com.securelegion.crypto.RustBridge.sendFriendRequest(
                recipientOnion = request.recipientOnion,
                encryptedFriendRequest = encryptedPhase1
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send Phase 1", e)
            false
        }

        // Update retry tracking based on result
        val nextRetryAt = calculateNextRetryTime(request.retryCount + 1)
        val timestamp = System.currentTimeMillis()

        if (success) {
            // Success: Clear needsRetry flag
            database.pendingFriendRequestDao().markSent(
                requestId = request.id,
                timestamp = timestamp,
                retryCount = request.retryCount + 1,
                nextRetryAt = nextRetryAt
            )
            Log.i(TAG, "✓ Phase 1 retry successful for request ${request.id}")
        } else {
            // Failure: Keep needsRetry = 1 for next attempt
            database.pendingFriendRequestDao().updateRetryTracking(
                requestId = request.id,
                timestamp = timestamp,
                retryCount = request.retryCount + 1,
                nextRetryAt = nextRetryAt
            )
            Log.w(TAG, "Phase 1 retry failed for request ${request.id}, next retry at $nextRetryAt")
        }

        return success
    }

    /**
     * Retry Phase 2 (X25519-encrypted acceptance)
     */
    private suspend fun retryPhase2(
        database: SecureLegionDatabase,
        request: PendingFriendRequest
    ): Boolean {
        if (request.phase2PayloadBase64 == null) {
            Log.e(TAG, "Cannot retry Phase 2: missing payload")
            database.pendingFriendRequestDao().markFailed(request.id)
            return false
        }

        Log.d(TAG, "Retrying Phase 2 to ${request.recipientOnion}")

        // Decode Phase 2 payload from Base64
        val encryptedPhase2 = try {
            android.util.Base64.decode(request.phase2PayloadBase64, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decode Phase 2 payload", e)
            database.pendingFriendRequestDao().markFailed(request.id)
            return false
        }

        val success = try {
            com.securelegion.crypto.RustBridge.sendFriendRequestAccepted(
                recipientOnion = request.recipientOnion,
                encryptedAcceptance = encryptedPhase2
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send Phase 2", e)
            false
        }

        // Update retry tracking based on result
        val nextRetryAt = calculateNextRetryTime(request.retryCount + 1)
        val timestamp = System.currentTimeMillis()

        if (success) {
            // Success: Clear needsRetry flag
            database.pendingFriendRequestDao().markSent(
                requestId = request.id,
                timestamp = timestamp,
                retryCount = request.retryCount + 1,
                nextRetryAt = nextRetryAt
            )
            Log.i(TAG, "✓ Phase 2 retry successful for request ${request.id}")
        } else {
            // Failure: Keep needsRetry = 1 for next attempt
            database.pendingFriendRequestDao().updateRetryTracking(
                requestId = request.id,
                timestamp = timestamp,
                retryCount = request.retryCount + 1,
                nextRetryAt = nextRetryAt
            )
            Log.w(TAG, "Phase 2 retry failed for request ${request.id}, next retry at $nextRetryAt")
        }

        return success
    }

    /**
     * Retry Phase 3 ACK (X25519-encrypted confirmation)
     */
    private suspend fun retryPhase3Ack(
        database: SecureLegionDatabase,
        request: PendingFriendRequest
    ): Boolean {
        if (request.contactCardJson == null) {
            Log.e(TAG, "Cannot retry Phase 3: missing contact card")
            database.pendingFriendRequestDao().markFailed(request.id)
            return false
        }

        Log.d(TAG, "Retrying Phase 3 ACK to ${request.recipientOnion}")

        // Rebuild Phase 3 ACK with our contact card
        val keyManager = KeyManager.getInstance(applicationContext)
        val torManager = com.securelegion.crypto.TorManager.getInstance(applicationContext)

        val ownContactCard = com.securelegion.models.ContactCard(
            displayName = keyManager.getUsername() ?: "Unknown",
            solanaPublicKey = keyManager.getSolanaPublicKey(),
            x25519PublicKey = keyManager.getEncryptionPublicKey(),
            kyberPublicKey = keyManager.getKyberPublicKey(),
            solanaAddress = keyManager.getSolanaAddress(),
            friendRequestOnion = keyManager.getFriendRequestOnion() ?: "",
            messagingOnion = torManager.getOnionAddress() ?: "",
            voiceOnion = torManager.getVoiceOnionAddress() ?: "",
            contactPin = keyManager.getContactPin() ?: "",
            timestamp = System.currentTimeMillis() / 1000
        )

        // Get recipient's X25519 key from stored contact card
        val recipientCard = try {
            com.securelegion.models.ContactCard.fromJson(request.contactCardJson)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse recipient contact card", e)
            database.pendingFriendRequestDao().markFailed(request.id)
            return false
        }

        val encryptedPhase3 = try {
            com.securelegion.crypto.RustBridge.encryptMessage(
                plaintext = ownContactCard.toJson(),
                recipientX25519PublicKey = recipientCard.x25519PublicKey
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt Phase 3 ACK", e)
            return false
        }

        val success = try {
            com.securelegion.crypto.RustBridge.sendFriendRequestAccepted(
                recipientOnion = request.recipientOnion,
                encryptedAcceptance = encryptedPhase3
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send Phase 3 ACK", e)
            false
        }

        val timestamp = System.currentTimeMillis()

        if (success) {
            // Phase 3 complete - mark friend request as completed
            database.pendingFriendRequestDao().markCompleted(
                requestId = request.id,
                timestamp = timestamp
            )
            Log.i(TAG, "✓ Phase 3 ACK sent - friend request ${request.id} complete")
        } else {
            // Failure: Keep needsRetry = 1 for next attempt
            val nextRetryAt = calculateNextRetryTime(request.retryCount + 1)
            database.pendingFriendRequestDao().updateRetryTracking(
                requestId = request.id,
                timestamp = timestamp,
                retryCount = request.retryCount + 1,
                nextRetryAt = nextRetryAt
            )
            Log.w(TAG, "Phase 3 ACK retry failed for request ${request.id}, next retry at $nextRetryAt")
        }

        return success
    }

    /**
     * Calculate next retry time using exponential backoff
     * Formula: 30s * (2 ^ retry_count)
     * Capped at 30 minutes
     */
    private fun calculateNextRetryTime(retryCount: Int): Long {
        val baseDelayMs = 30_000L // 30 seconds
        val maxDelayMs = 30 * 60 * 1000L // 30 minutes

        val delayMs = (baseDelayMs * Math.pow(2.0, retryCount.toDouble())).toLong()
        val cappedDelay = minOf(delayMs, maxDelayMs)

        return System.currentTimeMillis() + cappedDelay
    }
}
