package com.securelegion.workers

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkRequest
import androidx.work.WorkerParameters
import androidx.room.withTransaction
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.PendingFriendRequest
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import com.securelegion.services.FriendRequestEnvelope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * The only owner of persisted friend-request retries.
 *
 * Each invocation atomically leases and sends at most one row. Native code performs one bounded
 * connection attempt; this worker persists the next due time and chains exactly one successor.
 */
class FriendRequestWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "FriendRequestWorker"
        private const val DISPATCHER_WORK_NAME = "friend_request_dispatcher"
        private const val LEGACY_PERIODIC_WORK_NAME = "friend_request_retry_work"
        private const val LEGACY_IMMEDIATE_WORK_NAME = "friend_request_retry_immediate"
        private const val UPGRADE_PREFS = "friend_request_dispatcher_v33"
        private const val UPGRADE_COMPLETE = "legacy_work_cancelled"
        private const val LEASE_DURATION_MS = com.securelegion.services.FRIEND_REQUEST_LEASE_DURATION_MS

        private fun request(delayMs: Long) = OneTimeWorkRequestBuilder<FriendRequestWorker>()
            .setInitialDelay(delayMs.coerceAtLeast(0), TimeUnit.MILLISECONDS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            // Used only for database/key-store initialization failures. Transport failures are
            // persisted in Room and always return Result.success().
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                WorkRequest.MIN_BACKOFF_MILLIS,
                TimeUnit.MILLISECONDS
            )
            .addTag(DISPATCHER_WORK_NAME)
            .build()

        fun scheduleDispatcher(context: Context, reason: String = "convergence") {
            WorkManager.getInstance(context).enqueueUniqueWork(
                DISPATCHER_WORK_NAME,
                ExistingWorkPolicy.KEEP,
                request(0)
            )
            Log.i(TAG, "Friend-request dispatcher reconciled (reason=$reason)")
        }

        /** Compatibility entry point. There is no longer request-specific WorkManager work. */
        fun scheduleForRequest(context: Context, requestId: Long) {
            scheduleDispatcher(context, "request-$requestId")
        }

        /** Compatibility entry point. The dispatcher schedules itself at the next persisted due time. */
        fun schedulePeriodicSweep(context: Context) {
            val workManager = WorkManager.getInstance(context)
            workManager.cancelUniqueWork(LEGACY_PERIODIC_WORK_NAME)
            workManager.cancelUniqueWork(LEGACY_IMMEDIATE_WORK_NAME)
            scheduleDispatcher(context, "legacy-periodic-call")
        }

        fun scheduleImmediateSweep(context: Context) {
            scheduleDispatcher(context, "immediate")
        }

        /** Replace a stale future dispatcher with an immediate convergence pass. */
        fun nudgeDispatcher(context: Context, reason: String) {
            WorkManager.getInstance(context).enqueueUniqueWork(
                DISPATCHER_WORK_NAME,
                ExistingWorkPolicy.REPLACE,
                request(0)
            )
            Log.i(TAG, "Friend-request dispatcher nudged (reason=$reason)")
        }

        /**
         * One-time code-32 upgrade cleanup. It preserves every pending row and its backoff while
         * cancelling all known legacy work names. Any already-running legacy worker still uses
         * this build's lease-aware implementation and therefore cannot double-send.
         */
        suspend fun migrateLegacyScheduling(context: Context) = withContext(Dispatchers.IO) {
            val prefs = context.getSharedPreferences(UPGRADE_PREFS, Context.MODE_PRIVATE)
            val keyManager = KeyManager.getInstance(context)
            val database = SecureLegionDatabase.getInstance(
                context,
                keyManager.getDatabasePassphrase()
            )
            val dao = database.pendingFriendRequestDao()
            dao.reclaimExpiredLeases(System.currentTimeMillis())

            if (!prefs.getBoolean(UPGRADE_COMPLETE, false)) {
                val workManager = WorkManager.getInstance(context)
                workManager.cancelUniqueWork(LEGACY_PERIODIC_WORK_NAME)
                workManager.cancelUniqueWork(LEGACY_IMMEDIATE_WORK_NAME)
                dao.getAllUnfinished().forEach { request ->
                    workManager.cancelUniqueWork("friend_request_retry_${request.id}")
                }
                // Rows that code 32 marked sent still need convergence until an acceptance arrives.
                dao.markAllPendingNeedRetry()
                prefs.edit().putBoolean(UPGRADE_COMPLETE, true).apply()
                Log.i(TAG, "Cancelled code-32 friend-request work without deleting pending rows")
            }
            scheduleDispatcher(context, "v33-migration")
        }

        /** Legacy convergence API retained for call sites while preserving backoff after migration. */
        suspend fun markAllPendingNeedRetry(context: Context) {
            try {
                migrateLegacyScheduling(context)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to migrate/reconcile friend-request scheduling", e)
            }
        }

        suspend fun scheduleManualRetry(context: Context, requestId: Long): Boolean =
            withContext(Dispatchers.IO) {
                val keyManager = KeyManager.getInstance(context)
                val database = SecureLegionDatabase.getInstance(
                    context,
                    keyManager.getDatabasePassphrase()
                )
                val changed = database.pendingFriendRequestDao().makeDueForManualRetry(
                    requestId,
                    System.currentTimeMillis()
                ) == 1
                if (changed) {
                    WorkManager.getInstance(context).enqueueUniqueWork(
                        DISPATCHER_WORK_NAME,
                        ExistingWorkPolicy.REPLACE,
                        request(0)
                    )
                }
                changed
            }

        private fun enqueueSuccessor(context: Context, delayMs: Long) {
            WorkManager.getInstance(context).enqueueUniqueWork(
                DISPATCHER_WORK_NAME,
                ExistingWorkPolicy.APPEND_OR_REPLACE,
                request(delayMs)
            )
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val database = try {
            val keyManager = KeyManager.getInstance(applicationContext)
            SecureLegionDatabase.getInstance(applicationContext, keyManager.getDatabasePassphrase())
        } catch (e: Exception) {
            Log.e(TAG, "Dispatcher initialization failed", e)
            return@withContext Result.retry()
        }

        val dao = database.pendingFriendRequestDao()
        val now = System.currentTimeMillis()
        val reclaimed = dao.reclaimExpiredLeases(now)
        if (reclaimed > 0) Log.w(TAG, "Reclaimed $reclaimed expired friend-request lease(s)")

        val leaseToken = UUID.randomUUID().toString()
        val request = dao.claimNextDue(now, leaseToken, now + LEASE_DURATION_MS)
        if (request == null) {
            scheduleNext(database)
            return@withContext Result.success()
        }

        val operationId = "fr:${request.id}:$leaseToken"
        try {
            // A Phase 3 row exists specifically to deliver/replay the persisted ACK. The contact
            // is created before that send, so "already friend" must not suppress it.
            if (com.securelegion.services.shouldShortCircuitFriendRequestSend(
                    request.phase,
                    isAlreadyFriend(database, request)
                )
            ) {
                dao.markCompletedIfLeased(request.id, leaseToken, System.currentTimeMillis())
                Log.i(TAG, "Completed request ${request.id}: contact already exists")
                return@withContext Result.success()
            }

            val sendResult = when (request.phase) {
                PendingFriendRequest.PHASE_1_SENT -> retryPhase1(request, operationId)
                PendingFriendRequest.PHASE_2_SENT -> retryPhase2(request, operationId)
                PendingFriendRequest.PHASE_3_SENT -> retryPhase3Ack(request, operationId)
                else -> RustBridge.FriendRequestSendResult.PERMANENT_INPUT
            }
            persistResult(database, request, leaseToken, sendResult)
            Result.success()
        } catch (cancelled: CancellationException) {
            RustBridge.cancelFriendRequestOperation(operationId)
            withContext(NonCancellable) { dao.releaseLease(request.id, leaseToken) }
            throw cancelled
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected dispatcher failure for request ${request.id}", e)
            val timestamp = System.currentTimeMillis()
            dao.updateRetryTrackingIfLeased(
                request.id,
                leaseToken,
                timestamp,
                request.retryCount + 1,
                FriendRequestBackoff.nextRetryAt(timestamp, request.retryCount + 1)
            )
            Result.success()
        } finally {
            withContext(NonCancellable) {
                dao.releaseLease(request.id, leaseToken)
                scheduleNext(database)
            }
        }
    }

    private suspend fun scheduleNext(database: SecureLegionDatabase) {
        val now = System.currentTimeMillis()
        val earliest = database.pendingFriendRequestDao().getEarliestRetryAt(now) ?: return
        enqueueSuccessor(applicationContext, (earliest - now).coerceAtLeast(0))
    }

    private suspend fun persistResult(
        database: SecureLegionDatabase,
        request: PendingFriendRequest,
        leaseToken: String,
        result: RustBridge.FriendRequestSendResult
    ) {
        val dao = database.pendingFriendRequestDao()
        val now = System.currentTimeMillis()
        when (result) {
            RustBridge.FriendRequestSendResult.SUCCESS -> {
                if (request.phase == PendingFriendRequest.PHASE_3_SENT) {
                    if (completePhase3ContactAndTombstone(
                            database,
                            request,
                            leaseToken,
                            now
                        )
                    ) {
                        dao.deleteExpiredCompletedPhase3(
                            now - com.securelegion.services.PHASE3_REPLAY_TTL_MS
                        )
                        dao.deleteCompletedPhase3BeyondLimit(
                            com.securelegion.services.PHASE3_REPLAY_MAX_ROWS
                        )
                        com.securelegion.services.TorService
                            .completePendingUiForDatabaseId(applicationContext, request.id)
                    } else {
                        val attempt = request.retryCount + 1
                        dao.updateRetryTrackingIfLeased(
                            request.id,
                            leaseToken,
                            now,
                            attempt,
                            FriendRequestBackoff.nextRetryAt(now, attempt)
                        )
                    }
                } else {
                    val attempt = request.retryCount + 1
                    dao.updateRetryTrackingIfLeased(
                        request.id,
                        leaseToken,
                        now,
                        attempt,
                        FriendRequestBackoff.nextRetryAt(now, attempt)
                    )
                }
            }
            RustBridge.FriendRequestSendResult.TRANSIENT_NETWORK -> {
                val attempt = request.retryCount + 1
                dao.updateRetryTrackingIfLeased(
                    request.id,
                    leaseToken,
                    now,
                    attempt,
                    FriendRequestBackoff.nextRetryAt(now, attempt)
                )
            }
            RustBridge.FriendRequestSendResult.TOR_NOT_READY,
            RustBridge.FriendRequestSendResult.CANCELLED -> {
                dao.updateRetryTrackingIfLeased(
                    request.id,
                    leaseToken,
                    now,
                    request.retryCount,
                    now + 60_000L
                )
            }
            RustBridge.FriendRequestSendResult.PERMANENT_INPUT ->
                dao.markFailedIfLeased(request.id, leaseToken)
        }
        Log.i(TAG, "Request ${request.id} attempt result=$result")
    }

    private suspend fun completePhase3ContactAndTombstone(
        database: SecureLegionDatabase,
        request: PendingFriendRequest,
        leaseToken: String,
        completedAt: Long
    ): Boolean = database.withTransaction {
        val contactId = request.contactId ?: return@withTransaction false
        val contact = database.contactDao().getContactById(contactId)
            ?: return@withTransaction false
        if (contact.friendshipStatus !=
            com.securelegion.database.entities.Contact.FRIENDSHIP_CONFIRMED
        ) {
            database.contactDao().updateContact(
                contact.copy(
                    friendshipStatus =
                        com.securelegion.database.entities.Contact.FRIENDSHIP_CONFIRMED
                )
            )
        }
        if (database.pendingFriendRequestDao().markCompletedIfLeased(
                request.id,
                leaseToken,
                completedAt
            ) != 1
        ) {
            throw IllegalStateException("Lost Phase 3 lease before atomic completion")
        }
        true
    }

    private suspend fun retryPhase1(
        request: PendingFriendRequest,
        operationId: String
    ): RustBridge.FriendRequestSendResult {
        val payload = request.phase1PayloadJson
            ?: return RustBridge.FriendRequestSendResult.PERMANENT_INPUT
        val pin = request.recipientPin
            ?: return RustBridge.FriendRequestSendResult.PERMANENT_INPUT
        val encrypted = try {
            ContactCardManager(applicationContext).encryptWithPin(
                FriendRequestEnvelope.refreshTimestamp(payload),
                pin
            )
        } catch (e: Exception) {
            Log.e(TAG, "Invalid Phase 1 retry payload", e)
            return RustBridge.FriendRequestSendResult.PERMANENT_INPUT
        }
        return runNativeFriendSend(operationId) {
            RustBridge.sendFriendRequestTyped(request.recipientOnion, encrypted, operationId)
        }
    }

    private suspend fun retryPhase2(
        request: PendingFriendRequest,
        operationId: String
    ): RustBridge.FriendRequestSendResult {
        val payload = request.phase2PayloadBase64
            ?: return RustBridge.FriendRequestSendResult.PERMANENT_INPUT
        val encrypted = try {
            Base64.decode(payload, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid Phase 2 retry payload", e)
            return RustBridge.FriendRequestSendResult.PERMANENT_INPUT
        }
        return runNativeFriendSend(operationId) {
            RustBridge.sendFriendRequestAcceptedTyped(
                request.recipientOnion,
                encrypted,
                operationId
            )
        }
    }

    private suspend fun retryPhase3Ack(
        request: PendingFriendRequest,
        operationId: String
    ): RustBridge.FriendRequestSendResult {
        val payload = request.phase2PayloadBase64
            ?: return RustBridge.FriendRequestSendResult.PERMANENT_INPUT
        val encrypted = try {
            Base64.decode(payload, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid persisted Phase 3 retry payload", e)
            return RustBridge.FriendRequestSendResult.PERMANENT_INPUT
        }
        return runNativeFriendSend(operationId) {
            RustBridge.sendFriendRequestAcceptedTyped(
                request.recipientOnion,
                encrypted,
                operationId
            )
        }
    }

    /**
     * Run blocking JNI on Dispatchers.IO while exposing WorkManager cancellation to Rust's
     * operation CancellationToken. Native also enforces a hard 45-second deadline.
     */
    private suspend fun runNativeFriendSend(
        operationId: String,
        send: () -> RustBridge.FriendRequestSendResult
    ): RustBridge.FriendRequestSendResult = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation {
            try {
                RustBridge.cancelFriendRequestOperation(operationId)
            } catch (e: Throwable) {
                Log.w(TAG, "Unable to cancel native friend-request operation", e)
            }
        }
        Dispatchers.IO.dispatch(kotlin.coroutines.EmptyCoroutineContext, Runnable {
            if (!continuation.isActive) return@Runnable
            val result = try {
                send()
            } catch (e: Throwable) {
                Log.e(TAG, "Native friend-request send threw", e)
                RustBridge.FriendRequestSendResult.TRANSIENT_NETWORK
            }
            continuation.resume(result)
        })
    }

    private suspend fun isAlreadyFriend(
        database: SecureLegionDatabase,
        request: PendingFriendRequest
    ): Boolean {
        val contactDao = database.contactDao()
        request.contactId?.let { if (contactDao.getContactById(it) != null) return true }
        if (contactDao.getContactByOnionAddress(request.recipientOnion) != null) return true

        val card = try {
            request.contactCardJson?.let(ContactCard::fromJson)
        } catch (_: Exception) {
            null
        } ?: return false

        val publicKey = Base64.encodeToString(card.solanaPublicKey, Base64.NO_WRAP)
        if (contactDao.getContactByPublicKey(publicKey) != null) return true
        if (card.friendRequestOnion.isNotBlank() &&
            contactDao.getContactByOnionAddress(card.friendRequestOnion) != null
        ) return true
        return card.messagingOnion.isNotBlank() &&
            contactDao.getContactByOnionAddress(card.messagingOnion) != null
    }
}
