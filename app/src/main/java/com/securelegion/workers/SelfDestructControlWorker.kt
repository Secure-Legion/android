package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.securelegion.services.MessageService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Delivers a single 0x13 SELF_DESTRUCT control message (the TTL-set payload that
 * tells the receiver's client to start a disappearing timer on the referenced
 * message). Survives process kill because WorkManager persists the request in
 * its own DB.
 *
 * Layering:
 * - `MessageService.sendSelfDestructControl(...)` is the single-shot delivery
 *   implementation. It encrypts and sends, with an internal bounded retry for
 *   fast in-session recovery from transient Tor hiccups.
 * - This worker wraps that call. When the internal retry loop exhausts, the
 *   worker returns `Result.retry()` and WorkManager schedules another run with
 *   exponential backoff. Because each run (and each internal retry inside it)
 *   re-encrypts under a fresh chain-key counter, every arrival on the peer is
 *   a distinct in-order message — iOS's PATH 1 past-message silent-drop bug
 *   does not apply.
 *
 * The worker is capped at 10 run-attempts total (the WorkManager default for
 * `runAttemptCount`), which at the default exponential backoff spans enough
 * real time that if delivery still hasn't succeeded the peer is very likely
 * offline long-term and the TTL is better abandoned than retried forever.
 */
class SelfDestructControlWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "SelfDestructControlWorker"

        private const val KEY_CONTACT_ID = "contactId"
        private const val KEY_TARGET_MSG_ID = "targetMessageId"
        private const val KEY_TARGET_BLOB_ID = "targetBlobId"
        private const val KEY_TTL_SECONDS = "ttlSeconds"

        private const val MAX_ATTEMPTS = 10

        /**
         * Enqueue a persistent self-destruct control delivery. If the current
         * process is killed mid-retry, WorkManager will resume on next app
         * start (or earlier if the system's own scheduling wakes the worker).
         *
         * Uses `ExistingWorkPolicy.KEEP` keyed on the target message id so a
         * rapid duplicate send for the same message doesn't spawn a second
         * worker — the first one will deliver the TTL, which is idempotent.
         */
        fun enqueue(
            context: Context,
            contactId: Long,
            targetMessageId: String,
            targetBlobId: String?,
            ttlSeconds: Double
        ) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val data = workDataOf(
                KEY_CONTACT_ID to contactId,
                KEY_TARGET_MSG_ID to targetMessageId,
                KEY_TARGET_BLOB_ID to (targetBlobId ?: ""),
                KEY_TTL_SECONDS to ttlSeconds
            )

            val request = OneTimeWorkRequestBuilder<SelfDestructControlWorker>()
                .setInputData(data)
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    30, TimeUnit.SECONDS
                )
                .addTag("self_destruct_control")
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                "self_destruct_ctrl_$targetMessageId",
                ExistingWorkPolicy.KEEP,
                request
            )

            Log.i(TAG, "Enqueued self-destruct control for ${targetMessageId.take(16)} (ttl=${ttlSeconds}s)")
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val contactId = inputData.getLong(KEY_CONTACT_ID, -1L)
        val targetMessageId = inputData.getString(KEY_TARGET_MSG_ID) ?: return@withContext Result.failure()
        val targetBlobIdRaw = inputData.getString(KEY_TARGET_BLOB_ID) ?: ""
        val targetBlobId = targetBlobIdRaw.takeIf { it.isNotBlank() }
        val ttlSeconds = inputData.getDouble(KEY_TTL_SECONDS, 0.0)

        if (contactId < 0 || ttlSeconds <= 0.0) {
            Log.w(TAG, "Invalid inputs — dropping (contactId=$contactId ttl=$ttlSeconds)")
            return@withContext Result.failure()
        }

        Log.d(TAG, "SelfDestructControlWorker running (attempt ${runAttemptCount + 1}/$MAX_ATTEMPTS) for ${targetMessageId.take(16)}")

        val messageService = MessageService(applicationContext)
        val delivered: Boolean = try {
            // sendSelfDestructControl returns kotlin.Result<Unit>, which has a
            // name-collision with androidx.work.ListenableWorker.Result inside
            // this class. Collapse it to a Boolean here to keep the rest of
            // the function unambiguous.
            messageService.sendSelfDestructControl(
                contactId = contactId,
                targetMessageId = targetMessageId,
                targetBlobId = targetBlobId,
                ttlSeconds = ttlSeconds
            ).isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "sendSelfDestructControl threw", e)
            false
        }

        if (delivered) {
            Log.i(TAG, "Self-destruct control delivered for ${targetMessageId.take(16)}")
            return@withContext Result.success()
        }

        if (runAttemptCount + 1 >= MAX_ATTEMPTS) {
            Log.e(TAG, "Self-destruct control abandoned after $MAX_ATTEMPTS attempts for ${targetMessageId.take(16)}")
            return@withContext Result.failure()
        }

        Log.w(TAG, "Self-destruct control retrying (attempt ${runAttemptCount + 1}/$MAX_ATTEMPTS) for ${targetMessageId.take(16)}")
        Result.retry()
    }
}
