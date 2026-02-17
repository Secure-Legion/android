package com.securelegion.workers

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * TapSyncWorker
 *
 * TAP = "I'm online" (Wake) signal that triggers convergence (ACK sending + message retry).
 *
 * RESPONSIBILITY (STRICT):
 * - Send TAP to contacts that have needsTapSync = true
 * - Clear needsTapSync on success (via DAO)
 *
 * THIS WORKER DOES NOT:
 * - Poll for PONGs
 * - Send message blobs
 * - Manage protocol phase
 * - Maintain its own retry counters in DB
 *
 * Retries are handled by:
 * - bounded in-worker attempts (small)
 * - WorkManager backoff / re-enqueueing
 */
class TapSyncWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "TapSyncWorker"
        private const val PERIODIC_WORK_NAME = "tap_sync_periodic"

        /**
         * Schedule immediate TAP send for a specific contact.
         * Used when we have new messages or want convergence for this peer.
         */
        fun scheduleForContact(context: Context, contactId: Long) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val workData = workDataOf("CONTACT_ID" to contactId)

            val tapWork = OneTimeWorkRequestBuilder<TapSyncWorker>()
                .setInputData(workData)
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    WorkRequest.MIN_BACKOFF_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                "tap_sync_contact_$contactId",
                ExistingWorkPolicy.REPLACE,
                tapWork
            )

            Log.i(TAG, "Scheduled TAP for contact $contactId")
        }

        /**
         * Schedule TAP send for all contacts needing sync.
         * Used on app start and Tor reconnection.
         */
        fun scheduleImmediateSweep(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val tapWork = OneTimeWorkRequestBuilder<TapSyncWorker>()
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    WorkRequest.MIN_BACKOFF_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                "tap_sync_immediate",
                ExistingWorkPolicy.REPLACE,
                tapWork
            )

            Log.i(TAG, "Scheduled TAP sweep (all contacts)")
        }

        /**
         * Periodic TAP sweep (every 15 minutes).
         * Ensures convergence even if app doesn't explicitly trigger.
         */
        fun schedulePeriodicSweep(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val sweepWork = PeriodicWorkRequestBuilder<TapSyncWorker>(
                15, TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                PERIODIC_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                sweepWork
            )

            Log.i(TAG, "Scheduled periodic TAP sweep (15m)")
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val contactId = inputData.getLong("CONTACT_ID", -1L)
            val isContactSpecific = contactId != -1L

            Log.d(
                TAG,
                if (isContactSpecific)
                    "Starting TAP send for contact $contactId"
                else
                    "Starting TAP sweep (needsTapSync=true)"
            )

            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)

            val contacts = if (isContactSpecific) {
                val c = database.contactDao().getContactById(contactId)
                if (c != null && c.needsTapSync) listOf(c) else emptyList()
            } else {
                database.contactDao().getContactsNeedingTapSync()
            }

            if (contacts.isEmpty()) {
                Log.d(TAG, "No contacts need TAP sync")
                return@withContext Result.success()
            }

            Log.i(TAG, "Sending TAP to ${contacts.size} contact(s)")

            var successCount = 0
            var failureCount = 0

            for ((index, contact) in contacts.withIndex()) {
                val sent = sendTapBounded(contact)

                if (sent) {
                    // Single authoritative update:
                    // clears needsTapSync flag
                    database.contactDao().markTapSent(contact.id)
                    successCount++
                    Log.d(TAG, "TAP sent to ${contact.displayName}")
                } else {
                    failureCount++
                    Log.w(TAG, "TAP failed for ${contact.displayName} (will retry via WorkManager/backoff)")
                }

                // small pacing to avoid Tor congestion
                if (index < contacts.lastIndex) delay(150)
            }

            Log.i(TAG, "TAP sweep complete: $successCount success, $failureCount failed")

            // If there were failures, request retry so WM backoff applies.
            // This keeps behavior simple and avoids DB retry counters.
            if (failureCount > 0) Result.retry() else Result.success()

        } catch (e: Exception) {
            Log.e(TAG, "TapSyncWorker failed", e)
            Result.retry()
        }
    }

    /**
     * Send TAP with small bounded retries inside the worker.
     * We DO NOT store retry counters in the DB here.
     */
    private suspend fun sendTapBounded(
        contact: com.securelegion.database.entities.Contact,
        maxAttempts: Int = 3
    ): Boolean {
        val recipientOnion = contact.messagingOnion ?: contact.torOnionAddress ?: ""
        if (recipientOnion.isEmpty()) {
            Log.e(TAG, "No onion address for ${contact.displayName}, cannot send TAP")
            return false
        }

        val ed25519 = try {
            Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Bad Ed25519 pubkey for ${contact.displayName}", e)
            return false
        }

        val x25519 = try {
            Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Bad X25519 pubkey for ${contact.displayName}", e)
            return false
        }

        repeat(maxAttempts) { attempt ->
            try {
                val ok = com.securelegion.crypto.RustBridge.sendTap(
                    ed25519,
                    x25519,
                    recipientOnion
                )
                if (ok) return true

                Log.w(TAG, "TAP attempt ${attempt + 1}/$maxAttempts failed for ${contact.displayName}")

                if (attempt < maxAttempts - 1) {
                    delay(1000L * (attempt + 1))
                }
            } catch (e: Exception) {
                Log.e(TAG, "Exception sending TAP (attempt ${attempt + 1}) for ${contact.displayName}", e)
                if (attempt < maxAttempts - 1) {
                    delay(1000L * (attempt + 1))
                }
            }
        }

        return false
    }
}
