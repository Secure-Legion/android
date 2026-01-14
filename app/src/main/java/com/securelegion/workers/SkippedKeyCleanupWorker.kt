package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import java.util.concurrent.TimeUnit

/**
 * Background worker that deletes old skipped message keys
 * Runs daily to check for and delete keys older than 30 days (TTL)
 *
 * This prevents database bloat from accumulated skipped keys that were never used.
 * Keys older than 30 days are assumed to be from messages that will never arrive.
 */
class SkippedKeyCleanupWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "SkippedKeyCleanupWorker"
        const val WORK_NAME = "skipped_key_cleanup"

        // TTL for skipped keys: 30 days
        private const val KEY_TTL_DAYS = 30L
    }

    override suspend fun doWork(): Result {
        return try {
            Log.d(TAG, "Starting skipped key cleanup (TTL: $KEY_TTL_DAYS days)...")

            // Get database instance
            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)

            // Calculate cutoff time (current time - 30 days)
            val currentTime = System.currentTimeMillis()
            val cutoffTime = currentTime - TimeUnit.DAYS.toMillis(KEY_TTL_DAYS)

            Log.d(TAG, "Deleting skipped keys older than: $cutoffTime (${KEY_TTL_DAYS} days ago)")

            // Delete old keys
            val deletedCount = database.skippedMessageKeyDao().deleteOldKeys(cutoffTime)

            if (deletedCount > 0) {
                Log.i(TAG, "Deleted $deletedCount expired skipped message keys (older than $KEY_TTL_DAYS days)")
            } else {
                Log.d(TAG, "No expired skipped keys to delete")
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to cleanup skipped message keys", e)
            Result.retry()
        }
    }
}
