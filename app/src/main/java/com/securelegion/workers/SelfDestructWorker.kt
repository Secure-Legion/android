package com.securelegion.workers

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase

/**
 * Background worker that deletes expired self-destruct messages
 * Runs every hour to check for and delete messages past their self-destruct time
 */
class SelfDestructWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "SelfDestructWorker"
        const val WORK_NAME = "self_destruct_cleanup"
    }

    override suspend fun doWork(): Result {
        return try {
            Log.d(TAG, "Starting self-destruct cleanup...")

            // Get database instance
            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)

            // Delete expired messages
            val currentTime = System.currentTimeMillis()
            val deletedCount = database.messageDao().deleteExpiredMessages(currentTime)

            if (deletedCount > 0) {
                Log.i(TAG, "Deleted $deletedCount expired self-destruct messages")
            } else {
                Log.d(TAG, "No expired messages to delete")
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to cleanup self-destruct messages", e)
            Result.retry()
        }
    }
}
