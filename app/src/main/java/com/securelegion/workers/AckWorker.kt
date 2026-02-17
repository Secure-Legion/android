package com.securelegion.workers

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * AckWorker
 *
 * RESPONSIBILITY (STRICT):
 * - Send PING_ACKs for received PINGs
 * - Recover orphaned ACKs after crashes
 *
 * THIS WORKER DOES NOT:
 * - Retry PINGs
 * - Send message blobs
 * - Poll for PONGs
 *
 * Triggered by:
 * - TAP arrival (contact-specific)
 * - Periodic background sweep (crash recovery)
 */
class AckWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "AckWorker"
        private const val PERIODIC_WORK_NAME = "ack_sweep_work"

        fun scheduleForContact(context: Context, contactId: Long) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val data = workDataOf("CONTACT_ID" to contactId)

            val work = OneTimeWorkRequestBuilder<AckWorker>()
                .setInputData(data)
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                "ack_worker_contact_$contactId",
                ExistingWorkPolicy.REPLACE,
                work
            )

            Log.i(TAG, "Scheduled AckWorker for contact $contactId")
        }

        fun schedulePeriodicSweep(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val work = PeriodicWorkRequestBuilder<AckWorker>(
                15, TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                PERIODIC_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                work
            )

            Log.i(TAG, "Scheduled periodic AckWorker sweep")
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val contactId = inputData.getLong("CONTACT_ID", -1L)
            val isContactSpecific = contactId != -1L

            Log.d(
                TAG,
                if (isContactSpecific)
                    "Starting contact-specific ACK sweep for contact $contactId"
                else
                    "Starting periodic ACK sweep"
            )

            val keyManager = KeyManager.getInstance(applicationContext)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)

            val sent = if (isContactSpecific) {
                sendPendingPingAcksForContact(database, contactId)
            } else {
                sendPendingPingAcks(database)
            }

            if (sent > 0) {
                Log.i(TAG, "Sent $sent PING_ACK(s)")
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "AckWorker failed", e)
            Result.retry()
        }
    }

    /**
     * Send pending PING_ACKs for all contacts
     */
    private suspend fun sendPendingPingAcks(
        database: SecureLegionDatabase
    ): Int = withContext(Dispatchers.IO) {

        val pendingPings = database.pingInboxDao().getAllPending()
        if (pendingPings.isEmpty()) return@withContext 0

        var ackCount = 0

        for (ping in pendingPings) {
            if (ping.pingAckedAt != null) continue

            val contact = database.contactDao().getContactById(ping.contactId) ?: continue

            val success = sendAckWithRetry(
                contact = contact,
                itemId = ping.pingId,
                ackType = "PING_ACK"
            )

            if (success) {
                val now = System.currentTimeMillis()

                // Update ping inbox (transport layer)
                database.pingInboxDao().updatePingAckTime(ping.pingId, now)

                // CRITICAL FIX:
                // Update authoritative message state so protocol can advance safely
                database.messageDao().markPingDelivered(ping.pingId)

                ackCount++
                Log.d(TAG, "Sent PING_ACK for pingId=${ping.pingId.take(8)}...")
            }
        }

        ackCount
    }

    /**
     * Send pending PING_ACKs for a specific contact
     */
    private suspend fun sendPendingPingAcksForContact(
        database: SecureLegionDatabase,
        contactId: Long
    ): Int = withContext(Dispatchers.IO) {

        val pendingPings = database.pingInboxDao().getPendingByContact(contactId)
        if (pendingPings.isEmpty()) return@withContext 0

        var ackCount = 0

        for (ping in pendingPings) {
            if (ping.pingAckedAt != null) continue

            val contact = database.contactDao().getContactById(ping.contactId) ?: continue

            val success = sendAckWithRetry(
                contact = contact,
                itemId = ping.pingId,
                ackType = "PING_ACK"
            )

            if (success) {
                val now = System.currentTimeMillis()

                database.pingInboxDao().updatePingAckTime(ping.pingId, now)
                database.messageDao().markPingDelivered(ping.pingId)

                ackCount++
                Log.d(TAG, "Sent PING_ACK for pingId=${ping.pingId.take(8)}...")
            }
        }

        ackCount
    }

    /**
     * Send ACK with bounded retry
     */
    private suspend fun sendAckWithRetry(
        contact: com.securelegion.database.entities.Contact,
        itemId: String,
        ackType: String,
        maxRetries: Int = 3
    ): Boolean {
        repeat(maxRetries) { attempt ->
            try {
                val success = com.securelegion.crypto.RustBridge.sendDeliveryAck(
                    itemId = itemId,
                    ackType = ackType,
                    recipientEd25519Pubkey = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP),
                    recipientX25519Pubkey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP),
                    recipientOnion = contact.messagingOnion ?: contact.torOnionAddress ?: ""
                )

                if (success) return true

                if (attempt < maxRetries - 1) {
                    kotlinx.coroutines.delay(1000L * (attempt + 1))
                }

            } catch (e: Exception) {
                Log.e(TAG, "Exception sending $ackType (attempt ${attempt + 1})", e)
                if (attempt < maxRetries - 1) {
                    kotlinx.coroutines.delay(1000L * (attempt + 1))
                }
            }
        }

        return false
    }
}
