package com.securelegion.services

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlin.random.Random

/**
 * FIFO invite queue with bounded Tor concurrency (k=1).
 *
 * Replaces sleep-based backpressure in CreateGroupActivity and GroupMembersActivity.
 * Wraps CrdtGroupManager.inviteMember() without changing it.
 *
 * Usage:
 *   val batchId = dispatcher.enqueue(groupId, contacts)
 *   dispatcher.observeBatch(batchId).collect { state -> updateUI(state) }
 */
class InviteDispatcher private constructor(private val appContext: Context) {

    companion object {
        private const val TAG = "InviteDispatcher"
        private const val MAX_QUEUE_SIZE = 64
        private const val MAX_STORED_BATCHES = 20
        private const val BATCH_EXPIRY_MS = 10L * 60 * 1000 // 10 minutes
        private const val BACKOFF_JITTER_FRACTION = 0.25
        private val BACKOFF_BASE_MS = 500L

        @Volatile
        private var INSTANCE: InviteDispatcher? = null

        fun getInstance(context: Context): InviteDispatcher {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: InviteDispatcher(context.applicationContext).also {
                    INSTANCE = it
                }
            }
        }
    }

    private val jobChannel = Channel<InviteJob>(capacity = MAX_QUEUE_SIZE)

    private val _batchStates = MutableStateFlow<Map<String, InviteBatchState>>(emptyMap())
    val batchStates: StateFlow<Map<String, InviteBatchState>> = _batchStates.asStateFlow()

    private val dispatcherScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    init {
        startWorker()
        startExpiryReaper()
    }

    // ==================== Public API ====================

    /**
     * Enqueue a batch of invites. Returns a batchId for observation.
     * Non-blocking — jobs are processed FIFO by the single worker coroutine.
     */
    fun enqueue(
        groupId: String,
        contacts: List<Pair<String, String>>,  // (pubkeyHex, displayName)
        role: String = "Member"
    ): String {
        val batchId = "${groupId.take(16)}-${System.currentTimeMillis()}"

        val memberStates = contacts.associate { (pubkey, name) ->
            pubkey to InviteMemberState(
                contactPubkeyHex = pubkey,
                contactDisplayName = name,
                status = InviteStatus.QUEUED
            )
        }
        updateBatchState(InviteBatchState(
            batchId = batchId,
            groupId = groupId,
            members = memberStates
        ))

        for ((pubkey, name) in contacts) {
            val job = InviteJob(
                batchId = batchId,
                groupId = groupId,
                contactPubkeyHex = pubkey,
                contactDisplayName = name,
                role = role
            )
            val sent = jobChannel.trySend(job)
            if (sent.isFailure) {
                Log.e(TAG, "Queue full — dropped invite for $name")
                updateMemberStatus(batchId, pubkey, InviteStatus.FAILED, error = "Queue full")
            }
        }

        Log.i(TAG, "Enqueued batch $batchId: ${contacts.size} invites for group ${groupId.take(16)}")
        return batchId
    }

    /**
     * Observe a specific batch's state. Completes when the batch is done or cleared.
     */
    fun observeBatch(batchId: String): Flow<InviteBatchState> {
        return _batchStates
            .map { it[batchId] }
            .filterNotNull()
            .distinctUntilChanged()
    }

    /**
     * Clean up a completed batch's state (free memory).
     */
    fun clearBatch(batchId: String) {
        _batchStates.update { it - batchId }
    }

    // ==================== Worker ====================

    private fun startWorker() {
        dispatcherScope.launch {
            for (job in jobChannel) {
                processJob(job)
            }
        }
    }

    private suspend fun processJob(job: InviteJob) {
        val tag = "${job.contactDisplayName}(${job.contactPubkeyHex.take(8)})"
        val attemptNum = job.attemptCount + 1
        Log.i(TAG, "Processing invite: $tag attempt=$attemptNum/${job.maxAttempts}")

        updateMemberStatus(job.batchId, job.contactPubkeyHex, InviteStatus.IN_PROGRESS,
            attemptCount = attemptNum)

        val startMs = System.currentTimeMillis()
        try {
            val mgr = CrdtGroupManager.getInstance(appContext)
            mgr.inviteMember(job.groupId, job.contactPubkeyHex, job.role)
            val authorName = com.securelegion.crypto.KeyManager.getInstance(appContext).getUsername() ?: "Someone"
            mgr.sendSystemMessage(job.groupId, "$authorName added ${job.contactDisplayName}")

            val elapsedMs = System.currentTimeMillis() - startMs
            Log.i(TAG, "Invite succeeded: $tag (${elapsedMs}ms)")
            updateMemberStatus(job.batchId, job.contactPubkeyHex, InviteStatus.SUCCEEDED,
                attemptCount = attemptNum)

        } catch (e: CancellationException) {
            throw e // don't swallow cancellation
        } catch (e: Exception) {
            val elapsedMs = System.currentTimeMillis() - startMs
            Log.e(TAG, "Invite failed: $tag attempt=$attemptNum (${elapsedMs}ms)", e)

            if (attemptNum < job.maxAttempts) {
                val backoffMs = calculateBackoff(job.attemptCount)
                Log.i(TAG, "Retrying $tag in ${backoffMs}ms (attempt ${attemptNum + 1}/${job.maxAttempts})")

                updateMemberStatus(job.batchId, job.contactPubkeyHex, InviteStatus.RETRYING,
                    attemptCount = attemptNum, error = e.message)

                delay(backoffMs)

                val retryJob = job.copy(attemptCount = attemptNum)
                val sent = jobChannel.trySend(retryJob)
                if (sent.isFailure) {
                    Log.e(TAG, "Failed to re-enqueue retry for $tag")
                    updateMemberStatus(job.batchId, job.contactPubkeyHex, InviteStatus.FAILED,
                        attemptCount = attemptNum, error = "Retry queue full")
                }
            } else {
                Log.e(TAG, "Invite permanently failed: $tag after ${job.maxAttempts} attempts")
                updateMemberStatus(job.batchId, job.contactPubkeyHex, InviteStatus.FAILED,
                    attemptCount = attemptNum, error = e.message)
            }
        }
    }

    // ==================== Backoff ====================

    private fun calculateBackoff(attemptIndex: Int): Long {
        val baseMs = BACKOFF_BASE_MS * (1L shl attemptIndex)  // 500, 1000, 2000, 4000
        val jitter = (baseMs * BACKOFF_JITTER_FRACTION * (Random.nextDouble() * 2 - 1)).toLong()
        return (baseMs + jitter).coerceAtLeast(100L)
    }

    // ==================== Expiry Reaper ====================

    /**
     * Periodically purge completed batches older than BATCH_EXPIRY_MS
     * and enforce MAX_STORED_BATCHES cap.
     */
    private fun startExpiryReaper() {
        dispatcherScope.launch {
            while (isActive) {
                delay(60_000L) // check every 60s
                val now = System.currentTimeMillis()
                _batchStates.update { current ->
                    var result = current.filterValues { batch ->
                        // Keep if still in progress OR not yet expired
                        !batch.isComplete || (now - batch.startedAt < BATCH_EXPIRY_MS)
                    }
                    // Enforce cap: drop oldest completed batches first
                    if (result.size > MAX_STORED_BATCHES) {
                        val sortedByAge = result.entries.sortedBy { it.value.startedAt }
                        val toDrop = result.size - MAX_STORED_BATCHES
                        val dropKeys = sortedByAge
                            .filter { it.value.isComplete }
                            .take(toDrop)
                            .map { it.key }
                        result = result - dropKeys.toSet()
                    }
                    result
                }
            }
        }
    }

    // ==================== State Updates ====================

    private fun updateBatchState(state: InviteBatchState) {
        _batchStates.update { it + (state.batchId to state) }
    }

    private fun updateMemberStatus(
        batchId: String,
        pubkeyHex: String,
        status: InviteStatus,
        attemptCount: Int = 0,
        error: String? = null
    ) {
        _batchStates.update { current ->
            val batch = current[batchId] ?: return@update current
            val member = batch.members[pubkeyHex] ?: return@update current
            val updated = member.copy(status = status, attemptCount = attemptCount, error = error)
            current + (batchId to batch.copy(members = batch.members + (pubkeyHex to updated)))
        }
    }
}

// ==================== Data Classes ====================

enum class InviteStatus {
    QUEUED, IN_PROGRESS, SUCCEEDED, FAILED, RETRYING
}

data class InviteJob(
    val batchId: String,
    val groupId: String,
    val contactPubkeyHex: String,
    val contactDisplayName: String,
    val role: String = "Member",
    val attemptCount: Int = 0,
    val maxAttempts: Int = 4
)

data class InviteMemberState(
    val contactPubkeyHex: String,
    val contactDisplayName: String,
    val status: InviteStatus,
    val attemptCount: Int = 0,
    val error: String? = null
)

data class InviteBatchState(
    val batchId: String,
    val groupId: String,
    val members: Map<String, InviteMemberState>,
    val startedAt: Long = System.currentTimeMillis()
) {
    val totalCount: Int get() = members.size
    val succeededCount: Int get() = members.values.count { it.status == InviteStatus.SUCCEEDED }
    val failedCount: Int get() = members.values.count { it.status == InviteStatus.FAILED }
    val pendingCount: Int get() = members.values.count {
        it.status in listOf(InviteStatus.QUEUED, InviteStatus.IN_PROGRESS, InviteStatus.RETRYING)
    }
    val isComplete: Boolean get() = pendingCount == 0
    val summaryText: String get() = when {
        isComplete && failedCount == 0 -> "All $totalCount members invited"
        isComplete -> "$succeededCount invited, $failedCount failed"
        else -> {
            val current = members.values.find { it.status == InviteStatus.IN_PROGRESS }
            if (current != null) "Inviting ${current.contactDisplayName}... ($succeededCount/$totalCount)"
            else "Inviting members... ($succeededCount/$totalCount)"
        }
    }
}
