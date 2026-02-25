package com.securelegion.models

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArraySet

/**
 * ACK state machine for the simplified 4-hop protocol:
 *
 * Normal mode: NONE → PONG_RECEIVED → DELIVERED
 * DP mode:     NONE → PING_ACKED → PONG_RECEIVED → DELIVERED
 *
 * PONG_ACK is eliminated entirely — PONG serves as the acknowledgment.
 * Forward-progress: MESSAGE_ACK can jump to DELIVERED from any non-terminal state.
 * Forward-progress: PONG can jump to PONG_RECEIVED from NONE (if PING_ACK was lost in DP mode).
 *
 * THREAD SAFETY: Uses ConcurrentHashMap and CopyOnWriteArraySet for thread-safe access
 * from multiple threads (TorService background thread, MessageRetryWorker, etc.)
 */
enum class AckState {
    NONE,
    PING_ACKED,      // DP only: PING_ACK arrived (device alive, waiting for bio gate)
    PONG_RECEIVED,   // Normal: PONG arrived. DP: PONG arrived (after bio gate)
    DELIVERED;        // MESSAGE_ACK received

    /**
     * Check if this state can transition to the given ACK type.
     *
     * Normal mode: NONE → PONG_RECEIVED → DELIVERED
     * DP mode:     NONE → PING_ACKED → PONG_RECEIVED → DELIVERED
     *
     * Forward-progress allowed: MESSAGE_ACK can jump to DELIVERED from any non-terminal state.
     * PONG can jump to PONG_RECEIVED from NONE (if PING_ACK was lost in DP mode).
     */
    fun canTransitionTo(ackType: String): Boolean = when {
        // Normal mode transitions
        this == NONE && ackType == "PONG" -> true
        this == PONG_RECEIVED && ackType == "MESSAGE_ACK" -> true
        // DP mode transitions
        this == NONE && ackType == "PING_ACK" -> true
        this == PING_ACKED && ackType == "PONG" -> true
        // Forward progress: MESSAGE_ACK from any non-terminal state
        ackType == "MESSAGE_ACK" && this != DELIVERED -> true
        else -> false
    }

    /**
     * Perform state transition for the given ACK type.
     * Returns the new state, or null if transition is invalid.
     */
    fun transitionTo(ackType: String): AckState? = when {
        this == NONE && ackType == "PING_ACK" -> PING_ACKED
        this == NONE && ackType == "PONG" -> PONG_RECEIVED
        this == PING_ACKED && ackType == "PONG" -> PONG_RECEIVED
        this == PONG_RECEIVED && ackType == "MESSAGE_ACK" -> DELIVERED
        // Forward progress
        ackType == "MESSAGE_ACK" && this != DELIVERED -> DELIVERED
        else -> null
    }
}

/**
 * Tracks ACK state for each message in the thread.
 *
 * Simplified protocol state machine:
 * - Normal mode: PONG = acknowledgment, MESSAGE_ACK = delivered
 * - DP mode: PING_ACK = device alive, PONG = human verified, MESSAGE_ACK = delivered
 * - No PONG_ACK — eliminated entirely
 *
 * CRITICAL INVARIANTS:
 * 1. Each message has exactly one state machine
 * 2. State transitions are strictly enforced (no out-of-order ACKs)
 * 3. Duplicate ACKs are detected and ignored (idempotency guard)
 * 4. Invalid transitions are logged and rejected
 */
class AckStateTracker {
    // Maps messageId -> current ACK state
    // THREAD SAFE: ConcurrentHashMap allows concurrent access from multiple threads
    private val ackStates = ConcurrentHashMap<String, AckState>()

    // Set of (messageId, ackType) pairs that have been processed (idempotency guard)
    // THREAD SAFE: CopyOnWriteArraySet is optimized for read-heavy workloads
    private val processedAcks = CopyOnWriteArraySet<Pair<String, String>>()

    companion object {
        private const val TAG = "AckStateTracker"
    }

    /**
     * Process an incoming ACK with idempotent handling.
     *
     * Returns true if ACK was accepted (either new or duplicate of previously processed ACK).
     * Returns false only for invalid ACKs that were never processed.
     *
     * @param messageId The message ID this ACK is for
     * @param ackType The type of ACK (PING_ACK, PONG, MESSAGE_ACK)
     * @return true if ACK is valid (new or duplicate), false only for genuinely invalid ACKs
     */
    fun processAck(messageId: String, ackType: String): Boolean {
        val ackKey = messageId to ackType

        // Guard 1: Handle duplicate ACKs (idempotency)
        if (processedAcks.contains(ackKey)) {
            Log.d(TAG, "Duplicate ACK (idempotent): $messageId/$ackType")
            return true
        }

        val current = ackStates.getOrDefault(messageId, AckState.NONE)

        if (!current.canTransitionTo(ackType)) {
            Log.w(TAG, "Invalid transition: $current -> $ackType for $messageId")
            return false
        }

        val next = current.transitionTo(ackType) ?: return false
        ackStates[messageId] = next
        processedAcks.add(ackKey)

        Log.d(TAG, "ACK processed: $messageId | $current -> $next")
        return true
    }

    /**
     * Get the current ACK state for a message.
     * Returns NONE if message not yet tracked.
     */
    fun getState(messageId: String): AckState =
        ackStates.getOrDefault(messageId, AckState.NONE)

    /**
     * Check if message is fully delivered (MESSAGE_ACK received).
     */
    fun isDelivered(messageId: String): Boolean =
        getState(messageId) == AckState.DELIVERED

    /**
     * Clear state for a specific message (after delivery confirmed).
     */
    fun clear(messageId: String) {
        ackStates.remove(messageId)
        processedAcks.removeAll { it.first == messageId }
        Log.d(TAG, "Cleared ACK state for message: $messageId")
    }

    /**
     * Clear all ACK state for messages in a thread.
     * Called when thread is deleted to prevent resurrection.
     */
    fun clearByThread(messageIds: List<String>) {
        messageIds.forEach { messageId ->
            clear(messageId)
        }
        Log.d(TAG, "Cleared ACK state for ${messageIds.size} messages in deleted thread")
    }

    /**
     * Check if we have any pending ACKs for a message
     * (PING_ACKED or PONG_RECEIVED but not DELIVERED).
     */
    fun hasPendingAcks(messageId: String): Boolean {
        val state = getState(messageId)
        return state != AckState.NONE && state != AckState.DELIVERED
    }

    /**
     * Get all messages that are partially acknowledged (pending completion).
     */
    fun getPendingMessages(): List<String> =
        ackStates.filter { (_, state) -> state != AckState.NONE && state != AckState.DELIVERED }
            .map { it.key }

    /**
     * Debug: Print current state of all tracked messages.
     */
    fun dumpState() {
        Log.d(TAG, "====== AckStateTracker State Dump ======")
        Log.d(TAG, "Total messages tracked: ${ackStates.size}")
        Log.d(TAG, "Pending messages: ${getPendingMessages().size}")
        ackStates.forEach { (messageId, state) ->
            Log.d(TAG, "$messageId: $state")
        }
        Log.d(TAG, "=========================================")
    }
}
