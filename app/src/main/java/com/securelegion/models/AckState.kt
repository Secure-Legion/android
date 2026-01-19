package com.securelegion.models

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArraySet

/**
 * ACK state machine for enforcing strict ordering:
 * NONE -> PING_ACKED -> PONG_ACKED -> MESSAGE_ACKED
 *
 * This prevents out-of-order ACKs from causing crypto desync.
 * Only valid transitions are allowed; all others are silently dropped.
 *
 * CRITICAL: ACKs are synchronization points in cryptographic ratcheting.
 * Out-of-order ACKs cause permanent state divergence that's impossible to recover from.
 *
 * THREAD SAFETY: Uses ConcurrentHashMap and CopyOnWriteArraySet for thread-safe access
 * from multiple threads (TorService background thread, MessageRetryWorker, etc.)
 */
enum class AckState {
    NONE,
    PING_ACKED,
    PONG_ACKED,
    MESSAGE_ACKED;

    /**
     * Check if this state can transition to the given ACK type
     * Returns true only for valid state transitions
     *
     * CRITICAL PROTOCOL FIX:
     * - PING_ACK: received from receiver (NONE → PING_ACKED)
     * - PONG_ACK: sent by sender (not received, handled locally via pongDelivered flag)
     * - MESSAGE_ACK: received from receiver (PING_ACKED → MESSAGE_ACKED, skip PONG_ACKED)
     *
     * The state machine no longer enforces PONG_ACKED as a prerequisite for MESSAGE_ACK,
     * because PONG_ACK is an outbound milestone (sender sends it), not an inbound ACK.
     * PONG_ACKED state is still tracked internally via message.pongDelivered field.
     */
    fun canTransitionTo(ackType: String): Boolean = when {
        this == NONE && ackType == "PING_ACK" -> true
        this == PING_ACKED && ackType == "MESSAGE_ACK" -> true
        this == PING_ACKED && ackType == "PONG_ACK" -> true  // Allow PONG_ACK for backward compat
        this == PONG_ACKED && ackType == "MESSAGE_ACK" -> true  // Allow if already PONG_ACKED
        else -> false
    }

    /**
     * Perform state transition for the given ACK type
     * Returns the new state, or null if transition is invalid
     */
    fun transitionTo(ackType: String): AckState? = when {
        this == NONE && ackType == "PING_ACK" -> PING_ACKED
        this == PING_ACKED && ackType == "MESSAGE_ACK" -> MESSAGE_ACKED  // Direct transition (no PONG_ACK requirement)
        this == PING_ACKED && ackType == "PONG_ACK" -> PONG_ACKED  // Allow PONG_ACK for backward compat
        this == PONG_ACKED && ackType == "MESSAGE_ACK" -> MESSAGE_ACKED
        else -> null
    }
}

/**
 * Tracks ACK state for each message in the thread
 *
 * Prevents out-of-order or duplicate ACKs from advancing state.
 * Ensures strict ordering: PING_ACK -> PONG_ACK -> MESSAGE_ACK
 *
 * CRITICAL INVARIANTS:
 * 1. Each message has exactly one state machine
 * 2. State transitions are strictly enforced (no out-of-order ACKs)
 * 3. Duplicate ACKs are detected and ignored (idempotency guard)
 * 4. Invalid transitions are logged and rejected
 *
 * This is the core defense against permanent crypto desync.
 */
class AckStateTracker {
    // Maps messageId -> current ACK state
    // THREAD SAFE: ConcurrentHashMap allows concurrent access from multiple threads
    // without external synchronization (TorService background thread, MessageRetryWorker, etc.)
    private val ackStates = ConcurrentHashMap<String, AckState>()

    // Set of (messageId, ackType) pairs that have been processed (idempotency guard)
    // Prevents duplicate ACKs from changing state multiple times
    // THREAD SAFE: CopyOnWriteArraySet is optimized for read-heavy workloads (many reads, few writes)
    // Each ACK is processed once, making this appropriate for idempotency guard
    private val processedAcks = CopyOnWriteArraySet<Pair<String, String>>()

    companion object {
        private const val TAG = "AckStateTracker"
    }

    /**
     * Process an incoming ACK with strict ordering enforcement
     *
     * Returns true if ACK was accepted and state advanced
     * Returns false if ACK was rejected (duplicate, out-of-order, invalid)
     *
     * @param messageId The message ID this ACK is for
     * @param ackType The type of ACK (PING_ACK, PONG_ACK, MESSAGE_ACK)
     * @return true if state changed, false if ACK was rejected
     */
    fun processAck(messageId: String, ackType: String): Boolean {
        val ackKey = messageId to ackType

        // Guard 1: Reject duplicate ACKs (idempotency)
        if (processedAcks.contains(ackKey)) {
            Log.d(TAG, "Duplicate ACK ignored: $messageId/$ackType")
            return false
        }

        // Get current state (default to NONE if new message)
        val current = ackStates.getOrDefault(messageId, AckState.NONE)

        // Guard 2: Verify valid transition
        if (!current.canTransitionTo(ackType)) {
            Log.w(TAG, "Invalid ACK transition: $current -> $ackType for $messageId (out-of-order or invalid)")
            return false
        }

        // Perform transition
        val next = current.transitionTo(ackType) ?: return false
        ackStates[messageId] = next
        processedAcks.add(ackKey)

        Log.d(TAG, "ACK processed: $messageId | $current -> $next")
        return true
    }

    /**
     * Get the current ACK state for a message
     * Returns NONE if message not yet tracked
     */
    fun getState(messageId: String): AckState =
        ackStates.getOrDefault(messageId, AckState.NONE)

    /**
     * Check if message is fully delivered (all ACKs received)
     */
    fun isDelivered(messageId: String): Boolean =
        getState(messageId) == AckState.MESSAGE_ACKED

    /**
     * Clear state for a specific message (after delivery confirmed)
     */
    fun clear(messageId: String) {
        ackStates.remove(messageId)
        processedAcks.removeAll { it.first == messageId }
        Log.d(TAG, "Cleared ACK state for message: $messageId")
    }

    /**
     * Clear all ACK state for messages in a thread
     * Called when thread is deleted to prevent resurrection
     *
     * @param messageIds List of messageIds to clear (all messages in thread)
     */
    fun clearByThread(messageIds: List<String>) {
        messageIds.forEach { messageId ->
            clear(messageId)
        }
        Log.d(TAG, "Cleared ACK state for ${messageIds.size} messages in deleted thread")
    }

    /**
     * Check if we have any pending ACKs for a message
     * (PING_ACKED, PONG_ACKED but not MESSAGE_ACKED)
     *
     * @return true if message has some but not all ACKs
     */
    fun hasPendingAcks(messageId: String): Boolean {
        val state = getState(messageId)
        return state != AckState.NONE && state != AckState.MESSAGE_ACKED
    }

    /**
     * Get all messages that are partially acknowledged (pending completion)
     */
    fun getPendingMessages(): List<String> =
        ackStates.filter { (_, state) -> state != AckState.NONE && state != AckState.MESSAGE_ACKED }
            .map { it.key }

    /**
     * Debug: Print current state of all tracked messages
     */
    fun dumpState() {
        Log.d(TAG, "====== AckStateTracker State Dump ======")
        Log.d(TAG, "Total messages tracked: ${ackStates.size}")
        Log.d(TAG, "Pending messages: ${getPendingMessages().size}")
        ackStates.forEach { (messageId, state) ->
            Log.d(TAG, "  $messageId: $state")
        }
        Log.d(TAG, "=========================================")
    }
}
