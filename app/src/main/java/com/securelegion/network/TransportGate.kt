package com.securelegion.network

import android.os.SystemClock
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicInteger

/**
 * Global gate that blocks/allows all Tor network operations.
 *
 * When a network change occurs, gate is CLOSED until Tor probe succeeds.
 * All Tor operations must call awaitOpen() before proceeding.
 *
 * Timeouts prevent deadlocks — callers choose behavior on timeout:
 * - Best-effort ops (message send, inbox poll): proceed anyway
 * - Handshake ops (friend request, account publish): fail with TorNotReadyException
 */
class TransportGate {
    companion object {
        private const val TAG = "TransportGate"

        // Per-operation timeouts (tune by intent, not just bridge vs normal)
        const val TIMEOUT_QUICK_MS = 10_000L // Background polls, inbox checks
        const val TIMEOUT_SEND_MS = 20_000L // User-facing message send
        const val TIMEOUT_DEFAULT_MS = 30_000L // General operations
        const val TIMEOUT_HANDSHAKE_MS = 45_000L // Friend requests, key exchange
        const val TIMEOUT_BOOTSTRAP_MS = 90_000L // Account publish, HS descriptor upload
    }

    private val isOpen = MutableStateFlow(false)

    // Diagnostics
    private val timeoutCount = AtomicInteger(0)
    @Volatile var lastClosedAtMs: Long = 0L
        private set
    @Volatile var lastCloseReason: String = "INIT"
        private set

    /**
     * Block until gate opens, with a timeout to prevent deadlocks.
     * Returns true if gate opened, false if timed out.
     */
    suspend fun awaitOpen(timeoutMs: Long = TIMEOUT_DEFAULT_MS): Boolean {
        if (isOpen.value) {
            Log.d(TAG, "Gate already open — proceeding")
            return true
        }

        val closedAgeMs = SystemClock.elapsedRealtime() - lastClosedAtMs
        Log.d(TAG, "Awaiting gate open (timeout: ${timeoutMs}ms, closeReason=$lastCloseReason, closedAge=${closedAgeMs}ms)...")

        val result = withTimeoutOrNull(timeoutMs) {
            isOpen.filter { it }.first()
        }

        return if (result != null) {
            Log.d(TAG, "Gate opened, proceeding with network operation")
            true
        } else {
            val totalTimeouts = timeoutCount.incrementAndGet()
            Log.w(TAG, "Gate timed out (${timeoutMs}ms). closeReason=$lastCloseReason closedAge=${closedAgeMs + timeoutMs}ms timeouts=$totalTimeouts")
            false
        }
    }

    /**
     * Close gate, block all operations.
     * Called during network switch or restart sequence.
     */
    fun close(reason: String = "UNKNOWN") {
        Log.w(TAG, "Closing transport gate ($reason) - blocking all Tor operations")
        lastCloseReason = reason
        lastClosedAtMs = SystemClock.elapsedRealtime()
        isOpen.value = false
    }

    /**
     * Open gate, allow operations.
     * Called only after Tor probe succeeds.
     */
    fun open() {
        Log.i(TAG, "Opening transport gate - Tor verified working")
        isOpen.value = true
    }

    fun isOpenNow(): Boolean = isOpen.value
}
