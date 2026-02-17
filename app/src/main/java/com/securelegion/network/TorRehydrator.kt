package com.securelegion.network

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Listener rebind coordinator - debounces network events and requests TorService to rebind.
 *
 * DESIGN RULES:
 * - TorService owns Tor lifecycle (start/stop/health)
 * - TorRehydrator only coordinates listener rebinds
 * - No clearnet probes (no Google, no external hosts)
 * - Debounces rapid network flips into single rebind request
 *
 * Why this design:
 * - Avoids "second brain" competing with TorService
 * - No restart loops from failed clearnet probes
 * - No "Address already in use" from concurrent rebinds
 */
class TorRehydrator(
    private val onRebindRequest: suspend () -> Unit, // Callback to TorService
    private val scope: CoroutineScope
) {
    companion object {
        private const val TAG = "TorRehydrator"
        private const val DEBOUNCE_MS = 2000L // Wait 2s for network to settle
        private const val MIN_INTERVAL_MS = 5000L // Don't rebind more than once per 5s
    }

    private val rehydrateInFlight = AtomicBoolean(false)
    private val lastRehydrateMs = AtomicLong(0)
    private var debounceJob: Job? = null

    /**
     * Called when network changes - debounces and requests rebind
     */
    fun onNetworkChanged() {
        // Cancel any pending debounce
        debounceJob?.cancel()

        // Check if already in flight
        if (rehydrateInFlight.get()) {
            Log.d(TAG, "Network changed but rebind already in flight - ignoring")
            return
        }

        // Check if too soon since last rebind
        val now = System.currentTimeMillis()
        val timeSinceLastMs = now - lastRehydrateMs.get()
        if (timeSinceLastMs < MIN_INTERVAL_MS) {
            Log.d(TAG, "Network changed but last rebind was ${timeSinceLastMs}ms ago - ignoring")
            return
        }

        Log.i(TAG, "Network changed - will request rebind in ${DEBOUNCE_MS}ms")

        // Schedule debounced rebind request
        debounceJob = scope.launch {
            delay(DEBOUNCE_MS) // Wait for network to settle
            requestRebind()
        }
    }

    /**
     * Request TorService to rebind listeners (idempotent, gated)
     */
    private suspend fun requestRebind() {
        // Check again if already in flight (race condition)
        if (!rehydrateInFlight.compareAndSet(false, true)) {
            Log.d(TAG, "Rebind request dropped - already in flight")
            return
        }

        try {
            Log.i(TAG, "=== REBIND REQUEST START ===")
            lastRehydrateMs.set(System.currentTimeMillis())

            // Delegate to TorService (it handles gate, listeners, health)
            onRebindRequest()

            Log.i(TAG, "=== REBIND REQUEST COMPLETE ===")
        } catch (e: Exception) {
            Log.e(TAG, "Rebind request failed: ${e.message}", e)
        } finally {
            rehydrateInFlight.set(false)
        }
    }
}
