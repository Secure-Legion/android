package com.securelegion.network

import android.util.Log
import com.securelegion.crypto.RustBridge

/**
 * Probe to verify Tor is healthy using MetricsPort (no external traffic).
 *
 * Why MetricsPort instead of clearnet probe:
 * 1. No external correlation - doesn't hit clearnet hosts
 * 2. Checks what we actually care about - circuits + bootstrap
 * 3. Works on all networks - doesn't depend on external hosts being reachable
 * 4. Fast - no network round-trip needed
 *
 * Old behavior (hitting check.torproject.org) caused:
 * - False negatives on networks that block external hosts
 * - Restart loops when clearnet probe timed out but Tor was healthy
 * - Unnecessary external traffic creating correlation patterns
 */
class TorProbe {
    companion object {
        private const val TAG = "TorProbe"
        private const val SOCKS_HOST = "127.0.0.1"
        private const val SOCKS_PORT = 9050
    }

    /**
     * Check if Tor is healthy via MetricsPort health check
     *
     * Checks:
     * - Bootstrap progress = 100%
     * - At least 1 circuit established
     *
     * @param timeoutMs Unused (kept for API compatibility)
     * @return true if Tor is healthy, false otherwise
     */
    suspend fun checkTorUsable(timeoutMs: Long = 10_000): Boolean {
        return try {
            // Check MetricsPort for bootstrap status
            val bootstrapPercent = RustBridge.getBootstrapStatus()
            val circuitsEstablished = RustBridge.getCircuitEstablished()

            val isHealthy = bootstrapPercent == 100 && circuitsEstablished >= 1

            if (isHealthy) {
                Log.i(TAG, "Tor probe PASSED - bootstrap=$bootstrapPercent%, circuits=$circuitsEstablished")
            } else {
                Log.w(TAG, "Tor probe FAILED - bootstrap=$bootstrapPercent%, circuits=$circuitsEstablished")
            }

            isHealthy
        } catch (e: Exception) {
            Log.e(TAG, "Tor probe FAILED: ${e.message}", e)
            false
        }
    }

}
