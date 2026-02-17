package com.securelegion.models

import android.os.SystemClock

/**
 * Tor health status enum
 *
 * HEALTHY: SOCKS5 responding, circuits working
 * DEGRADED: SOCKS5 responding but circuit checks failing (peer unreachable)
 * UNHEALTHY: SOCKS5 not responding or bootstrap incomplete after retries
 * RECOVERING: Attempting restart, give it time before trying to send
 */
enum class TorHealthStatus {
    HEALTHY,
    DEGRADED,
    UNHEALTHY,
    RECOVERING
}

/**
 * Failure type for diagnostics and state machine
 *
 * SOCKS_DOWN: SOCKS5 port not responding (immediate UNHEALTHY)
 * BOOTSTRAP_NOT_READY: Tor bootstrapping < 100% (RECOVERING, try later)
 * CIRCUIT_FAILED: Self-check to onion failed (DEGRADED, retry circuit setup)
 * PEER_UNREACHABLE: Connecting to peer onion failed (DEGRADED, not Tor's fault)
 * UNKNOWN: Parse error or unexpected failure
 */
enum class TorFailureType {
    SOCKS_DOWN,
    BOOTSTRAP_NOT_READY,
    CIRCUIT_FAILED,
    PEER_UNREACHABLE,
    UNKNOWN
}

/**
 * Snapshot of Tor health state at a point in time
 *
 * Stored in SharedPreferences for fast access by workers/services
 * Updated by TorHealthMonitorWorker every 30-60 seconds
 *
 * IMPORTANT: Uses elapsedRealtime() for all time calculations (immune to clock sync)
 */
data class TorHealthSnapshot(
    val status: TorHealthStatus = TorHealthStatus.HEALTHY,

    // When was the last successful health check (SOCKS + circuit both OK)? (elapsedRealtime)
    val lastOkElapsedMs: Long = 0,

    // How many consecutive health checks have failed?
    val failCount: Int = 0,

    // When was the last Tor restart attempt? (elapsedRealtime)
    val lastRestartElapsedMs: Long = 0,

    // When was the last health check performed? (elapsedRealtime)
    val lastCheckElapsedMs: Long = 0,

    // When did status last transition (to help UI/debugging)? (elapsedRealtime)
    val lastStatusChangeElapsedMs: Long = 0,

    // Current restart cooldown (ms) - increases exponentially: 0 → 1s → 5s → 30s → 60s cap
    val restartCooldownMs: Long = 0,

    // Type of failure (for state machine transitions)
    val lastFailureType: TorFailureType = TorFailureType.UNKNOWN,

    // Error message from last failed check (capped at 512 chars, no newlines)
    val lastError: String = ""
) {
    companion object {
        private const val TAG = "TorHealthSnapshot"
        private const val MAX_ERROR_LEN = 512

        /**
         * Serialize to string for SharedPreferences storage
         * Format: status|lastOkElapsedMs|failCount|lastRestartElapsedMs|lastCheckElapsedMs|lastStatusChangeElapsedMs|restartCooldownMs|failureType|lastError
         */
        fun toPrefsString(snapshot: TorHealthSnapshot): String {
            // Sanitize lastError: cap length, remove newlines
            val sanitizedError = snapshot.lastError
                .replace("\n", " ")
                .replace("\r", " ")
                .take(MAX_ERROR_LEN)

            return "${snapshot.status.ordinal}|" +
                   "${snapshot.lastOkElapsedMs}|" +
                   "${snapshot.failCount}|" +
                   "${snapshot.lastRestartElapsedMs}|" +
                   "${snapshot.lastCheckElapsedMs}|" +
                   "${snapshot.lastStatusChangeElapsedMs}|" +
                   "${snapshot.restartCooldownMs}|" +
                   "${snapshot.lastFailureType.ordinal}|" +
                   sanitizedError
        }

        /**
         * Deserialize from SharedPreferences string
         *
         * On parse error, defaults to RECOVERING (conservative) not HEALTHY (dangerous)
         */
        fun fromPrefsString(prefsString: String): TorHealthSnapshot {
            return try {
                val parts = prefsString.split("|", limit = 9) // Split into max 9 parts
                if (parts.size < 9) {
                    // Malformed: return RECOVERING to avoid false-healthy
                    return TorHealthSnapshot(
                        status = TorHealthStatus.RECOVERING,
                        lastError = "prefs parse error (incomplete)"
                    )
                }

                TorHealthSnapshot(
                    status = TorHealthStatus.values().getOrElse(parts[0].toIntOrNull() ?: 0) { TorHealthStatus.RECOVERING },
                    lastOkElapsedMs = parts[1].toLongOrNull() ?: 0,
                    failCount = parts[2].toIntOrNull() ?: 0,
                    lastRestartElapsedMs = parts[3].toLongOrNull() ?: 0,
                    lastCheckElapsedMs = parts[4].toLongOrNull() ?: 0,
                    lastStatusChangeElapsedMs = parts[5].toLongOrNull() ?: 0,
                    restartCooldownMs = parts[6].toLongOrNull() ?: 0,
                    lastFailureType = TorFailureType.values().getOrElse(parts[7].toIntOrNull() ?: 0) { TorFailureType.UNKNOWN },
                    lastError = parts[8]
                )
            } catch (e: Exception) {
                // Parse exception: default to RECOVERING (safe conservative state)
                TorHealthSnapshot(
                    status = TorHealthStatus.RECOVERING,
                    lastError = "prefs parse exception: ${e.message?.take(100) ?: "unknown"}"
                )
            }
        }
    }

    /**
     * Check if we should attempt another restart
     * Respects exponential backoff cooldown using monotonic time
     */
    fun shouldAttemptRestart(): Boolean {
        val elapsedNow = SystemClock.elapsedRealtime()
        val timeSinceLastRestart = elapsedNow - lastRestartElapsedMs
        return timeSinceLastRestart >= restartCooldownMs
    }

    /**
     * Calculate next restart cooldown (exponential backoff)
     * 0 → 1s → 5s → 30s → 60s (cap)
     *
     * Fixed off-by-one: starting at 0 ensures first call yields 1000ms
     */
    fun nextRestartCooldown(): Long {
        return when {
            restartCooldownMs == 0L -> 1000 // First attempt: 1s
            restartCooldownMs < 5000 -> 5000 // Second: 5s
            restartCooldownMs < 30000 -> 30000 // Third: 30s
            else -> 60000 // Cap at 60s
        }
    }

    /**
     * Get time since last successful health check
     * Uses monotonic time (elapsedRealtime) - immune to clock sync issues
     */
    fun timeSinceLastOkMs(): Long {
        val elapsedNow = SystemClock.elapsedRealtime()
        return elapsedNow - lastOkElapsedMs
    }

    /**
     * Check if health check is stale (hasn't run in > 2 minutes)
     * If stale, we can't trust the status
     */
    fun isCheckStale(): Boolean {
        val elapsedNow = SystemClock.elapsedRealtime()
        val timeSinceLastCheck = elapsedNow - lastCheckElapsedMs
        return timeSinceLastCheck > 120000 // 2 minutes
    }
}
