package com.securelegion.utils

import android.content.Context
import com.securelegion.models.TorHealthSnapshot
import com.securelegion.models.TorHealthStatus

/**
 * Helper to query Tor health status from any service/worker
 * Single source of truth for Tor health checks
 */
object TorHealthHelper {

    /**
     * Get current Tor health snapshot
     */
    fun getTorHealthSnapshot(context: Context): TorHealthSnapshot {
        val prefs = context.getSharedPreferences("tor_health", Context.MODE_PRIVATE)
        val prefsString = prefs.getString("snapshot", "")
        return if (prefsString.isNullOrEmpty()) {
            TorHealthSnapshot()  // Default to HEALTHY if no data
        } else {
            TorHealthSnapshot.fromPrefsString(prefsString)
        }
    }

    /**
     * Check if Tor is healthy enough to attempt sends
     */
    fun isTorHealthy(context: Context): Boolean {
        val snapshot = getTorHealthSnapshot(context)
        return snapshot.status == TorHealthStatus.HEALTHY
    }

    /**
     * Check if Tor is degraded (can send, but with caution)
     */
    fun isTorDegraded(context: Context): Boolean {
        val snapshot = getTorHealthSnapshot(context)
        return snapshot.status == TorHealthStatus.DEGRADED
    }

    /**
     * Check if Tor is unhealthy or recovering (should not send)
     */
    fun isTorUnavailable(context: Context): Boolean {
        val snapshot = getTorHealthSnapshot(context)
        return snapshot.status in listOf(TorHealthStatus.UNHEALTHY, TorHealthStatus.RECOVERING)
    }

    /**
     * Get human-readable status string for logging/UI
     */
    fun getStatusString(context: Context): String {
        val snapshot = getTorHealthSnapshot(context)
        return buildString {
            append(snapshot.status.name)
            if (snapshot.failCount > 0) append(" (failures: ${snapshot.failCount})")
            if (snapshot.lastError.isNotEmpty()) append(" - ${snapshot.lastError.take(50)}")
        }
    }
}
