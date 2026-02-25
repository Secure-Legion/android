package com.securelegion.utils

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * Mediates biometric/credential authentication before PONG emission in Device Protection mode.
 *
 * Key behaviors:
 * - Single-flight: multiple pings → one prompt → batch release
 * - Cooldown: 60s window after success (configurable)
 * - Idempotent per pingId
 * - Rate limiting is enforced via PingInbox.lastPongSentAt (DB)
 */
class DeviceProtectionGate(private val context: Context) {

    companion object {
        private const val TAG = "DeviceProtectionGate"
        const val DEFAULT_COOLDOWN_MS = 60_000L  // 60 seconds
        const val GATE_TIMEOUT_MS = 300_000L     // 5 minutes (matches PING expiry)
        const val JITTER_MIN_MS = 5_000L         // 5 seconds
        const val JITTER_MAX_MS = 15_000L        // 15 seconds
        const val JITTER_CAP_MS = 20_000L        // 20 seconds hard cap

        @Volatile
        private var instance: DeviceProtectionGate? = null

        fun getInstance(context: Context): DeviceProtectionGate {
            return instance ?: synchronized(this) {
                instance ?: DeviceProtectionGate(context.applicationContext).also { instance = it }
            }
        }
    }

    // Timestamp of last successful authentication
    @Volatile
    var lastHumanUnlockAt: Long = 0L
        private set

    // Pending pings waiting for gate to open
    private val pendingPings = ConcurrentHashMap<String, PendingPing>()

    // Gate state observable
    private val _gateState = MutableStateFlow<GateState>(GateState.Idle)
    val gateState: StateFlow<GateState> = _gateState

    data class PendingPing(
        val pingId: String,
        val contactId: Long,
        val connectionId: Long,
        val enqueuedAt: Long = System.currentTimeMillis()
    )

    sealed class GateState {
        object Idle : GateState()
        object PromptShowing : GateState()
        object Granted : GateState()
        data class Denied(val reason: String) : GateState()
    }

    sealed class GateResult {
        object Granted : GateResult()
        object Denied : GateResult()
        object Unavailable : GateResult()
    }

    fun getCooldownMs(): Long {
        val prefs = context.getSharedPreferences("security", Context.MODE_PRIVATE)
        return prefs.getLong("device_protection_cooldown_ms", DEFAULT_COOLDOWN_MS)
    }

    fun isInCooldown(): Boolean {
        return System.currentTimeMillis() - lastHumanUnlockAt <= getCooldownMs()
    }

    /**
     * Enqueue a ping for biometric gate. If cooldown is active, immediately releases.
     * If not, queues for batch release on next auth success.
     *
     * @return true if ping was immediately released (cooldown), false if queued
     */
    fun enqueue(pingId: String, contactId: Long, connectionId: Long): Boolean {
        if (isInCooldown()) {
            Log.d(TAG, "Cooldown active — immediately releasing ping $pingId")
            return true  // Caller should proceed with PONG
        }

        pendingPings[pingId] = PendingPing(pingId, contactId, connectionId)
        Log.d(TAG, "Ping $pingId enqueued for biometric gate (${pendingPings.size} pending)")

        // Trigger prompt if not already showing
        if (_gateState.value != GateState.PromptShowing) {
            _gateState.value = GateState.PromptShowing
        }

        return false  // Caller should NOT send PONG yet
    }

    /**
     * Called when biometric/credential auth succeeds.
     * Releases all pending pings and starts cooldown.
     */
    fun onAuthSuccess() {
        lastHumanUnlockAt = System.currentTimeMillis()
        _gateState.value = GateState.Granted
        Log.i(TAG, "Auth success — releasing ${pendingPings.size} pending pings, cooldown started")
    }

    /**
     * Called when biometric/credential auth fails or is cancelled.
     */
    fun onAuthDenied(reason: String = "User cancelled") {
        _gateState.value = GateState.Denied(reason)
        Log.w(TAG, "Auth denied: $reason — ${pendingPings.size} pings remain pending")
    }

    /**
     * Drain and return all pending pings (called after auth success).
     */
    fun drainPendingPings(): List<PendingPing> {
        val drained = pendingPings.values.toList()
        pendingPings.clear()
        _gateState.value = GateState.Idle
        Log.d(TAG, "Drained ${drained.size} pending pings")
        return drained
    }

    /**
     * Clean up expired pings (older than GATE_TIMEOUT_MS).
     * Resets gate state to Idle if all pings have expired.
     */
    fun cleanupExpired() {
        val now = System.currentTimeMillis()
        val expired = pendingPings.filter { now - it.value.enqueuedAt > GATE_TIMEOUT_MS }
        expired.forEach { pendingPings.remove(it.key) }
        if (expired.isNotEmpty()) {
            Log.d(TAG, "Cleaned up ${expired.size} expired pending pings")
        }
        // Reset state if no pending pings remain (prevents sticky PromptShowing)
        if (pendingPings.isEmpty() && _gateState.value == GateState.PromptShowing) {
            _gateState.value = GateState.Idle
        }
    }

    /**
     * Calculate jitter delay for DP mode PONG send (M5 timing side channel mitigation).
     * Uniform random in [JITTER_MIN_MS, JITTER_MAX_MS], capped at JITTER_CAP_MS.
     */
    fun calculateJitterMs(): Long {
        val jitter = JITTER_MIN_MS + (Math.random() * (JITTER_MAX_MS - JITTER_MIN_MS)).toLong()
        return jitter.coerceAtMost(JITTER_CAP_MS)
    }
}
