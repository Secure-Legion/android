package com.securelegion.network

import android.os.SystemClock
import android.util.Log
import com.securelegion.crypto.RustBridge
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Per-peer health tracking that gates outbound Arti sends behind a cheap
 * connect/close probe when a peer's failure streak is high. Inspired by the
 * iOS pattern in `Secure/VPNManager.swift` (artiPeerFailureStreak +
 * artiPreflightConnect) — minus the cooldown gate, which doubles up with the
 * existing retry-loop cadence.
 *
 * Why this exists: when Arti's circuit graph to a specific `.onion` is
 * temporarily dead (relay set in the descriptor is stale, intro points are
 * down, kernel is returning ENETUNREACH for that target), repeated full
 * PING+PONG+ACK exchanges burn time and battery and feed the AllGuardsDown
 * poison detector. A 3.5s preflight catches the problem cheaply, lets the
 * caller skip just THAT attempt, and the existing retry loop tries again on
 * its own cadence with a fresh probe.
 *
 * Thread-safe via ConcurrentHashMap + AtomicInteger. Process-scoped state —
 * cleared on app/service restart, which is the right semantics (fresh Arti
 * client = fresh circuits = streaks no longer meaningful).
 */
object ArtiPeerHealthGate {
    private const val TAG = "ArtiPeerHealthGate"

    /** Failures before preflight is invoked. Below this we just retry. */
    const val PREFLIGHT_FAILURE_THRESHOLD = 3

    /** Preflight probe timeout. Matches iOS Self.artiPreflightTimeoutMs. */
    const val PREFLIGHT_TIMEOUT_MS = 3_500

    private const val PREFLIGHT_NEWNYM_THRESHOLD = PREFLIGHT_FAILURE_THRESHOLD + 2
    private const val PREFLIGHT_NEWNYM_COOLDOWN_MS = 45_000L

    private val peerStreak = ConcurrentHashMap<String, AtomicInteger>()
    private val lastPreflightNewnymAtMs = AtomicLong(0L)

    /** True when the peer's consecutive-failure streak crossed the threshold. */
    fun shouldPreflight(onion: String): Boolean {
        val streak = peerStreak[onion]?.get() ?: 0
        return streak >= PREFLIGHT_FAILURE_THRESHOLD
    }

    /**
     * Run the preflight probe. On success returns true and the caller should
     * proceed with the real send. On failure returns false and increments the
     * streak — the caller skips THIS attempt; the next retry cycle gets a
     * fresh probe with no artificial cooldown layered on top of the existing
     * retry cadence.
     */
    fun runPreflight(onion: String, port: Int): Boolean {
        val result = try {
            RustBridge.artiPreflightConnect(onion, port, PREFLIGHT_TIMEOUT_MS)
        } catch (t: Throwable) {
            Log.w(TAG, "preflight JNI threw for $onion:$port — treating as failure", t)
            -3L
        }
        if (result >= 0) {
            Log.d(TAG, "preflight OK $onion:$port latencyMs=$result")
            return true
        }
        val reason = when (result) {
            -1L -> "not_ready"
            -2L -> "timeout"
            else -> "connect_failed"
        }
        val streak = recordFailure(onion)
        maybeRequestNewnym(onion, streak, reason)
        Log.w(TAG, "preflight FAILED $onion:$port reason=$reason — skipping this attempt")
        return false
    }

    private fun maybeRequestNewnym(onion: String, streak: Int, reason: String) {
        if (streak < PREFLIGHT_NEWNYM_THRESHOLD) return

        val now = SystemClock.elapsedRealtime()
        val last = lastPreflightNewnymAtMs.get()
        val remaining = PREFLIGHT_NEWNYM_COOLDOWN_MS - (now - last)
        if (remaining > 0L) {
            Log.d(TAG, "preflight NEWNYM suppressed for $onion (cooldown ${remaining}ms, streak=$streak)")
            return
        }

        if (!lastPreflightNewnymAtMs.compareAndSet(last, now)) return

        try {
            val ok = RustBridge.sendNewnym()
            Log.w(TAG, "preflight failure streak=$streak for $onion reason=$reason - requested NEWNYM success=$ok")
        } catch (t: Throwable) {
            Log.w(TAG, "preflight NEWNYM failed for $onion", t)
        }
    }

    /** Successful send — clear streak state for this peer. */
    fun recordSuccess(onion: String) {
        peerStreak.remove(onion)
    }

    /** Failed send (real send, not preflight) — bump the streak. */
    fun recordFailure(onion: String): Int {
        return peerStreak.computeIfAbsent(onion) { AtomicInteger(0) }.incrementAndGet()
    }

    /** Test/diagnostic: clear all per-peer state. */
    fun resetAll() {
        peerStreak.clear()
    }
}
