package com.securelegion.services

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Per-contact download state machine.
 *
 * States:
 *   IDLE        — no active download, queue empty or retries pending invisibly
 *   DOWNLOADING — at least one active download in progress (typing indicator ON)
 *   BACKOFF     — all downloads failed, retry scheduled (typing OFF, invisible to user)
 *   PAUSED      — background delivery stopped; lock icon allowed (rare)
 *
 * UI rules:
 *   Typing indicator = DOWNLOADING only
 *   Lock icon        = PAUSED only (device protection ON, no network, etc.)
 *   Nothing visible  = IDLE or BACKOFF
 *
 * Thread-safe: all fields are ConcurrentHashMap / AtomicInteger.
 * Process-death safety: DOWNLOADING entries older than STALE_THRESHOLD_MS auto-expire to BACKOFF.
 */
object DownloadStateManager {

    private const val TAG = "DownloadStateMgr"

    /** Maximum time a contact can stay in DOWNLOADING before we assume the download died. */
    private const val STALE_THRESHOLD_MS = 120_000L // 2 minutes

    enum class State { IDLE, DOWNLOADING, BACKOFF, PAUSED }

    /** Active download count per contact. >0 means DOWNLOADING. */
    private val activeDownloads = ConcurrentHashMap<Long, AtomicInteger>()

    /** Timestamp when contact ENTERED DOWNLOADING (0→1 transition only) — for stale detection. */
    private val downloadStartedAt = ConcurrentHashMap<Long, Long>()

    /** Explicit state override for BACKOFF and PAUSED (not tracked by counter). */
    private val overrides = ConcurrentHashMap<Long, State>()

    /**
     * Current state for a contact.
     * Derived: activeDownloads > 0 → DOWNLOADING (unless stale), else check overrides, else IDLE.
     */
    fun getState(contactId: Long): State {
        val count = activeDownloads[contactId]?.get() ?: 0
        if (count > 0) {
            // Check staleness — if session started more than STALE_THRESHOLD_MS ago, auto-expire
            val startedAt = downloadStartedAt[contactId] ?: 0L
            if (startedAt > 0 && System.currentTimeMillis() - startedAt > STALE_THRESHOLD_MS) {
                Log.w(TAG, "Contact $contactId stuck in DOWNLOADING for >${STALE_THRESHOLD_MS / 1000}s — forcing BACKOFF")
                activeDownloads.remove(contactId)
                downloadStartedAt.remove(contactId)
                overrides[contactId] = State.BACKOFF
                return State.BACKOFF
            }
            return State.DOWNLOADING
        }
        return overrides[contactId] ?: State.IDLE
    }

    /** True if at least one download is actively in progress for this contact. */
    fun isDownloading(contactId: Long): Boolean = getState(contactId) == State.DOWNLOADING

    /**
     * A download attempt has ACTUALLY BEGUN (network I/O starting).
     * Not when a ping is queued or claimed — when bytes start flowing.
     */
    fun onDownloadStarted(contactId: Long) {
        val counter = activeDownloads.getOrPut(contactId) { AtomicInteger(0) }
        val newCount = counter.incrementAndGet()
        if (newCount == 1) {
            // 0→1 transition: record session start time for staleness tracking
            downloadStartedAt[contactId] = System.currentTimeMillis()
        }
        overrides.remove(contactId) // Clear BACKOFF/PAUSED — we're actively downloading
        Log.d(TAG, "DOWNLOADING: contact=$contactId (active=$newCount)")
    }

    /**
     * A download completed successfully.
     * Decrements counter; transitions to IDLE when counter hits 0.
     * No-op if contact is PAUSED (late event from a cancelled download).
     */
    fun onDownloadCompleted(contactId: Long) {
        if (overrides[contactId] == State.PAUSED) return // Don't override explicit PAUSED
        val counter = activeDownloads[contactId]
        if (counter != null) {
            val remaining = counter.decrementAndGet()
            if (remaining <= 0) {
                activeDownloads.remove(contactId)
                downloadStartedAt.remove(contactId)
                overrides.remove(contactId) // → IDLE
            }
            Log.d(TAG, "COMPLETED: contact=$contactId (remaining=$remaining → ${getState(contactId)})")
        } else {
            Log.d(TAG, "COMPLETED: contact=$contactId (no active counter — already IDLE)")
        }
    }

    /**
     * A download failed (retryable).
     * Typing goes away IMMEDIATELY; background retry pipeline takes over invisibly.
     * No-op if contact is PAUSED (don't downgrade to BACKOFF).
     */
    fun onDownloadFailed(contactId: Long) {
        if (overrides[contactId] == State.PAUSED) return // Don't override explicit PAUSED
        val counter = activeDownloads[contactId]
        if (counter != null) {
            val remaining = counter.decrementAndGet()
            if (remaining <= 0) {
                activeDownloads.remove(contactId)
                downloadStartedAt.remove(contactId)
                overrides[contactId] = State.BACKOFF
            }
            Log.d(TAG, "FAILED: contact=$contactId (remaining=$remaining → ${getState(contactId)})")
        } else {
            overrides[contactId] = State.BACKOFF
            Log.d(TAG, "FAILED: contact=$contactId (no active counter → BACKOFF)")
        }
    }

    /**
     * Background delivery is stopped for this contact.
     * Only in this state should a lock icon appear.
     * Call when: device protection ON, no network, workers killed, user paused.
     */
    fun onPaused(contactId: Long) {
        overrides[contactId] = State.PAUSED
        Log.d(TAG, "PAUSED: contact=$contactId")
    }

    /**
     * Resume after pause. Transitions to IDLE (ready for next download trigger).
     */
    fun onResumed(contactId: Long) {
        if (overrides[contactId] == State.PAUSED) {
            overrides.remove(contactId)
            Log.d(TAG, "RESUMED: contact=$contactId → IDLE")
        }
    }

    /** Clear all state (e.g., on logout or process restart). */
    fun reset() {
        activeDownloads.clear()
        downloadStartedAt.clear()
        overrides.clear()
        Log.d(TAG, "RESET: all state cleared")
    }
}
