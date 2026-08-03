package com.securelegion.workers

import kotlin.random.Random

/** Persisted friend-request retry cadence. WorkManager never owns transport backoff. */
internal object FriendRequestBackoff {
    const val MAX_DELAY_MS = 60L * 60L * 1000L
    private val scheduleMs = longArrayOf(
        60_000L,
        2L * 60L * 1000L,
        5L * 60L * 1000L,
        15L * 60L * 1000L,
        30L * 60L * 1000L,
        MAX_DELAY_MS
    )

    fun baseDelayMs(attemptCount: Int): Long =
        scheduleMs[(attemptCount.coerceAtLeast(1) - 1).coerceAtMost(scheduleMs.lastIndex)]

    fun delayMs(attemptCount: Int, jitterMultiplier: Double = Random.nextDouble(0.8, 1.2)): Long =
        (baseDelayMs(attemptCount) * jitterMultiplier.coerceIn(0.8, 1.2))
            .toLong()
            .coerceAtMost(MAX_DELAY_MS)

    fun nextRetryAt(nowMs: Long, attemptCount: Int): Long =
        nowMs + delayMs(attemptCount)
}
