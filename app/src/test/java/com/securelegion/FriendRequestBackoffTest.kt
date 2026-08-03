package com.securelegion.workers

import org.junit.Assert.assertEquals
import org.junit.Test

class FriendRequestBackoffTest {
    @Test
    fun baseDelay_usesDocumentedScheduleAndCapsAtOneHour() {
        val expected = longArrayOf(
            60_000L,
            120_000L,
            300_000L,
            900_000L,
            1_800_000L,
            3_600_000L,
            3_600_000L
        )

        expected.forEachIndexed { index, delay ->
            assertEquals(delay, FriendRequestBackoff.baseDelayMs(index + 1))
        }
    }

    @Test
    fun jitter_isBoundedAndNeverExceedsCap() {
        assertEquals(48_000L, FriendRequestBackoff.delayMs(1, 0.8))
        assertEquals(72_000L, FriendRequestBackoff.delayMs(1, 1.2))
        assertEquals(FriendRequestBackoff.MAX_DELAY_MS, FriendRequestBackoff.delayMs(6, 1.2))
        assertEquals(48_000L, FriendRequestBackoff.delayMs(1, -10.0))
        assertEquals(72_000L, FriendRequestBackoff.delayMs(1, 10.0))
    }
}
