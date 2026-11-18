package com.securelegion.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope

class DeviceSyncControlQueueTest {
    private val peer = "P".repeat(43)

    @Test fun distinctReplyStartsWhileEarlierSocketWriteIsPending() = runBlocking {
        val firstStarted = CountDownLatch(1)
        val secondStarted = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val sends = AtomicInteger()
        val job = SupervisorJob()
        val queue = DeviceSyncControlQueue(CoroutineScope(job + Dispatchers.IO),
            ByteArray(32), "L".repeat(43), { true }, { _, wire ->
                sends.incrementAndGet()
                if (wire.last() == 1.toByte()) {
                    firstStarted.countDown()
                    releaseFirst.await(5, TimeUnit.SECONDS)
                } else secondStarted.countDown()
                true
            })
        try {
            val first = packet(1)
            val second = packet(2)
            assertTrue(queue.enqueue(peer, listOf(first)))
            assertTrue(firstStarted.await(5, TimeUnit.SECONDS))
            assertTrue(queue.enqueue(peer, listOf(first.copyOf())))
            assertTrue(queue.enqueue(peer, listOf(second)))
            assertTrue(secondStarted.await(5, TimeUnit.SECONDS))
            assertEquals(2, sends.get())
            assertFalse(queue.enqueue(peer, listOf(ByteArray(8193))))
            assertFalse(queue.enqueue(peer, List(3) { packet(it) }))
        } finally {
            releaseFirst.countDown()
            job.cancelAndJoin()
        }
    }

    private fun packet(step: Int): ByteArray = byteArrayOf(0xB6.toByte(), 0, 0, 0, 1,
        step.toByte())
}
