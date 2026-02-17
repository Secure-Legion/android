package com.securelegion.models

import android.util.Log
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Out-of-Order Message Buffer with Gap Timeout
 *
 * CRITICAL: Prevents unbounded memory growth and conversation hangs
 * when messages arrive out of sequence.
 *
 * Problem: Messages arrive as: 1, 2, 3, [MISSING], 5, 6, 7
 * Without timeout: Messages 5-7 are buffered forever waiting for 4
 * App hangs indefinitely, memory leaks, sender doesn't know why ACKs stopped
 *
 * Solution: Gap Timeout
 * - Buffer out-of-order messages with timestamp
 * - Check age on each new message
 * - If buffered message exceeds timeout (e.g., 30s), assume message 4 is lost forever
 * - Either:
 * A. Request resend of the gap (preferred)
 * B. Skip the gap and advance (acceptable if protocol allows)
 *
 * THREAD SAFETY: Uses CopyOnWriteArrayList for thread-safe access
 * OutOfOrderBuffer instances are accessed from MessageService (receive path) and gap timeout checks
 */
class OutOfOrderBuffer(
    private val gapTimeoutSeconds: Long = 30L
) {
    /**
     * Represents a buffered message waiting for a gap to fill
     */
    data class BufferedMessage(
        val sequenceNum: Long,
        val encryptedData: String,
        val senderPublicKey: ByteArray,
        val senderOnionAddress: String,
        val messageType: String,
        val voiceDuration: Int?,
        val selfDestructAt: Long?,
        val requiresReadReceipt: Boolean,
        val pingId: String?,
        val timestamp: Long,
        val bufferedAt: Instant = Instant.now()
    )

    // THREAD SAFE: CopyOnWriteArrayList for read-heavy workload (many checks, few adds)
    // Buffer holds out-of-order messages waiting for gaps to fill
    private val buffer = CopyOnWriteArrayList<BufferedMessage>()

    // Expected sequence number (volatile since accessed from multiple threads)
    @Volatile
    private var expectedSequence = 0L

    // Last time we checked for gap timeout
    @Volatile
    private var lastGapCheck = Instant.now()

    companion object {
        private const val TAG = "OutOfOrderBuffer"
    }

    /**
     * Add an out-of-order message to buffer
     * Returns list of messages that can now be processed (if gap filled)
     *
     * @param seqNum The sequence number of the message
     * @param message The buffered message to add
     * @return List of messages that can now be processed in order
     */
    fun addMessage(seqNum: Long, message: BufferedMessage): List<BufferedMessage> {
        buffer.add(message)
        Log.d(TAG, "Buffered message seq=$seqNum, buffer size now: ${buffer.size}, expecting: $expectedSequence")

        // Check for timeout on existing buffered messages
        checkForGapTimeout()

        // Try to process any messages that can now be delivered
        return tryProcessBuffer(expectedSequence)
    }

    /**
     * Set the expected next sequence number
     * Call when a gap-resolving message arrives
     *
     * @param nextExpected The next sequence number we expect
     */
    fun setExpectedSequence(nextExpected: Long) {
        expectedSequence = nextExpected
        Log.d(TAG, "Expected sequence updated to: $nextExpected")
    }

    /**
     * Try to process buffered messages starting from expectedSequence
     * Removes processed messages from buffer and returns them
     *
     * @param nextExpectedSeq The next sequence we're expecting
     * @return List of messages that are now in sequence
     */
    fun tryProcessBuffer(nextExpectedSeq: Long): List<BufferedMessage> {
        val processable = mutableListOf<BufferedMessage>()

        // Sort buffer by sequence to process in order
        buffer.sortBy { it.sequenceNum }

        // Process all messages that fill the gap
        while (buffer.isNotEmpty() && buffer.first().sequenceNum == nextExpectedSeq) {
            val buffered = buffer.removeAt(0)
            processable.add(buffered)
            // Don't update expectedSequence here - caller should do it after successful processing
        }

        if (processable.isNotEmpty()) {
            Log.d(TAG, "Processed ${processable.size} buffered messages from gap, buffer now: ${buffer.size}")
        }

        return processable
    }

    /**
     * Check if any buffered messages have exceeded the gap timeout
     * If so, either request resend or skip ahead
     *
     * Returns list of sequence numbers that are confirmed lost (gaps)
     */
    fun checkForGapTimeout(): List<LongRange> {
        val now = Instant.now()
        val timeout = Duration.ofSeconds(gapTimeoutSeconds)
        val lostRanges = mutableListOf<LongRange>()

        // Check each buffered message
        for (buffered in buffer) {
            val age = Duration.between(buffered.bufferedAt, now)

            if (age > timeout) {
                // Gap timeout detected!
                val gapStart = expectedSequence
                val gapEnd = buffered.sequenceNum - 1

                Log.w(TAG, "GAP TIMEOUT: Missing seq $gapStart..$gapEnd (${gapEnd - gapStart + 1} messages)")
                Log.w(TAG, "Oldest buffered message age: ${age.seconds}s, timeout: ${timeout.seconds}s")

                // Mark this range as lost
                if (gapStart <= gapEnd) {
                    lostRanges.add(gapStart..gapEnd)
                }

                // Strategy A: Skip ahead (acceptable if protocol allows lost messages)
                // This unblocks the conversation and allows it to continue
                skipToSequence(buffered.sequenceNum)

                break // Only handle first timeout per check
            }
        }

        return lostRanges
    }

    /**
     * Skip ahead to a specific sequence number
     * This happens when gap timeout is triggered
     *
     * @param nextSeq The sequence number to skip to
     */
    fun skipToSequence(nextSeq: Long) {
        Log.w(TAG, "Skipping gap: advancing from seq=$expectedSequence to seq=$nextSeq")

        // Remove all buffered messages before nextSeq
        val beforeGap = buffer.takeWhile { it.sequenceNum < nextSeq }
        buffer.removeAll(beforeGap)

        // Remove messages at nextSeq for reprocessing
        if (buffer.isNotEmpty() && buffer.first().sequenceNum == nextSeq) {
            // Keep this message - it will be processed next
        }

        expectedSequence = nextSeq
        Log.w(TAG, "Skipped gap, buffer now has ${buffer.size} messages")
    }

    /**
     * Get current buffer size
     */
    fun size(): Int = buffer.size

    /**
     * Clear buffer (e.g., when thread is deleted)
     */
    fun clear() {
        buffer.clear()
        expectedSequence = 0L
        Log.d(TAG, "Buffer cleared")
    }

    /**
     * Debug: Print buffer state
     */
    fun dumpState() {
        Log.d(TAG, "====== OutOfOrderBuffer State ======")
        Log.d(TAG, "Expected sequence: $expectedSequence")
        Log.d(TAG, "Buffer size: ${buffer.size}")
        val sorted = buffer.sortedBy { it.sequenceNum }
        for (msg in sorted) {
            val age = Duration.between(msg.bufferedAt, Instant.now())
            Log.d(TAG, "seq=${msg.sequenceNum}, age=${age.seconds}s, from=${msg.senderOnionAddress.take(16)}...")
        }
        Log.d(TAG, "=====================================")
    }
}
