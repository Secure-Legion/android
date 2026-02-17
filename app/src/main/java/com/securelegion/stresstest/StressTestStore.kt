package com.securelegion.stresstest

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * In-memory event and metrics aggregator for stress tests
 * Thread-safe for concurrent event collection during stress runs
 */
class StressTestStore {

    // Event storage (thread-safe queue)
    private val events = ConcurrentLinkedQueue<StressEvent>()

    // Real-time counters
    val sentCount = AtomicInteger(0)
    val deliveredCount = AtomicInteger(0)
    val failedCount = AtomicInteger(0)
    val inFlightCount = AtomicInteger(0)

    /**
     * Add event to store
     */
    fun addEvent(event: StressEvent) {
        events.add(event)

        // Update counters based on event type
        when (event) {
            is StressEvent.MessageAttempt -> {
                sentCount.incrementAndGet()
                inFlightCount.incrementAndGet()
            }
            is StressEvent.Phase -> {
                when (event.phase) {
                    "DELIVERED", "MESSAGE_SENT" -> {
                        if (event.ok) {
                            deliveredCount.incrementAndGet()
                            inFlightCount.decrementAndGet()
                        }
                    }
                    "FAILED" -> {
                        if (!event.ok) {
                            failedCount.incrementAndGet()
                            inFlightCount.decrementAndGet()
                        }
                    }
                }
            }
            else -> { /* no counter updates for other events */ }
        }
    }

    /**
     * Get all events (snapshot)
     */
    fun getEvents(): List<StressEvent> = events.toList()

    /**
     * Get events since a timestamp
     */
    fun getEventsSince(timestampMs: Long): List<StressEvent> {
        return events.filter { it.timestampMs >= timestampMs }
    }

    /**
     * Get events for a specific correlation ID
     */
    fun getEventsForCorrelation(correlationId: String): List<StressEvent> {
        return events.filter { event ->
            when (event) {
                is StressEvent.MessageAttempt -> event.correlationId == correlationId
                is StressEvent.Phase -> event.correlationId == correlationId
                else -> false
            }
        }
    }

    /**
     * Clear all events and reset counters
     */
    fun clear() {
        events.clear()
        sentCount.set(0)
        deliveredCount.set(0)
        failedCount.set(0)
        inFlightCount.set(0)
    }

    /**
     * Get summary statistics
     */
    fun getSummary(): Summary {
        return Summary(
            totalSent = sentCount.get(),
            totalDelivered = deliveredCount.get(),
            totalFailed = failedCount.get(),
            inFlight = inFlightCount.get(),
            eventCount = events.size
        )
    }

    /**
     * Export events as JSON Lines format
     */
    fun exportJsonLines(): String {
        return events.joinToString("\n") { event ->
            when (event) {
                is StressEvent.RunStarted ->
                    """{"type":"RUN_STARTED","runId":"${event.runId.id}","ts":${event.timestampMs}}"""
                is StressEvent.MessageAttempt ->
                    """{"type":"MESSAGE_ATTEMPT","cid":"${event.correlationId}","msgId":${event.localMessageId},"contactId":${event.contactId},"size":${event.size},"ts":${event.timestampMs}}"""
                is StressEvent.Phase ->
                    """{"type":"PHASE","cid":"${event.correlationId}","phase":"${event.phase}","ok":${event.ok},"detail":"${event.detail ?: ""}","ts":${event.timestampMs}}"""
                is StressEvent.Progress ->
                    """{"type":"PROGRESS","sent":${event.sent},"delivered":${event.delivered},"failed":${event.failed},"ts":${event.timestampMs}}"""
                is StressEvent.RunFinished ->
                    """{"type":"RUN_FINISHED","runId":"${event.runId.id}","durationMs":${event.durationMs},"ts":${event.timestampMs}}"""
            }
        }
    }

    data class Summary(
        val totalSent: Int,
        val totalDelivered: Int,
        val totalFailed: Int,
        val inFlight: Int,
        val eventCount: Int
    )
}

/**
 * Stress test run identifier
 */
data class StressRunId(val id: String) {
    companion object {
        fun generate(scenario: Scenario): StressRunId {
            val timestamp = System.currentTimeMillis()
            return StressRunId("${scenario.name.lowercase()}_$timestamp")
        }
    }
}

/**
 * Stress test scenarios
 */
enum class Scenario {
    BURST, // Send N messages as fast as possible
    CASCADE, // Test session leak fix (force first to fail, verify second works)
    CONCURRENT_CONTACTS, // Round-robin sends to multiple contacts
    RETRY_STORM, // Resend all failed messages
    MIXED // Mixed message types (TEXT small, TEXT large, VOICE, IMAGE)
}

/**
 * Stress test events (sealed class for type safety)
 */
sealed class StressEvent(val timestampMs: Long = System.currentTimeMillis()) {
    data class RunStarted(val runId: StressRunId) : StressEvent()

    data class MessageAttempt(
        val correlationId: String,
        val localMessageId: Long,
        val contactId: Long,
        val size: Int
    ) : StressEvent()

    data class Phase(
        val correlationId: String,
        val phase: String, // "PING_SENT", "PONG_RECEIVED", "MESSAGE_SENT", "DELIVERED", "FAILED"
        val ok: Boolean,
        val detail: String? = null
    ) : StressEvent()

    data class Progress(
        val sent: Int,
        val delivered: Int,
        val failed: Int
    ) : StressEvent()

    data class RunFinished(
        val runId: StressRunId,
        val durationMs: Long
    ) : StressEvent()
}

/**
 * Stress test configuration
 */
data class StressTestConfig(
    val scenario: Scenario,
    val messageCount: Int,
    val delayMs: Long = 0,
    val messageSize: Int = 256, // bytes
    val contactId: Long,
    val includeMixedTypes: Boolean = false
)
