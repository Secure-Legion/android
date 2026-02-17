package com.securelegion.stresstest

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.services.MessageService
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import java.util.concurrent.atomic.AtomicInteger

/**
 * Stress test engine - runs through REAL MessageService pipeline
 * No simulation - uses actual send paths to diagnose SOCKS timeout and MESSAGE_TX race
 */
class StressTestEngine(
    private val context: Context,
    private val store: StressTestStore
) {
    private val TAG = "StressTestEngine"

    private var currentJob: Job? = null
    private var runScope: CoroutineScope? = null

    /**
     * Start stress test run
     * Returns immediately - run executes in background
     */
    fun start(config: StressTestConfig) {
        // Cancel any existing run
        stop()

        // Create run scope
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        runScope = scope

        // Clear previous run data
        store.clear()

        // Start run
        currentJob = scope.launch {
            executeRun(config)
        }
    }

    /**
     * Stop current run
     */
    fun stop() {
        currentJob?.cancel()
        currentJob = null
        runScope?.cancel()
        runScope = null
    }

    /**
     * Execute stress test run
     */
    private suspend fun executeRun(config: StressTestConfig) {
        val runId = StressRunId.generate(config.scenario)
        val startTime = System.currentTimeMillis()

        store.addEvent(StressEvent.RunStarted(runId))
        Log.i(TAG, "")
        Log.i(TAG, "STRESS TEST RUN STARTED")
        Log.i(TAG, "Run ID: ${runId.id}")
        Log.i(TAG, "Scenario: ${config.scenario}")
        Log.i(TAG, "Message count: ${config.messageCount}")
        Log.i(TAG, "")

        try {
            when (config.scenario) {
                Scenario.BURST -> executeBurst(runId, config)
                Scenario.CASCADE -> executeCascade(runId, config)
                Scenario.CONCURRENT_CONTACTS -> executeConcurrentContacts(runId, config)
                Scenario.RETRY_STORM -> executeRetryStorm(runId, config)
                Scenario.MIXED -> executeMixed(runId, config)
            }

            val duration = System.currentTimeMillis() - startTime
            store.addEvent(StressEvent.RunFinished(runId, duration))

            Log.i(TAG, "")
            Log.i(TAG, "STRESS TEST RUN FINISHED")
            Log.i(TAG, "Duration: ${duration}ms")
            Log.i(TAG, "Summary: ${store.getSummary()}")
            Log.i(TAG, "")

        } catch (e: CancellationException) {
            Log.i(TAG, "Stress test run cancelled")
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Stress test run failed", e)
        }
    }

    /**
     * BURST: Send N messages as fast as possible
     * Diagnoses SOCKS timeout and MESSAGE_TX initialization race
     */
    private suspend fun executeBurst(runId: StressRunId, config: StressTestConfig) {
        val messageService = MessageService(context)
        val keyManager = KeyManager.getInstance(context)
        val database = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())

        val counter = AtomicInteger(0)

        // Get contact info once (don't query in loop)
        val contact = database.contactDao().getContactById(config.contactId)
            ?: throw IllegalArgumentException("Contact not found: ${config.contactId}")

        Log.i(TAG, "Starting burst of ${config.messageCount} messages to ${contact.displayName}")

        // Fire messages concurrently (real burst behavior)
        val jobs = (1..config.messageCount).map { i ->
            coroutineScope {
                launch {
                    val count = counter.incrementAndGet()
                    val correlationId = "stress_${runId.id}_$count"

                    // Generate test payload
                    val testMessage = generateTestMessage(config.messageSize, correlationId)

                    // Record attempt
                    store.addEvent(StressEvent.MessageAttempt(
                        correlationId = correlationId,
                        localMessageId = 0, // Will be set after send
                        contactId = config.contactId,
                        size = testMessage.length
                    ))

                    try {
                        // !! REAL PIPELINE !! - Call actual MessageService.sendMessage
                        val result = messageService.sendMessage(
                            contactId = config.contactId,
                            plaintext = testMessage,
                            correlationId = correlationId // Pass correlation ID for tracing
                        )

                        if (result.isSuccess) {
                            val message = result.getOrNull()
                            Log.d(TAG, "[$correlationId] Enqueued message (id=${message?.id})")

                            // Monitor message status in background
                            if (message != null) {
                                launch {
                                    monitorMessageStatus(database, message.id, correlationId)
                                }
                            }
                        } else {
                            store.addEvent(StressEvent.Phase(
                                correlationId = correlationId,
                                phase = "FAILED",
                                ok = false,
                                detail = result.exceptionOrNull()?.message
                            ))
                        }

                    } catch (e: Exception) {
                        Log.e(TAG, "[$correlationId] Send failed", e)
                        store.addEvent(StressEvent.Phase(
                            correlationId = correlationId,
                            phase = "FAILED",
                            ok = false,
                            detail = e.message
                        ))
                    }

                    // Optional delay between sends
                    if (config.delayMs > 0) {
                        delay(config.delayMs)
                    }
                }
            }
        }

        // Wait for all sends to complete
        jobs.joinAll()

        Log.i(TAG, "Burst complete: ${config.messageCount} messages enqueued")
    }

    /**
     * CASCADE: Test session leak fix
     * Force first message to fail (or succeed), verify second message works
     */
    private suspend fun executeCascade(runId: StressRunId, config: StressTestConfig) {
        // TODO: Implement cascade test (send 2 messages sequentially)
        Log.i(TAG, "CASCADE test not yet implemented")
    }

    /**
     * CONCURRENT_CONTACTS: Round-robin sends to multiple contacts
     * Tests cross-contact contamination
     */
    private suspend fun executeConcurrentContacts(runId: StressRunId, config: StressTestConfig) {
        // TODO: Implement concurrent contacts test
        Log.i(TAG, "CONCURRENT_CONTACTS test not yet implemented")
    }

    /**
     * RETRY_STORM: Resend all failed messages
     * Tests retry infrastructure under load
     */
    private suspend fun executeRetryStorm(runId: StressRunId, config: StressTestConfig) {
        // TODO: Implement retry storm test
        Log.i(TAG, "RETRY_STORM test not yet implemented")
    }

    /**
     * MIXED: Send mixed message types
     * Tests type-byte routing and port selection
     */
    private suspend fun executeMixed(runId: StressRunId, config: StressTestConfig) {
        // TODO: Implement mixed types test
        Log.i(TAG, "MIXED test not yet implemented")
    }

    /**
     * Monitor message status changes and emit events
     */
    private suspend fun monitorMessageStatus(database: SecureLegionDatabase, messageId: Long, correlationId: String) {
        try {
            // Poll message status every 500ms for up to 60 seconds
            var lastStatus = Message.STATUS_PENDING
            val startTime = System.currentTimeMillis()
            val timeout = 60_000L // 60 seconds

            while (System.currentTimeMillis() - startTime < timeout) {
                val message = database.messageDao().getMessageById(messageId)

                if (message != null && message.status != lastStatus) {
                    lastStatus = message.status

                    val (phase, ok) = when (message.status) {
                        Message.STATUS_PING_SENT -> "PING_SENT" to true
                        Message.STATUS_SENT -> "MESSAGE_SENT" to true
                        Message.STATUS_DELIVERED -> "DELIVERED" to true
                        Message.STATUS_FAILED -> "FAILED" to false
                        else -> "UNKNOWN" to true
                    }

                    store.addEvent(StressEvent.Phase(
                        correlationId = correlationId,
                        phase = phase,
                        ok = ok,
                        detail = message.lastError
                    ))

                    // Terminal state reached
                    if (message.status == Message.STATUS_DELIVERED || message.status == Message.STATUS_FAILED) {
                        break
                    }
                }

                delay(500)
            }

            // Timeout reached
            if (lastStatus != Message.STATUS_DELIVERED) {
                store.addEvent(StressEvent.Phase(
                    correlationId = correlationId,
                    phase = "TIMEOUT",
                    ok = false,
                    detail = "No terminal state after ${timeout}ms"
                ))
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to monitor message $messageId", e)
        }
    }

    /**
     * Generate test message payload
     */
    private fun generateTestMessage(size: Int, correlationId: String): String {
        val prefix = "[ST:$correlationId] "
        val padding = "x".repeat(maxOf(0, size - prefix.length))
        return prefix + padding
    }

    /**
     * Get current run status
     */
    fun isRunning(): Boolean = currentJob?.isActive == true
}
