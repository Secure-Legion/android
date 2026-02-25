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
                Scenario.RAPID_FIRE -> executeRapidFire(runId, config)
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
     * RAPID_FIRE: Send messages at human typing speed
     * Uses configurable delay (default 200ms) between sequential sends
     * Simulates someone smashing the send button as fast as they can
     */
    private suspend fun executeRapidFire(runId: StressRunId, config: StressTestConfig) {
        val messageService = MessageService(context)
        val keyManager = KeyManager.getInstance(context)
        val database = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())

        val contact = database.contactDao().getContactById(config.contactId)
            ?: throw IllegalArgumentException("Contact not found: ${config.contactId}")

        val delayBetween = if (config.delayMs > 0) config.delayMs else 200L

        Log.i(TAG, "Starting rapid-fire: ${config.messageCount} msgs to ${contact.displayName}, ${delayBetween}ms between sends")

        val counter = AtomicInteger(0)

        for (i in 1..config.messageCount) {
            val count = counter.incrementAndGet()
            val correlationId = "stress_${runId.id}_$count"
            val testMessage = generateTestMessage(config.messageSize, correlationId)

            store.addEvent(StressEvent.MessageAttempt(
                correlationId = correlationId,
                localMessageId = 0,
                contactId = config.contactId,
                size = testMessage.length
            ))

            try {
                val result = messageService.sendMessage(
                    contactId = config.contactId,
                    plaintext = testMessage,
                    correlationId = correlationId
                )

                if (result.isSuccess) {
                    val message = result.getOrNull()
                    Log.d(TAG, "[$correlationId] Enqueued (id=${message?.id})")
                    if (message != null) {
                        // Monitor in background — don't block the next send
                        CoroutineScope(Dispatchers.IO).launch {
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

            // Wait before next send (human typing speed)
            delay(delayBetween)
        }

        Log.i(TAG, "Rapid-fire complete: ${config.messageCount} messages sent at ${delayBetween}ms intervals")
    }

    /**
     * CASCADE: Sequential sends - each message waits for terminal state before next
     * Tests session cleanup and handoff between consecutive messages
     */
    private suspend fun executeCascade(runId: StressRunId, config: StressTestConfig) {
        val messageService = MessageService(context)
        val keyManager = KeyManager.getInstance(context)
        val database = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())

        val contact = database.contactDao().getContactById(config.contactId)
            ?: throw IllegalArgumentException("Contact not found: ${config.contactId}")

        Log.i(TAG, "Starting cascade: ${config.messageCount} sequential messages to ${contact.displayName}")

        val counter = AtomicInteger(0)
        val timeout = 30_000L // 30s per message

        for (i in 1..config.messageCount) {
            val count = counter.incrementAndGet()
            val correlationId = "stress_${runId.id}_$count"
            val testMessage = generateTestMessage(config.messageSize, correlationId)

            store.addEvent(StressEvent.MessageAttempt(
                correlationId = correlationId,
                localMessageId = 0,
                contactId = config.contactId,
                size = testMessage.length
            ))

            try {
                val result = messageService.sendMessage(
                    contactId = config.contactId,
                    plaintext = testMessage,
                    correlationId = correlationId
                )

                if (result.isSuccess) {
                    val message = result.getOrNull()
                    Log.d(TAG, "[$correlationId] Enqueued (id=${message?.id}), waiting for terminal state...")

                    // BLOCK until this message reaches terminal state
                    if (message != null) {
                        val startWait = System.currentTimeMillis()
                        var terminal = false
                        while (System.currentTimeMillis() - startWait < timeout) {
                            val current = database.messageDao().getMessageById(message.id)
                            if (current != null) {
                                when (current.status) {
                                    Message.STATUS_DELIVERED, Message.STATUS_SENT -> {
                                        store.addEvent(StressEvent.Phase(
                                            correlationId = correlationId,
                                            phase = if (current.status == Message.STATUS_DELIVERED) "DELIVERED" else "MESSAGE_SENT",
                                            ok = true
                                        ))
                                        terminal = true
                                        break
                                    }
                                    Message.STATUS_FAILED -> {
                                        store.addEvent(StressEvent.Phase(
                                            correlationId = correlationId,
                                            phase = "FAILED",
                                            ok = false,
                                            detail = current.lastError
                                        ))
                                        terminal = true
                                        break
                                    }
                                }
                            }
                            delay(300)
                        }
                        if (!terminal) {
                            store.addEvent(StressEvent.Phase(
                                correlationId = correlationId,
                                phase = "TIMEOUT",
                                ok = false,
                                detail = "No terminal state after ${timeout}ms"
                            ))
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

            Log.i(TAG, "Cascade [$i/${config.messageCount}] complete")
        }

        Log.i(TAG, "Cascade complete: ${config.messageCount} messages processed sequentially")
    }

    /**
     * CONCURRENT_CONTACTS: Round-robin sends across ALL contacts
     * Tests cross-contact session contamination
     */
    private suspend fun executeConcurrentContacts(runId: StressRunId, config: StressTestConfig) {
        val messageService = MessageService(context)
        val keyManager = KeyManager.getInstance(context)
        val database = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())

        // Get all contacts for round-robin
        val allContacts = database.contactDao().getAllContacts()
        if (allContacts.isEmpty()) {
            Log.e(TAG, "No contacts available for concurrent test")
            return
        }

        Log.i(TAG, "Starting concurrent contacts: ${config.messageCount} msgs across ${allContacts.size} contacts")

        val counter = AtomicInteger(0)
        val delayBetween = if (config.delayMs > 0) config.delayMs else 100L

        // Round-robin messages across all contacts
        val jobs = (1..config.messageCount).map { i ->
            coroutineScope {
                launch {
                    val contactIndex = (i - 1) % allContacts.size
                    val contact = allContacts[contactIndex]
                    val count = counter.incrementAndGet()
                    val correlationId = "stress_${runId.id}_${contact.id}_$count"
                    val testMessage = generateTestMessage(config.messageSize, correlationId)

                    store.addEvent(StressEvent.MessageAttempt(
                        correlationId = correlationId,
                        localMessageId = 0,
                        contactId = contact.id,
                        size = testMessage.length
                    ))

                    try {
                        val result = messageService.sendMessage(
                            contactId = contact.id,
                            plaintext = testMessage,
                            correlationId = correlationId
                        )

                        if (result.isSuccess) {
                            val message = result.getOrNull()
                            Log.d(TAG, "[$correlationId] → ${contact.displayName} enqueued (id=${message?.id})")
                            if (message != null) {
                                launch { monitorMessageStatus(database, message.id, correlationId) }
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
                        Log.e(TAG, "[$correlationId] Send to ${contact.displayName} failed", e)
                        store.addEvent(StressEvent.Phase(
                            correlationId = correlationId,
                            phase = "FAILED",
                            ok = false,
                            detail = e.message
                        ))
                    }

                    if (delayBetween > 0) delay(delayBetween)
                }
            }
        }

        jobs.joinAll()
        Log.i(TAG, "Concurrent contacts complete: ${config.messageCount} messages across ${allContacts.size} contacts")
    }

    /**
     * RETRY_STORM: Find all failed/pending messages in DB and retry them concurrently
     * Tests retry infrastructure under load
     */
    private suspend fun executeRetryStorm(runId: StressRunId, config: StressTestConfig) {
        val messageService = MessageService(context)
        val keyManager = KeyManager.getInstance(context)
        val database = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())

        // Get all pending/failed messages
        val pendingMessages = database.messageDao().getPendingMessages()

        if (pendingMessages.isEmpty()) {
            Log.i(TAG, "RETRY_STORM: No failed/pending messages to retry")
            store.addEvent(StressEvent.Phase(
                correlationId = "retry_storm_${runId.id}",
                phase = "NO_MESSAGES",
                ok = true,
                detail = "No failed/pending messages found"
            ))
            return
        }

        Log.i(TAG, "Starting retry storm: ${pendingMessages.size} messages to retry")

        val counter = AtomicInteger(0)

        // Retry all failed messages concurrently
        val jobs = pendingMessages.map { message ->
            coroutineScope {
                launch {
                    val count = counter.incrementAndGet()
                    val correlationId = "retry_${runId.id}_${message.id}_$count"

                    store.addEvent(StressEvent.MessageAttempt(
                        correlationId = correlationId,
                        localMessageId = message.id,
                        contactId = message.contactId,
                        size = 0
                    ))

                    try {
                        val result = messageService.retryMessageNow(message.id)

                        if (result.isSuccess) {
                            Log.d(TAG, "[$correlationId] Retry queued for msg ${message.id}")
                            // Monitor the retried message
                            launch { monitorMessageStatus(database, message.id, correlationId) }
                        } else {
                            store.addEvent(StressEvent.Phase(
                                correlationId = correlationId,
                                phase = "RETRY_FAILED",
                                ok = false,
                                detail = result.exceptionOrNull()?.message
                            ))
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "[$correlationId] Retry failed", e)
                        store.addEvent(StressEvent.Phase(
                            correlationId = correlationId,
                            phase = "RETRY_FAILED",
                            ok = false,
                            detail = e.message
                        ))
                    }
                }
            }
        }

        jobs.joinAll()
        Log.i(TAG, "Retry storm complete: ${pendingMessages.size} messages retried")
    }

    /**
     * MIXED: Send messages with varying payload sizes
     * Tests payload handling from tiny (32B) to large (16KB)
     */
    private suspend fun executeMixed(runId: StressRunId, config: StressTestConfig) {
        val messageService = MessageService(context)
        val keyManager = KeyManager.getInstance(context)
        val database = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())

        val contact = database.contactDao().getContactById(config.contactId)
            ?: throw IllegalArgumentException("Contact not found: ${config.contactId}")

        // Payload size tiers
        val sizes = listOf(32, 128, 256, 1024, 4096, 16384)

        Log.i(TAG, "Starting mixed: ${config.messageCount} msgs to ${contact.displayName}, sizes=${sizes}")

        val counter = AtomicInteger(0)
        val delayBetween = if (config.delayMs > 0) config.delayMs else 300L

        for (i in 1..config.messageCount) {
            val size = sizes[(i - 1) % sizes.size]
            val count = counter.incrementAndGet()
            val correlationId = "stress_${runId.id}_${size}B_$count"
            val testMessage = generateTestMessage(size, correlationId)

            store.addEvent(StressEvent.MessageAttempt(
                correlationId = correlationId,
                localMessageId = 0,
                contactId = config.contactId,
                size = testMessage.length
            ))

            try {
                val result = messageService.sendMessage(
                    contactId = config.contactId,
                    plaintext = testMessage,
                    correlationId = correlationId
                )

                if (result.isSuccess) {
                    val message = result.getOrNull()
                    Log.d(TAG, "[$correlationId] ${size}B enqueued (id=${message?.id})")
                    if (message != null) {
                        CoroutineScope(Dispatchers.IO).launch {
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

            delay(delayBetween)
        }

        Log.i(TAG, "Mixed complete: ${config.messageCount} messages with varying sizes")
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
