package com.securelegion.voice

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.CallQualityLog
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Call Quality Telemetry - Real-time metrics for voice call quality monitoring
 *
 * Tracks and reports metrics every 5 seconds:
 * - Late frame % (overall + per-circuit)
 * - PLC % (packet loss concealment usage)
 * - FEC recovery success %
 * - Out-of-order frame %
 * - Jitter buffer size (ms)
 * - Scheduler circuit distribution (actual vs target 70/20/10)
 * - Circuit cooldown events
 * - Audio underruns
 *
 * Usage:
 * val telemetry = CallQualityTelemetry()
 * telemetry.start(coroutineScope)
 * telemetry.reportLateFrame(circuitIndex)
 * telemetry.reportFECAttempt(success = true)
 * // ... telemetry.getSnapshot() for UI display
 */
class CallQualityTelemetry {
    companion object {
        private const val TAG = "CallQualityTelemetry"
        private const val REPORT_INTERVAL_MS = 5000L // 5 seconds

        // === Last Call Summary (singleton storage for UI) ===
        @Volatile
        private var lastCallSummary: TelemetrySnapshot? = null

        /**
         * Get the last call's final telemetry summary
         * Used by Settings > Log to display post-call metrics
         */
        fun getLastCallSummary(): TelemetrySnapshot? = lastCallSummary

        /**
         * Clear the last call summary
         */
        fun clearLastCallSummary() {
            lastCallSummary = null
        }
    }

    // === Overall Metrics ===
    private val totalFrames = AtomicLong(0)
    private val lateFrames = AtomicLong(0)
    private val plcFrames = AtomicLong(0)
    private val fecAttempts = AtomicLong(0)
    private val fecSuccesses = AtomicLong(0)
    private val outOfOrderFrames = AtomicLong(0)
    private val underruns = AtomicLong(0)

    // === Per-Circuit Metrics ===
    private data class CircuitMetrics(
        val framesReceived: AtomicLong = AtomicLong(0), // Frames WE received on this circuit (incoming)
        val lateFrames: AtomicLong = AtomicLong(0),
        val framesSent: AtomicLong = AtomicLong(0), // Frames WE sent on this circuit (outgoing)
        val cooldownEvents: AtomicInteger = AtomicInteger(0),
        // FIX #4: Add missing% and PLC% tracking per circuit
        val plcFrames: AtomicLong = AtomicLong(0), // PLC used on this circuit
        var lastReceivedSeq: Long = -1, // Last sequence seen (for burst detection)
        var burstLossEvents: AtomicInteger = AtomicInteger(0), // Consecutive loss events
        val peerFramesReceived: AtomicLong = AtomicLong(0) // Frames PEER received (from their feedback) - CRITICAL FIX!
    )

    private val circuitMetrics = mutableMapOf<Int, CircuitMetrics>()

    // === Jitter Buffer ===
    @Volatile
    private var currentJitterBufferMs: Int = 0

    // === Last Sequence (for out-of-order detection) ===
    @Volatile
    private var lastReceivedSeq: Long = -1

    // === CPU Usage Tracking ===
    private var lastCpuTime: Long = 0
    private var lastWallTime: Long = 0

    // === Telemetry Job ===
    private var telemetryJob: Job? = null

    /**
     * Start periodic telemetry reporting
     */
    fun start(scope: CoroutineScope) {
        telemetryJob = scope.launch {
            while (isActive) {
                delay(REPORT_INTERVAL_MS)
                logTelemetry()
            }
        }
        Log.i(TAG, "Call quality telemetry started (${REPORT_INTERVAL_MS}ms interval)")
    }

    /**
     * Stop telemetry reporting and save final summary
     */
    fun stop() {
        telemetryJob?.cancel()
        telemetryJob = null

        // Save final snapshot for post-call viewing
        lastCallSummary = getSnapshot()

        Log.i(TAG, "Call quality telemetry stopped")
        Log.i(TAG, "Final call quality: ${getQualityScore()} bars")
    }

    /**
     * Save telemetry to database for debugging/analysis
     * @param context Application context
     * @param callId Voice call ID
     * @param contactName Contact name
     * @param durationSeconds Call duration in seconds
     */
    suspend fun saveToDatabase(
        context: Context,
        callId: String,
        contactName: String,
        durationSeconds: Int
    ) = withContext(Dispatchers.IO) {
        try {
            val snapshot = getSnapshot()

            // Convert per-circuit stats to JSON (v3 - with missing% and PLC%)
            val circuitStatsJson = JSONArray()
            snapshot.perCircuitStats.forEach { circuit ->
                val json = JSONObject()
                json.put("circuitIndex", circuit.circuitIndex)
                json.put("latePercent", circuit.latePercent)
                json.put("framesSent", circuit.framesSent)
                json.put("framesReceived", circuit.framesReceived)
                json.put("cooldownEvents", circuit.cooldownEvents)
                // FIX #4: Include new metrics in database
                json.put("missingPercent", circuit.missingPercent)
                json.put("plcPercent", circuit.plcPercent)
                json.put("burstLossEvents", circuit.burstLossEvents)
                circuitStatsJson.put(json)
            }

            // Create log entry
            val log = CallQualityLog(
                callId = callId,
                contactName = contactName,
                timestamp = System.currentTimeMillis(),
                durationSeconds = durationSeconds,
                qualityScore = getQualityScore(),
                totalFrames = snapshot.totalFrames,
                latePercent = snapshot.latePercent,
                plcPercent = snapshot.plcPercent,
                fecSuccessPercent = snapshot.fecSuccessPercent,
                outOfOrderPercent = snapshot.outOfOrderPercent,
                jitterBufferMs = snapshot.jitterBufferMs,
                audioUnderruns = snapshot.audioUnderruns,
                circuitStatsJson = circuitStatsJson.toString()
            )

            // Get database and save
            val keyManager = KeyManager.getInstance(context)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val db = SecureLegionDatabase.getInstance(context, dbPassphrase)
            db.callQualityLogDao().insert(log)

            Log.i(TAG, "Saved call quality log to database (ID: $callId, Quality: ${log.qualityScore}/5)")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save call quality log to database", e)
        }
    }

    // === Recording Methods ===

    fun reportFrameReceived(sequenceNumber: Long, circuitIndex: Int) {
        totalFrames.incrementAndGet()
        getCircuitMetrics(circuitIndex).framesReceived.incrementAndGet()

        // Check for out-of-order
        if (lastReceivedSeq >= 0 && sequenceNumber < lastReceivedSeq) {
            outOfOrderFrames.incrementAndGet()
        }
        lastReceivedSeq = maxOf(lastReceivedSeq, sequenceNumber)
    }

    fun reportLateFrame(circuitIndex: Int) {
        lateFrames.incrementAndGet()
        getCircuitMetrics(circuitIndex).lateFrames.incrementAndGet()
    }

    fun reportPLC() {
        plcFrames.incrementAndGet()
    }

    /**
     * FIX #4: Report PLC (Packet Loss Concealment) for a specific circuit
     * This helps identify which circuit is causing quality issues
     */
    fun reportPLCForCircuit(circuitIndex: Int) {
        plcFrames.incrementAndGet()
        getCircuitMetrics(circuitIndex).plcFrames.incrementAndGet()
    }

    /**
     * CRITICAL FIX: Update peer's received count from CONTROL packet feedback
     * This is needed to correctly calculate missing% = (sent - peerReceived) / sent
     */
    fun updatePeerReceivedCount(circuitIndex: Int, peerReceivedCount: Long) {
        getCircuitMetrics(circuitIndex).peerFramesReceived.set(peerReceivedCount)
    }

    fun reportFECAttempt(success: Boolean) {
        fecAttempts.incrementAndGet()
        if (success) {
            fecSuccesses.incrementAndGet()
        }
    }

    fun reportFrameSent(circuitIndex: Int) {
        getCircuitMetrics(circuitIndex).framesSent.incrementAndGet()
    }

    fun reportCircuitCooldown(circuitIndex: Int) {
        getCircuitMetrics(circuitIndex).cooldownEvents.incrementAndGet()
    }

    fun reportAudioUnderrun() {
        underruns.incrementAndGet()
    }

    fun updateJitterBuffer(jitterBufferMs: Int) {
        currentJitterBufferMs = jitterBufferMs
    }

    /**
     * Get or create circuit metrics
     */
    private fun getCircuitMetrics(circuitIndex: Int): CircuitMetrics {
        return circuitMetrics.getOrPut(circuitIndex) { CircuitMetrics() }
    }

    /**
     * Calculate current CPU usage percentage for this app
     *
     * Reads /proc/self/stat to get app CPU time and calculates usage since last call
     * Returns percentage of CPU cores used (e.g., 50% = using half a core)
     */
    private fun calculateCpuUsage(): Double {
        try {
            // Read /proc/self/stat to get app CPU time (utime + stime)
            val stat = java.io.File("/proc/self/stat").readText()
            val parts = stat.split(" ")

            // Fields 14 and 15 are utime and stime (in clock ticks)
            val utime = parts.getOrNull(13)?.toLongOrNull() ?: return 0.0
            val stime = parts.getOrNull(14)?.toLongOrNull() ?: return 0.0
            val totalCpuTime = utime + stime // Total CPU time in clock ticks

            // Get wall time
            val currentWallTime = System.currentTimeMillis()

            // Calculate CPU usage since last measurement
            if (lastCpuTime > 0 && lastWallTime > 0) {
                val cpuTimeDelta = totalCpuTime - lastCpuTime // Clock ticks
                val wallTimeDelta = currentWallTime - lastWallTime // Milliseconds

                if (wallTimeDelta > 0) {
                    // Convert clock ticks to milliseconds (100 ticks per second on Android)
                    val clockTicksPerSecond = 100.0
                    val cpuTimeMs = (cpuTimeDelta * 1000.0) / clockTicksPerSecond

                    // Calculate percentage
                    val cpuPercent = (cpuTimeMs / wallTimeDelta) * 100.0

                    // Update last values
                    lastCpuTime = totalCpuTime
                    lastWallTime = currentWallTime

                    return cpuPercent.coerceIn(0.0, 100.0 * Runtime.getRuntime().availableProcessors())
                }
            }

            // First measurement - initialize
            lastCpuTime = totalCpuTime
            lastWallTime = currentWallTime

            return 0.0
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read CPU usage: ${e.message}")
            return 0.0
        }
    }

    /**
     * Get current telemetry snapshot for UI display
     */
    fun getSnapshot(): TelemetrySnapshot {
        val total = totalFrames.get()
        val late = lateFrames.get()
        val plc = plcFrames.get()
        val fecAttempt = fecAttempts.get()
        val fecSuccess = fecSuccesses.get()
        val outOfOrder = outOfOrderFrames.get()

        // Calculate percentages
        val latePercent = if (total > 0) (late * 100.0 / total) else 0.0
        val plcPercent = if (total > 0) (plc * 100.0 / total) else 0.0
        val fecSuccessPercent = if (fecAttempt > 0) (fecSuccess * 100.0 / fecAttempt) else 0.0
        val outOfOrderPercent = if (total > 0) (outOfOrder * 100.0 / total) else 0.0

        // Per-circuit stats (v3 - with missing% and PLC%)
        val perCircuit = circuitMetrics.map { (idx, metrics) ->
            val received = metrics.framesReceived.get() // Frames WE received (incoming)
            val circuitLate = metrics.lateFrames.get()
            val sent = metrics.framesSent.get() // Frames WE sent (outgoing)
            val cooldowns = metrics.cooldownEvents.get()
            val plc = metrics.plcFrames.get()
            val burstEvents = metrics.burstLossEvents.get()
            val peerReceived = metrics.peerFramesReceived.get() // Frames PEER received (from feedback)

            // CRITICAL FIX: Calculate missing% = (sent - peerReceived) / sent * 100
            // Compare what WE sent vs what PEER received (NOT what we received!)
            val missingPercent = if (sent > 0) {
                ((sent - peerReceived) * 100.0 / sent).coerceAtLeast(0.0)
            } else {
                0.0
            }

            // FIX #4: Calculate PLC% for this circuit
            val plcPercent = if (received > 0) {
                (plc * 100.0 / received)
            } else {
                0.0
            }

            CircuitSnapshot(
                circuitIndex = idx,
                latePercent = if (received > 0) (circuitLate * 100.0 / received) else 0.0,
                framesReceived = received,
                framesSent = sent,
                cooldownEvents = cooldowns,
                missingPercent = missingPercent,
                plcPercent = plcPercent,
                burstLossEvents = burstEvents
            )
        }

        // Calculate actual circuit distribution
        val totalSent = perCircuit.sumOf { it.framesSent }
        val distribution = perCircuit.map { circuit ->
            if (totalSent > 0) {
                (circuit.framesSent * 100.0 / totalSent)
            } else {
                0.0
            }
        }

        return TelemetrySnapshot(
            totalFrames = total,
            latePercent = latePercent,
            plcPercent = plcPercent,
            fecSuccessPercent = fecSuccessPercent,
            outOfOrderPercent = outOfOrderPercent,
            jitterBufferMs = currentJitterBufferMs,
            audioUnderruns = underruns.get(),
            cpuUsagePercent = calculateCpuUsage(),
            perCircuitStats = perCircuit,
            circuitDistribution = distribution
        )
    }

    /**
     * Calculate call quality score (0-5 bars) based on current metrics
     *
     * Quality criteria:
     * - 5 bars (Excellent): Late% < 2%, PLC% < 1%, Jitter < 300ms
     * - 4 bars (Good): Late% < 5%, PLC% < 3%, Jitter < 400ms
     * - 3 bars (Fair): Late% < 10%, PLC% < 5%, Jitter < 500ms
     * - 2 bars (Poor): Late% < 20%, PLC% < 10%, Jitter < 600ms
     * - 1 bar (Bad): Late% < 30%, PLC% < 15%
     * - 0 bars (Terrible): Worse than above
     */
    fun getQualityScore(): Int {
        val snapshot = getSnapshot()

        return when {
            // Excellent (5 bars)
            snapshot.latePercent < 2.0 &&
            snapshot.plcPercent < 1.0 &&
            snapshot.jitterBufferMs < 300 -> 5

            // Good (4 bars)
            snapshot.latePercent < 5.0 &&
            snapshot.plcPercent < 3.0 &&
            snapshot.jitterBufferMs < 400 -> 4

            // Fair (3 bars)
            snapshot.latePercent < 10.0 &&
            snapshot.plcPercent < 5.0 &&
            snapshot.jitterBufferMs < 500 -> 3

            // Poor (2 bars)
            snapshot.latePercent < 20.0 &&
            snapshot.plcPercent < 10.0 &&
            snapshot.jitterBufferMs < 600 -> 2

            // Bad (1 bar)
            snapshot.latePercent < 30.0 &&
            snapshot.plcPercent < 15.0 -> 1

            // Terrible (0 bars)
            else -> 0
        }
    }

    /**
     * Log telemetry to logcat
     */
    private fun logTelemetry() {
        val snapshot = getSnapshot()

        val report = buildString {
            appendLine()
            appendLine("=======================================================")
            appendLine("CALL QUALITY TELEMETRY (5s window)")
            appendLine("=======================================================")
            appendLine()
            appendLine("Overall Metrics:")
            appendLine(" Total Frames: ${snapshot.totalFrames}")
            appendLine(" Late%: ${String.format("%.2f%%", snapshot.latePercent)}")
            appendLine(" PLC%: ${String.format("%.2f%%", snapshot.plcPercent)}")
            appendLine(" FEC Success%: ${String.format("%.2f%%", snapshot.fecSuccessPercent)}")
            appendLine(" Out-of-Order%: ${String.format("%.2f%%", snapshot.outOfOrderPercent)}")
            appendLine(" Jitter Buffer: ${snapshot.jitterBufferMs}ms")
            appendLine(" Audio Underruns: ${snapshot.audioUnderruns}")
            appendLine(" CPU Usage: ${String.format("%.1f%%", snapshot.cpuUsagePercent)} (${Runtime.getRuntime().availableProcessors()} cores)")
            appendLine()
            appendLine("Per-Circuit Stats:")
            snapshot.perCircuitStats.forEachIndexed { idx, circuit ->
                val distribution = if (idx < snapshot.circuitDistribution.size) {
                    snapshot.circuitDistribution[idx]
                } else {
                    0.0
                }
                appendLine(" Circuit ${circuit.circuitIndex}:")
                appendLine(" Late%: ${String.format("%.2f%%", circuit.latePercent)}")
                // FIX #4: Show missing% and PLC% in telemetry logs
                appendLine(" Missing%: ${String.format("%.2f%%", circuit.missingPercent)}")
                appendLine(" PLC%: ${String.format("%.2f%%", circuit.plcPercent)}")
                appendLine(" Distribution: ${String.format("%.1f%%", distribution)} (target: ${getTargetDistribution(idx)}%)")
                appendLine(" Sent/Recv: ${circuit.framesSent}/${circuit.framesReceived}")
                appendLine(" Cooldowns: ${circuit.cooldownEvents}")
                if (circuit.burstLossEvents > 0) {
                    appendLine(" Burst Loss: ${circuit.burstLossEvents} events")
                }
            }
            appendLine()
            appendLine("=======================================================")
        }

        Log.i(TAG, report)
    }

    /**
     * Get target distribution for comparison (70/20/10)
     */
    private fun getTargetDistribution(index: Int): Int {
        return when (index) {
            0 -> 70
            1 -> 20
            2 -> 10
            else -> 0
        }
    }

    /**
     * Reset all metrics (useful for testing)
     */
    fun reset() {
        totalFrames.set(0)
        lateFrames.set(0)
        plcFrames.set(0)
        fecAttempts.set(0)
        fecSuccesses.set(0)
        outOfOrderFrames.set(0)
        underruns.set(0)
        circuitMetrics.clear()
        lastReceivedSeq = -1
        Log.d(TAG, "Telemetry reset")
    }

    /**
     * Immutable snapshot of telemetry data
     */
    data class TelemetrySnapshot(
        val totalFrames: Long,
        val latePercent: Double,
        val plcPercent: Double,
        val fecSuccessPercent: Double,
        val outOfOrderPercent: Double,
        val jitterBufferMs: Int,
        val audioUnderruns: Long,
        val cpuUsagePercent: Double,
        val perCircuitStats: List<CircuitSnapshot>,
        val circuitDistribution: List<Double>
    )

    /**
     * Per-circuit snapshot (v3 - enhanced with missing% and PLC%)
     */
    data class CircuitSnapshot(
        val circuitIndex: Int,
        val latePercent: Double,
        val framesReceived: Long,
        val framesSent: Long,
        val cooldownEvents: Int,
        // FIX #4: New fields for better circuit health monitoring
        val missingPercent: Double, // (sent - received) / sent * 100
        val plcPercent: Double, // PLC frames / received * 100
        val burstLossEvents: Int // Number of burst loss events detected
    )
}
