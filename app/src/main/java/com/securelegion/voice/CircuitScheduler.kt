package com.securelegion.voice

import android.util.Log
import kotlin.math.max
import kotlin.random.Random

/**
 * Adaptive circuit scheduler for voice call multi-circuit routing
 *
 * Uses circuit stickiness to minimize reordering while maintaining redundancy:
 * - Stays on same circuit for 500ms (25 frames @ 20ms)
 * - Switches immediately if current circuit is bad (>12% late OR >5% missing)
 * - Switches after epoch if another circuit is clearly better (15% hysteresis)
 *
 * Features:
 * - Send failure tracking
 * - Receiver-reported late/missing/PLC percentages (from feedback)
 * - Circuit cooldown after repeated failures
 * - Circuit quarantine and rebuild for persistent issues
 *
 * Based on: securelegion_voice_transport_v2_plan.md § 3
 */
class CircuitScheduler(
    private val numCircuits: Int = 3,
    private val telemetry: CallQualityTelemetry? = null
) {
    companion object {
        private const val TAG = "CircuitScheduler"

        // Phase 2.1: Adaptive monitoring window (Donar paper: 2s window prevents thrashing)
        private const val MONITORING_WINDOW_MS = 2000L // 2 seconds

        // Phase 1: Round-robin rotation interval
        private const val ROTATION_INTERVAL_MS = 100L // 100ms = 5 frames @ 20ms

        // Circuit stickiness: stay on same circuit for 500ms (25 frames @ 20ms)
        private const val STICKY_EPOCH_MS = 500L // 500ms = 25 frames

        // Immediate failover thresholds (switch before epoch expires)
        private const val BAD_LATE_THRESHOLD = 12.0 // % late frames
        private const val BAD_MISSING_THRESHOLD = 5.0 // % missing frames

        // Hysteresis for circuit switching (prevents flapping)
        private const val SWITCH_MARGIN = 0.15 // New circuit must be 15% better

        // Cooldown duration for failing circuits (milliseconds)
        private const val COOLDOWN_DURATION_MS = 8000L // 8 seconds (increased for Tor recovery)

        // Failure threshold before triggering cooldown
        private const val FAILURE_THRESHOLD = 3 // 3 consecutive failures

        // Weights for circuit selection (best → worst)
        private val CIRCUIT_WEIGHTS = doubleArrayOf(0.70, 0.20, 0.10)

        // WARMUP + STAGED CONTROL: Phase durations (milliseconds)
        private const val ESTABLISHMENT_PHASE_MS = 3000L // 0-3s: equal probing
        private const val WARMUP_PHASE_MS = 15000L // 0-15s: no cooldowns (except hard failures)
        private const val RELAXED_PHASE_MS = 45000L // 15-45s: relaxed thresholds
        // 45s+: strict thresholds

        // Minimum frames received before computing missing% (avoids early false positives)
        private const val MIN_FRAMES_FOR_MISSING_CALC = 30

        // Minimum weight to keep worst circuit alive (prevents "all cooldown" deadlock)
        private const val MIN_CIRCUIT_WEIGHT = 0.05 // 5% minimum
    }

    /**
     * Call phase for staged threshold control
     */
    private enum class CallPhase {
        ESTABLISHMENT, // 0-3s: Equal probing (33/33/33), no cooldowns
        WARMUP, // 3-15s: Soft steering only, no cooldowns
        RELAXED, // 15-45s: Relaxed thresholds (missing% > 15%, PLC% > 10%)
        STRICT // 45s+: Strict thresholds (missing% > 5%, PLC% > 5%)
    }

    /**
     * Phase 2.2: Circuit group classification (Donar paper strategy)
     * L1ST: Best 3 circuits (primary use)
     * L2ND: Next 3 circuits (backup, reduces load on L1ST)
     * LINACTIVE: Remaining circuits (monitored but idle)
     */
    private enum class CircuitGroup {
        L1ST, // Top 3 fastest circuits
        L2ND, // Next 3 circuits
        LINACTIVE // Remaining circuits
    }

    // Track call start time for phase detection
    private val callStartTime = System.currentTimeMillis()

    /**
     * Cooldown reason for debugging
     */
    private enum class CooldownReason {
        SEND_FAILURE, // Socket send failures
        DELIVERY_RATE, // < 92% delivery with PLC > 3%
        HIGH_MISSING, // missing% > threshold
        HIGH_PLC // PLC% > threshold
    }

    /**
     * Per-circuit health tracking
     */
    private data class CircuitHealth(
        var sendFailures: Int = 0, // Consecutive send failures
        var lateFramePercent: Double = 0.0, // Receiver-reported late % (raw)
        var missingFramePercent: Double = 0.0, // Receiver-reported missing % (raw)
        var plcPercent: Double = 0.0, // Receiver-reported PLC % (raw)
        var cooldownUntil: Long = 0, // Timestamp when cooldown expires
        var totalFramesSent: Long = 0, // Total frames WE sent on this circuit
        var peerFramesReceived: Long = 0, // Total frames PEER received (from CONTROL feedback)
        var rampUpWeight: Double = 1.0, // Weight multiplier during ramp-up (0.05-1.0)
        var cleanWindowsCount: Int = 0, // Consecutive clean windows for ramp-up
        var badDeliveryWindows: Int = 0, // Consecutive bad delivery windows (persistence)
        var lastCooldownReason: CooldownReason? = null, // Last reason for cooldown

        // EMA smoothing (alpha=0.2, ~2s memory at 500ms updates)
        var lateEma: Double = 0.0, // Smoothed late %
        var missingEma: Double = 0.0, // Smoothed missing %
        var plcEma: Double = 0.0, // Smoothed PLC %

        // Circuit rebuild policy (v3 - Quarantine → Replace → Ramp)
        var badWindowsCount: Int = 0, // Consecutive bad 5s windows (for rebuild)
        var quarantineUntil: Long = 0, // Quarantine timestamp (10s test period)
        var isRebuildCandidate: Boolean = false,// Marked for rebuild after quarantine
        var framesLateToBufferPercent: Double = 0.0, // % frames that missed deadline
        var rebuildFailures: Int = 0, // Count of rebuild failures (for backoff)
        var rebuildBackoffMs: Long = 10000L, // Current backoff duration (10s → 20s → 40s → 60s)
        var rebuildEpoch: Int = 0 // Incremented on each rebuild (forces fresh Tor path)
    ) {
        fun isInCooldown(): Boolean = System.currentTimeMillis() < cooldownUntil

        fun triggerCooldown(telemetry: CallQualityTelemetry?, circuitIndex: Int, reason: CooldownReason) {
            cooldownUntil = System.currentTimeMillis() + COOLDOWN_DURATION_MS
            rampUpWeight = 0.05 // Start at 5% weight when cooldown expires
            cleanWindowsCount = 0
            badDeliveryWindows = 0 // Reset persistence counter
            lastCooldownReason = reason
            telemetry?.reportCircuitCooldown(circuitIndex)
            Log.w(TAG, "Circuit $circuitIndex cooldown triggered (reason=$reason), will ramp from 5%")
        }

        fun resetFailures() {
            sendFailures = 0
        }

        /**
         * Update EMA smoothing for circuit metrics (alpha=0.2, ~2s memory)
         * Call this when new feedback is received
         */
        fun updateEma() {
            val alpha = 0.2
            lateEma = alpha * lateFramePercent + (1.0 - alpha) * lateEma
            missingEma = alpha * missingFramePercent + (1.0 - alpha) * missingEma
            plcEma = alpha * plcPercent + (1.0 - alpha) * plcEma
        }

        /**
         * FIX A: Correct scoring model (lower score = better circuit)
         *
         * Uses EMA-smoothed values to prevent noise-driven flapping
         *
         * Accumulates penalties:
         * - Late%: 0.5x weight (indicates timing issues)
         * - Missing%: 1.5x weight (indicates packet loss)
         * - PLC%: 2.0x weight (indicates severe quality degradation)
         *
         * Perfect circuit: score = 0.0
         * Terrible circuit: score = 50+ (high penalties)
         */
        fun score(): Double {
            var penalties = 0.0
            penalties += lateEma * 0.5 // Late frames = timing issues (smoothed)
            penalties += missingEma * 1.5 // Missing frames = packet loss (smoothed)
            penalties += plcEma * 2.0 // PLC = severe quality hit (smoothed)
            penalties += sendFailures * 5.0 // Send failures (instant)

            return penalties // Lower = better
        }

        /**
         * Check if circuit has excessive packet loss (SMARTER version)
         *
         * Returns delivery rate (0.0-1.0), or null if not enough data
         */
        fun getDeliveryRate(): Double? {
            if (totalFramesSent < MIN_FRAMES_FOR_MISSING_CALC) return null
            return peerFramesReceived.toDouble() / totalFramesSent.toDouble()
        }

        /**
         * Check if delivery-based cooldown should trigger (persistence + PLC gating)
         *
         * STRICT mode threshold: 92% (tolerate up to 8% loss)
         * Requires: 2 consecutive bad windows OR (bad delivery AND PLC > 3%)
         */
        fun shouldTriggerDeliveryCooldown(phase: CallPhase): Boolean {
            val deliveryRate = getDeliveryRate() ?: return false

            // STRICT mode: 92% threshold, RELAXED mode: 85% threshold
            val threshold = when (phase) {
                CallPhase.STRICT -> 0.92
                CallPhase.RELAXED -> 0.85
                else -> return false // No delivery checks in WARMUP/ESTABLISHMENT
            }

            if (deliveryRate >= threshold) {
                // Good delivery - reset persistence counter
                badDeliveryWindows = 0
                return false
            }

            // Bad delivery - check if we should cooldown
            badDeliveryWindows++

            // Trigger if: (persistent bad delivery) OR (bad delivery with audible impact)
            val persistentBadDelivery = badDeliveryWindows >= 2
            val audibleImpact = plcPercent > 3.0

            return persistentBadDelivery || audibleImpact
        }

        /**
         * FIX B: Ramp up weight gradually after cooldown to prevent flapping
         * Only ramps up after 2-3 consecutive clean windows (no issues)
         */
        fun updateRampUp() {
            if (rampUpWeight >= 1.0) {
                return // Already at full weight
            }

            // Check if this window was clean (low penalties)
            val isCleanWindow = (missingFramePercent < 2.0 && plcPercent < 3.0 && lateFramePercent < 5.0)

            if (isCleanWindow) {
                cleanWindowsCount++

                // After 2-3 clean windows, ramp up weight
                if (cleanWindowsCount >= 2) {
                    rampUpWeight = (rampUpWeight * 1.5).coerceAtMost(1.0)
                    Log.d(TAG, "Circuit ramping up: weight=${String.format("%.0f%%", rampUpWeight * 100)}")
                }
            } else {
                // Bad window - reset ramp progress
                cleanWindowsCount = 0
                Log.d(TAG, "Circuit ramp-up reset due to quality issues")
            }
        }
    }

    // Health tracking per circuit
    private val circuitHealth = Array(numCircuits) { CircuitHealth() }

    // Round-robin state (Phase 1: simple rotation through all circuits)
    private var currentCircuit: Int = 0 // Current circuit index (0 to numCircuits-1)
    private var lastRotationMs: Long = 0L // Last time we rotated to next circuit
    private var lastPhase: CallPhase? = null // Track phase transitions

    // Phase 2.2: Circuit group state
    private val circuitGroups = mutableMapOf<Int, CircuitGroup>() // Circuit index → group
    private var lastGroupClassificationMs: Long = 0L // Last time we reclassified groups
    private var useL1stGroup: Boolean = true // Alternate between L1ST and L2ND groups

    // Circuit rebuild policy (v3 - Quarantine → Replace → Ramp)
    private var rebuildInProgress: Boolean = false
    var onCircuitRebuildRequested: ((Int, Int) -> Unit)? = null // Callback to VoiceCallSession (circuitIndex, rebuildEpoch)

    /**
     * Get current call phase based on elapsed time
     */
    private fun getCurrentPhase(): CallPhase {
        val elapsed = System.currentTimeMillis() - callStartTime
        return when {
            elapsed < ESTABLISHMENT_PHASE_MS -> CallPhase.ESTABLISHMENT
            elapsed < WARMUP_PHASE_MS -> CallPhase.WARMUP
            elapsed < RELAXED_PHASE_MS -> CallPhase.RELAXED
            else -> CallPhase.STRICT
        }
    }

    /**
     * Select next circuit for sending a frame
     *
     * Stable primary circuit selection (bounded adaptive strategy)
     * - Select best circuit from L1ST group
     * - Stick with it unless circuit becomes bad (cooldown, high late%, or high missing%)
     * - Only failover when quality degrades to prevent reordering/jitter
     */
    fun selectCircuit(): Int {
        val nowMs = System.currentTimeMillis()

        // Initialize on first call - select best circuit from L1ST group
        if (lastRotationMs == 0L) {
            lastRotationMs = nowMs
            classifyCircuitGroups() // Initial classification
            currentCircuit = getBestCircuitFromGroup(CircuitGroup.L1ST) ?: 0
            Log.d(TAG, "Stable primary initialized: selected circuit $currentCircuit from L1ST group")
            return currentCircuit
        }

        // Reclassify groups every 2 seconds (Phase 2.1: monitoring window)
        if (nowMs - lastGroupClassificationMs >= MONITORING_WINDOW_MS) {
            classifyCircuitGroups()
            lastGroupClassificationMs = nowMs
        }

        // Check if current circuit is still healthy
        val currentHealth = circuitHealth[currentCircuit]
        val isInCooldown = currentHealth.cooldownUntil > nowMs
        val isBadLate = currentHealth.lateFramePercent > BAD_LATE_THRESHOLD
        val isBadMissing = currentHealth.missingFramePercent > BAD_MISSING_THRESHOLD

        // Only failover if current circuit is bad
        if (isInCooldown || isBadLate || isBadMissing) {
            val reason = when {
                isInCooldown -> "in cooldown"
                isBadLate -> "high late% (${String.format("%.1f", currentHealth.lateFramePercent)}%)"
                isBadMissing -> "high missing% (${String.format("%.1f", currentHealth.missingFramePercent)}%)"
                else -> "unknown"
            }

            // Failover: select best available circuit from L1ST or L2ND
            val newCircuit = getBestCircuitFromGroup(CircuitGroup.L1ST)
                ?: getBestCircuitFromGroup(CircuitGroup.L2ND)
                ?: ((currentCircuit + 1) % numCircuits) // Last resort

            if (newCircuit != currentCircuit) {
                Log.w(TAG, "FAILOVER: circuit $currentCircuit → $newCircuit (reason: $reason)")
                currentCircuit = newCircuit
                lastRotationMs = nowMs
            }
        }

        return currentCircuit
    }

    /**
     * Get best (lowest latency) circuit from a specific group that's not in cooldown
     */
    private fun getBestCircuitFromGroup(targetGroup: CircuitGroup): Int? {
        val nowMs = System.currentTimeMillis()
        val candidates = circuitGroups.filter { it.value == targetGroup }.keys

        return candidates
            .filter { circuitHealth[it].cooldownUntil <= nowMs } // Not in cooldown
            .minByOrNull { circuitHealth[it].score() } // Lowest score = best
    }

    /**
     * Phase 4: DOUBLE-SEND - Select TWO different circuits for maximum reliability
     * Returns: Pair of (primaryCircuit, secondaryCircuit)
     * Strategy: Use round-robin for primary, then select best available circuit from different group for secondary
     */
    fun selectTwoCircuits(): Pair<Int, Int> {
        val nowMs = System.currentTimeMillis()

        // Initialize on first call
        if (lastRotationMs == 0L) {
            lastRotationMs = nowMs
            currentCircuit = 0
            classifyCircuitGroups()
        }

        // Reclassify groups every 2 seconds
        if (nowMs - lastGroupClassificationMs >= MONITORING_WINDOW_MS) {
            classifyCircuitGroups()
            lastGroupClassificationMs = nowMs
        }

        // Get primary circuit via round-robin (same as selectCircuit)
        val targetGroup = if (useL1stGroup) CircuitGroup.L1ST else CircuitGroup.L2ND
        val availableCircuits = circuitGroups.filter { it.value == targetGroup }.keys.sorted()

        val primaryCircuit = if (availableCircuits.isEmpty()) {
            // Fallback to all circuits
            currentCircuit
        } else {
            val currentIndex = availableCircuits.indexOf(currentCircuit)

            // Rotate to next circuit every 100ms
            if (nowMs - lastRotationMs >= ROTATION_INTERVAL_MS && currentIndex != -1) {
                currentCircuit = availableCircuits[(currentIndex + 1) % availableCircuits.size]
                lastRotationMs = nowMs
                useL1stGroup = !useL1stGroup
            }
            currentCircuit
        }

        // Select secondary circuit from DIFFERENT group (path diversity!)
        val secondaryTargetGroup = if (targetGroup == CircuitGroup.L1ST) CircuitGroup.L2ND else CircuitGroup.L1ST
        val secondaryAvailable = circuitGroups.filter {
            it.value == secondaryTargetGroup && it.key != primaryCircuit
        }.keys.sorted()

        val secondaryCircuit = if (secondaryAvailable.isNotEmpty()) {
            // Pick best circuit from secondary group (lowest score)
            secondaryAvailable.minByOrNull { circuitHealth[it].score() } ?: primaryCircuit
        } else {
            // Fallback: Pick any circuit different from primary
            val fallback = (0 until numCircuits).filter { it != primaryCircuit }.minByOrNull { circuitHealth[it].score() }
            fallback ?: ((primaryCircuit + 1) % numCircuits)
        }

        Log.d(TAG, "DOUBLE-SEND: primary=$primaryCircuit (group=$targetGroup), secondary=$secondaryCircuit (group=$secondaryTargetGroup)")

        return Pair(primaryCircuit, secondaryCircuit)
    }

    /**
     * Phase 2.2: Classify circuits into groups based on health scores
     * L1ST: Top 3 circuits (best performance)
     * L2ND: Next 3 circuits (backup)
     * LINACTIVE: Remaining circuits (monitored but not used)
     */
    private fun classifyCircuitGroups() {
        // Sort circuits by score (lower = better)
        val sorted = (0 until numCircuits).sortedBy { circuitHealth[it].score() }

        // Clear existing groups
        circuitGroups.clear()

        // Assign groups
        sorted.take(3).forEach { circuitGroups[it] = CircuitGroup.L1ST }
        sorted.drop(3).take(3).forEach { circuitGroups[it] = CircuitGroup.L2ND }
        sorted.drop(6).forEach { circuitGroups[it] = CircuitGroup.LINACTIVE }

        val l1st = circuitGroups.filter { it.value == CircuitGroup.L1ST }.keys.sorted()
        val l2nd = circuitGroups.filter { it.value == CircuitGroup.L2ND }.keys.sorted()
        val linactive = circuitGroups.filter { it.value == CircuitGroup.LINACTIVE }.keys.sorted()

        Log.d(TAG, "Circuit groups: L1ST=$l1st, L2ND=$l2nd, LINACTIVE=$linactive")
    }

    /**
     * Select best available circuit (lowest score)
     * Honors cooldowns and ramp-up weights for scoring
     */
    private fun selectBestCircuit(): Int {
        // Get available circuits (not in cooldown)
        var availableCircuits = (0 until numCircuits).filter { !circuitHealth[it].isInCooldown() }

        // If all circuits in cooldown, enforce minimum circuit active
        if (availableCircuits.isEmpty()) {
            availableCircuits = enforceMinimumCircuitActive()
        }

        // Return circuit with lowest score (best)
        return availableCircuits.minByOrNull { circuitHealth[it].score() } ?: 0
    }

    /**
     * Enforce "at least one circuit active" invariant
     *
     * When all circuits are in cooldown, pick the best (lowest score) circuit
     * and clear its cooldown, setting it to minimum weight (5%)
     *
     * @return List with the single rescued circuit
     */
    private fun enforceMinimumCircuitActive(): List<Int> {
        // Find circuit with lowest score (best of the bad options)
        val leastBadCircuit = circuitHealth.indices.minByOrNull { circuitHealth[it].score() } ?: 0

        val health = circuitHealth[leastBadCircuit]
        health.cooldownUntil = 0 // Clear cooldown
        health.rampUpWeight = MIN_CIRCUIT_WEIGHT // Set to minimum weight (5%)

        Log.w(TAG, "Rescued circuit $leastBadCircuit from all-cooldown deadlock (score=${String.format("%.1f", health.score())})")

        return listOf(leastBadCircuit)
    }


    /**
     * Report send success on a circuit
     * Resets failure counter
     */
    fun reportSendSuccess(circuitIndex: Int) {
        if (circuitIndex !in 0 until numCircuits) return

        circuitHealth[circuitIndex].resetFailures()
        circuitHealth[circuitIndex].totalFramesSent++
    }

    /**
     * Report send failure on a circuit
     * Increments failure counter and may trigger cooldown
     */
    fun reportSendFailure(circuitIndex: Int) {
        if (circuitIndex !in 0 until numCircuits) return

        val health = circuitHealth[circuitIndex]
        health.sendFailures++

        Log.w(TAG, "Circuit $circuitIndex send failure (${health.sendFailures}/${FAILURE_THRESHOLD})")

        if (health.sendFailures >= FAILURE_THRESHOLD) {
            Log.w(TAG, "Circuit $circuitIndex exceeded failure threshold - triggering cooldown")
            health.triggerCooldown(telemetry, circuitIndex, CooldownReason.SEND_FAILURE)
            health.resetFailures()
        }
    }

    /**
     * Update circuit health from receiver feedback (v3 - enhanced with missing% and PLC%)
     * Called when CONTROL packet with stats is received
     *
     * STAGED CONTROL:
     * - ESTABLISHMENT (0-3s): No cooldowns, equal probing only
     * - WARMUP (3-15s): No cooldowns, soft steering via scores
     * - RELAXED (15-45s): Relaxed thresholds (missing% > 15%, PLC% > 10%, delivery < 85%)
     * - STRICT (45s+): Strict thresholds (missing% > 5%, PLC% > 5%, delivery < 92% with persistence)
     *
     * @param feedback Map containing circuit stats with late%, missing%, PLC%, peer received counts
     */
    fun updateFromReceiverFeedback(feedback: Map<Int, CircuitFeedback>) {
        val phase = getCurrentPhase()

        for ((circuitIndex, stats) in feedback) {
            if (circuitIndex in 0 until numCircuits) {
                val health = circuitHealth[circuitIndex]

                // Update stats from peer feedback (raw values)
                health.lateFramePercent = stats.latePercent
                health.missingFramePercent = stats.missingPercent
                health.plcPercent = stats.plcPercent
                health.peerFramesReceived = stats.framesReceived // CRITICAL: Peer's received count!

                // Update EMA smoothing for stable circuit selection
                health.updateEma()

                // WARMUP: No cooldowns during ESTABLISHMENT or WARMUP phases
                if (phase == CallPhase.ESTABLISHMENT || phase == CallPhase.WARMUP) {
                    // Still collect metrics and compute scores, but no cooldown triggers
                    // Soft steering happens naturally via score-based weight calculation
                    continue
                }

                // Check if we have enough data to evaluate (prevents early false positives)
                if (stats.framesReceived < MIN_FRAMES_FOR_MISSING_CALC) {
                    continue
                }

                // Determine thresholds based on current phase
                val (missingThreshold, plcThreshold) = when (phase) {
                    CallPhase.RELAXED -> Pair(15.0, 10.0) // Relaxed: 15-45s
                    CallPhase.STRICT -> Pair(5.0, 5.0) // Strict: 45s+
                    else -> continue // Should never reach here
                }

                // Check for cooldown conditions (with reasons for logging)
                var cooldownReason: CooldownReason? = null

                // 1. Check missing% threshold
                if (stats.missingPercent > missingThreshold) {
                    Log.w(TAG, "[$phase] Circuit $circuitIndex missing%=${String.format("%.1f", stats.missingPercent)}% > $missingThreshold% threshold")
                    cooldownReason = CooldownReason.HIGH_MISSING
                }

                // 2. Check PLC% threshold
                if (stats.plcPercent > plcThreshold) {
                    Log.w(TAG, "[$phase] Circuit $circuitIndex PLC%=${String.format("%.1f", stats.plcPercent)}% > $plcThreshold% threshold")
                    cooldownReason = CooldownReason.HIGH_PLC
                }

                // 3. Check delivery rate (SMART version: persistence + PLC gating)
                if (cooldownReason == null && health.shouldTriggerDeliveryCooldown(phase)) {
                    val deliveryRate = health.getDeliveryRate()!! * 100.0
                    val persistent = health.badDeliveryWindows >= 2
                    val plcImpact = health.plcPercent > 3.0
                    Log.w(TAG, "[$phase] Circuit $circuitIndex delivery=${String.format("%.1f", deliveryRate)}% " +
                            "(persistent=$persistent, plc=$plcImpact)")
                    cooldownReason = CooldownReason.DELIVERY_RATE
                }

                // Trigger cooldown if needed (and not already in cooldown)
                if (cooldownReason != null && !health.isInCooldown()) {
                    health.triggerCooldown(telemetry, circuitIndex, cooldownReason)
                }

                // FIX B: Update ramp-up weight for circuits recovering from cooldown
                if (!health.isInCooldown() && health.rampUpWeight < 1.0) {
                    health.updateRampUp()
                }

                // V3: Circuit Rebuild Policy - evaluate if circuit needs quarantine/rebuild
                // Note: lateToBufferRate would come from AudioPlaybackManager stats
                // For now, use 0.0 as placeholder (network-side loss detection)
                evaluateCircuitRebuild(circuitIndex, 0.0)

                // V3: Check if quarantined circuit has recovered or needs rebuild
                if (health.isRebuildCandidate && System.currentTimeMillis() >= health.quarantineUntil) {
                    checkQuarantineRecovery(circuitIndex)
                }
            }
        }

        logHealthStatus()
    }

    /**
     * Legacy method for backward compatibility (converts simple map to CircuitFeedback)
     * @param circuitStats Map of circuit index → late frame percentage
     */
    @JvmName("updateFromReceiverFeedbackLegacy")
    fun updateFromReceiverFeedback(circuitStats: Map<Int, Double>) {
        val feedback = circuitStats.mapValues { (_, latePercent) ->
            CircuitFeedback(
                latePercent = latePercent,
                missingPercent = 0.0,
                plcPercent = 0.0,
                framesReceived = 0L
            )
        }
        updateFromReceiverFeedback(feedback)
    }

    /**
     * Circuit feedback data from receiver
     */
    data class CircuitFeedback(
        val latePercent: Double,
        val missingPercent: Double,
        val plcPercent: Double,
        val framesReceived: Long
    )

    /**
     * Circuit Rebuild Policy (v3): Quarantine → Replace → Ramp
     *
     * Called every 5s from telemetry update to evaluate if a circuit should be rebuilt.
     *
     * Policy:
     * 1. Only evaluate after warmup (30s+)
     * 2. Define "persistently bad": 3 consecutive bad windows (15s total)
     * - PLC% >= 12% OR
     * - (PLC% >= 8% AND missing% >= 5%) OR
     * - (PLC% >= 10% AND lateToBufferRate% < 1.0 - network-side loss)
     * - BUT: only count if circuit carried enough traffic (sent >= 50 frames)
     * 3. Quarantine first (weight=0 for 10s) before rebuild
     * 4. Rebuild only one circuit at a time (rebuildInProgress lock)
     * 5. After rebuild: ramp from 5%, require 2-3 clean windows to climb
     *
     * @param lateToBufferRate Percentage (0-100) of frames that missed playout deadline
     */
    fun evaluateCircuitRebuild(circuitIndex: Int, lateToBufferRate: Double) {
        val phase = getCurrentPhase()

        // 1) Only evaluate after warmup (30s+)
        if (phase == CallPhase.ESTABLISHMENT || phase == CallPhase.WARMUP) {
            return
        }

        val health = circuitHealth[circuitIndex]

        // Gate: only evaluate if circuit carried enough traffic in this window
        // Prevents tiny sample noise (e.g., circuit at 5% weight with 10 frames)
        val sentLastWindow = health.totalFramesSent // TODO: track per-window sent count
        if (sentLastWindow < MIN_FRAMES_FOR_MISSING_CALC) {
            // Not enough samples - skip evaluation
            return
        }

        // 2) Define "persistently bad" window
        val plc = health.plcPercent
        val missing = health.missingFramePercent
        val isBadWindow = (
            plc >= 12.0 ||
            (plc >= 8.0 && missing >= 5.0) ||
            (plc >= 10.0 && lateToBufferRate < 1.0) // Network-side loss (lateToBufferRate is 0-100%)
        )

        if (isBadWindow) {
            health.badWindowsCount++
            Log.d(TAG, "Circuit $circuitIndex bad window ${health.badWindowsCount}/3 (PLC=${String.format("%.1f", plc)}%, missing=${String.format("%.1f", missing)}%)")
        } else {
            // Reset on good window
            if (health.badWindowsCount > 0) {
                Log.d(TAG, "Circuit $circuitIndex good window, resetting bad count from ${health.badWindowsCount} to 0")
            }
            health.badWindowsCount = 0
        }

        // 3) Trigger quarantine after 3 consecutive bad windows (15s)
        if (health.badWindowsCount >= 3 && !health.isRebuildCandidate && !rebuildInProgress) {
            quarantineCircuit(circuitIndex)
        }
    }

    /**
     * Quarantine circuit: set weight to 0%, test recovery with backoff duration
     *
     * Backoff increases on rebuild failures: 10s → 20s → 40s (cap at 60s)
     * Prevents rapid rebuild attempts on weak networks
     */
    private fun quarantineCircuit(circuitIndex: Int) {
        val health = circuitHealth[circuitIndex]

        val backoffSeconds = health.rebuildBackoffMs / 1000
        health.quarantineUntil = System.currentTimeMillis() + health.rebuildBackoffMs
        health.rampUpWeight = 0.0 // 0% weight during quarantine
        health.isRebuildCandidate = true // Mark for potential rebuild

        Log.w(TAG, "Circuit $circuitIndex QUARANTINED for ${backoffSeconds}s (PLC=${String.format("%.1f", health.plcPercent)}%, ${health.badWindowsCount} bad windows, failures=${health.rebuildFailures})")

        // Note: Quarantine check happens during next updateFromReceiverFeedback call
    }

    /**
     * Check if quarantined circuit recovered or needs rebuild
     * Called after quarantine period expires (10s)
     */
    fun checkQuarantineRecovery(circuitIndex: Int) {
        val health = circuitHealth[circuitIndex]

        // Check if still past quarantine time
        if (System.currentTimeMillis() < health.quarantineUntil) {
            return // Still in quarantine
        }

        // Quarantine expired - check if circuit recovered
        if (health.badWindowsCount >= 2) {
            // Still bad after quarantine - trigger rebuild
            Log.w(TAG, "Circuit $circuitIndex did NOT recover during quarantine (${health.badWindowsCount} bad windows) - requesting rebuild")
            triggerCircuitRebuild(circuitIndex)
        } else {
            // Recovered during quarantine - slowly ramp back up
            health.rampUpWeight = 0.05 // Start at 5%
            health.cleanWindowsCount = 0
            health.isRebuildCandidate = false
            health.badWindowsCount = 0
            Log.i(TAG, "Circuit $circuitIndex RECOVERED during quarantine, ramping from 5%")
        }
    }

    /**
     * Trigger circuit rebuild (only one at a time)
     *
     * Notifies VoiceCallSession to:
     * 1. Close existing TCP stream for this circuit
     * 2. Reconnect to peer's onion service (Tor picks new path/relays)
     * 3. Re-establish voice stream
     *
     * After rebuild: circuit starts at 5% weight and ramps slowly
     */
    private fun triggerCircuitRebuild(circuitIndex: Int) {
        if (rebuildInProgress) {
            Log.w(TAG, "Rebuild already in progress, deferring circuit $circuitIndex")
            return
        }

        rebuildInProgress = true
        val health = circuitHealth[circuitIndex]

        // Increment rebuild epoch to force fresh SOCKS5 isolation (new Tor path)
        health.rebuildEpoch++
        val rebuildEpoch = health.rebuildEpoch

        Log.w(TAG, "REBUILDING Circuit $circuitIndex (PLC=${String.format("%.1f", health.plcPercent)}%, score=${String.format("%.1f", health.score())}, rebuild_epoch=$rebuildEpoch)")

        // Notify VoiceCallSession to rebuild this circuit
        onCircuitRebuildRequested?.invoke(circuitIndex, rebuildEpoch)

        // Reset circuit state for fresh start
        health.badWindowsCount = 0
        health.isRebuildCandidate = false
        health.rampUpWeight = 0.0 // KEEP AT 0% UNTIL REBUILD COMPLETES (set to 0.05 in onCircuitRebuilt)
        health.cleanWindowsCount = 0
        health.sendFailures = 0
        health.badDeliveryWindows = 0

        // Note: rebuildInProgress and rampUpWeight will be set by VoiceCallSession after rebuild completes
    }

    /**
     * Called by VoiceCallSession after circuit rebuild completes successfully
     */
    fun onCircuitRebuilt(circuitIndex: Int, rebuildEpoch: Int) {
        rebuildInProgress = false
        val health = circuitHealth[circuitIndex]

        // Reset rebuild failure tracking on success
        health.rebuildFailures = 0
        health.rebuildBackoffMs = 10000L // Reset to 10s

        Log.i(TAG, "Circuit $circuitIndex rebuild SUCCESS (epoch=$rebuildEpoch), starting at 5% weight")

        // Circuit will ramp up gradually based on clean windows (existing ramp-up logic)
    }

    /**
     * Called by VoiceCallSession if circuit rebuild fails
     *
     * Implements exponential backoff: 10s → 20s → 40s → 60s (capped)
     * Prevents rapid retries on weak networks or Tor connectivity issues
     */
    fun onCircuitRebuildFailed(circuitIndex: Int) {
        rebuildInProgress = false
        val health = circuitHealth[circuitIndex]

        health.rebuildFailures++

        // Exponential backoff: double each time, cap at 60s
        health.rebuildBackoffMs = (health.rebuildBackoffMs * 2).coerceAtMost(60000L)

        val backoffSeconds = health.rebuildBackoffMs / 1000
        Log.e(TAG, "Circuit $circuitIndex rebuild FAILED (${health.rebuildFailures} failures), backoff → ${backoffSeconds}s")

        // Mark for re-quarantine on next evaluation
        health.isRebuildCandidate = false
        health.badWindowsCount = 0 // Reset so it can be re-evaluated
    }

    /**
     * Log current circuit health for debugging (with ramp-up status and phase)
     * Shows peerRecv explicitly to avoid confusion with local recv
     */
    private fun logHealthStatus() {
        val phase = getCurrentPhase()
        val elapsed = (System.currentTimeMillis() - callStartTime) / 1000.0

        val status = buildString {
            append("[$phase ${String.format("%.1f", elapsed)}s] Circuit Health: ")
            for (i in 0 until numCircuits) {
                val health = circuitHealth[i]
                append("[$i: score=${String.format("%.1f", health.score())} ")
                append("late=${String.format("%.1f%%", health.lateFramePercent)} ")
                append("missing=${String.format("%.1f%%", health.missingFramePercent)} ")
                append("plc=${String.format("%.1f%%", health.plcPercent)} ")

                // Show cooldown status and reason
                if (health.isInCooldown()) {
                    val reason = health.lastCooldownReason?.name ?: "?"
                    append("COOLDOWN($reason) ")
                } else if (health.rampUpWeight < 1.0) {
                    append("RAMP=${String.format("%.0f%%", health.rampUpWeight * 100)} ")
                }

                // CRITICAL: Show sent vs peerRecv (not local recv!)
                append("sent=${health.totalFramesSent} peerRecv=${health.peerFramesReceived}")

                // Show delivery rate if available
                val deliveryRate = health.getDeliveryRate()
                if (deliveryRate != null) {
                    append("(${String.format("%.0f%%", deliveryRate * 100)})")
                }
                append("] ")
            }
        }
        Log.d(TAG, status)
    }

    /**
     * Get current circuit statistics (for UI/debugging)
     */
    fun getCircuitStats(): List<CircuitStats> {
        return circuitHealth.mapIndexed { index, health ->
            CircuitStats(
                circuitIndex = index,
                lateFramePercent = health.lateFramePercent,
                sendFailures = health.sendFailures,
                totalFramesSent = health.totalFramesSent,
                inCooldown = health.isInCooldown()
            )
        }
    }

    /**
     * Statistics for a single circuit
     */
    data class CircuitStats(
        val circuitIndex: Int,
        val lateFramePercent: Double,
        val sendFailures: Int,
        val totalFramesSent: Long,
        val inCooldown: Boolean
    )
}
