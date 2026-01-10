package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Call Quality Log - Stores telemetry from voice calls for debugging
 *
 * Persists call quality metrics including:
 * - Overall stats (late%, PLC%, FEC%, out-of-order%)
 * - Per-circuit performance
 * - Jitter buffer size
 * - Quality score (0-5 bars)
 */
@Entity(tableName = "call_quality_logs")
data class CallQualityLog(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * Call ID (matches voice call session)
     */
    val callId: String,

    /**
     * Contact name or number
     */
    val contactName: String,

    /**
     * Call timestamp (Unix milliseconds)
     */
    val timestamp: Long,

    /**
     * Call duration in seconds
     */
    val durationSeconds: Int,

    /**
     * Overall quality score (0-5 bars)
     */
    val qualityScore: Int,

    // === Overall Metrics ===

    /**
     * Total audio frames processed
     */
    val totalFrames: Long,

    /**
     * Late frame percentage (0-100)
     */
    val latePercent: Double,

    /**
     * PLC (Packet Loss Concealment) percentage (0-100)
     */
    val plcPercent: Double,

    /**
     * FEC recovery success percentage (0-100)
     */
    val fecSuccessPercent: Double,

    /**
     * Out-of-order frame percentage (0-100)
     */
    val outOfOrderPercent: Double,

    /**
     * Jitter buffer size in milliseconds
     */
    val jitterBufferMs: Int,

    /**
     * Audio underrun count
     */
    val audioUnderruns: Long,

    // === Per-Circuit Stats (stored as JSON) ===

    /**
     * Per-circuit statistics in JSON format
     * Format: [{"circuitIndex":0,"latePercent":2.5,"framesSent":100,"framesReceived":98,"cooldowns":0}, ...]
     */
    val circuitStatsJson: String
)
