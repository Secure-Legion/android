package com.securelegion

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.text.SimpleDateFormat
import java.util.*

/**
 * CallLogActivity - Display call quality telemetry history from database
 *
 * Shows recent call logs with detailed metrics:
 * - Overall stats: Late%, PLC%, FEC success%, out-of-order%
 * - Per-circuit stats: Late%, distribution, sent/recv counts, cooldowns
 * - Jitter buffer size
 * - Audio underruns
 * - Call duration and quality score
 */
class CallLogActivity : BaseActivity() {

    private lateinit var logTextView: TextView
    private lateinit var noDataView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_call_log)

        // Initialize views
        logTextView = findViewById(R.id.logTextView)
        noDataView = findViewById(R.id.noDataTextView)

        // Set up back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Load and display call history
        displayCallHistory()
    }

    private fun displayCallHistory() {
        lifecycleScope.launch {
            try {
                // Get database
                val keyManager = KeyManager.getInstance(this@CallLogActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val db = SecureLegionDatabase.getInstance(this@CallLogActivity, dbPassphrase)

                // Load recent call logs
                val logs = withContext(Dispatchers.IO) {
                    db.callQualityLogDao().getRecentLogs(limit = 20)
                }

                if (logs.isEmpty()) {
                    // No call data available
                    logTextView.visibility = View.GONE
                    noDataView.visibility = View.VISIBLE
                    return@launch
                }

                // Show telemetry
                logTextView.visibility = View.VISIBLE
                noDataView.visibility = View.GONE

                // Format telemetry into readable text
                val report = buildString {
                    appendLine("==================================================")
                    appendLine("CALL QUALITY HISTORY (${logs.size} calls)")
                    appendLine("==================================================")
                    appendLine()

                    logs.forEachIndexed { index, log ->
                        // Format timestamp
                        val dateFormat = SimpleDateFormat("MMM dd, HH:mm:ss", Locale.US)
                        val timestamp = dateFormat.format(Date(log.timestamp))

                        // Quality text
                        val qualityText = when (log.qualityScore) {
                            5 -> "Excellent (5/5)"
                            4 -> "Good (4/5)"
                            3 -> "Fair (3/5)"
                            2 -> "Poor (2/5)"
                            1 -> "Bad (1/5)"
                            else -> "Terrible (0/5)"
                        }

                        appendLine("=== Call ${index + 1}: $timestamp ===")
                        appendLine()
                        appendLine("Contact: ${log.contactName}")
                        appendLine("Duration: ${formatDuration(log.durationSeconds)}")
                        appendLine("Quality: $qualityText")
                        appendLine()
                        appendLine("Overall Metrics:")
                        appendLine(" Total Frames: ${log.totalFrames}")
                        appendLine(" Late%: ${String.format("%.2f%%", log.latePercent)}")
                        appendLine(" PLC%: ${String.format("%.2f%%", log.plcPercent)}")
                        appendLine(" FEC Success%: ${String.format("%.2f%%", log.fecSuccessPercent)}")
                        appendLine(" Out-of-Order%: ${String.format("%.2f%%", log.outOfOrderPercent)}")
                        appendLine(" Jitter Buffer: ${log.jitterBufferMs}ms")
                        appendLine(" Underruns: ${log.audioUnderruns}")
                        appendLine()

                        // Parse circuit stats JSON
                        try {
                            val circuitStats = JSONArray(log.circuitStatsJson)
                            if (circuitStats.length() > 0) {
                                appendLine("Per-Circuit:")
                                for (i in 0 until circuitStats.length()) {
                                    val circuit = circuitStats.getJSONObject(i)
                                    appendLine(" Circuit ${circuit.getInt("circuitIndex")}:")
                                    appendLine(" Late%: ${String.format("%.1f%%", circuit.getDouble("latePercent"))}")

                                    // FIX #4: Display missing% and PLC% if available (v3 telemetry)
                                    if (circuit.has("missingPercent")) {
                                        appendLine(" Missing%: ${String.format("%.1f%%", circuit.getDouble("missingPercent"))}")
                                    }
                                    if (circuit.has("plcPercent")) {
                                        appendLine(" PLC%: ${String.format("%.1f%%", circuit.getDouble("plcPercent"))}")
                                    }

                                    appendLine(" Sent: ${circuit.getLong("framesSent")}")
                                    appendLine(" Received: ${circuit.getLong("framesReceived")}")
                                    appendLine(" Cooldowns: ${circuit.getInt("cooldownEvents")}")

                                    // Show burst loss events if present
                                    if (circuit.has("burstLossEvents") && circuit.getInt("burstLossEvents") > 0) {
                                        appendLine(" Burst Loss: ${circuit.getInt("burstLossEvents")} events")
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            appendLine(" (Circuit stats unavailable)")
                        }

                        appendLine()
                        if (index < logs.size - 1) {
                            appendLine("-------------------------------------------------")
                            appendLine()
                        }
                    }

                    appendLine("==================================================")
                }

                logTextView.text = report

            } catch (e: Exception) {
                android.util.Log.e("CallLogActivity", "Error loading call history", e)
                noDataView.visibility = View.VISIBLE
                logTextView.visibility = View.GONE
                noDataView.text = "Error loading call history:\n${e.message}"
            }
        }
    }

    private fun formatDuration(seconds: Int): String {
        val mins = seconds / 60
        val secs = seconds % 60
        return String.format("%d:%02d", mins, secs)
    }
}
