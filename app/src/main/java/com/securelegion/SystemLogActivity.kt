package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.util.Log
import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.*

/**
 * SystemLogActivity - Shows filtered logcat output for beta debugging.
 *
 * Captures ERROR and WARN level logs from the app's process,
 * with color-coded display and copy/share for easy bug reporting.
 */
class SystemLogActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "SystemLogActivity"
        private const val MAX_LINES = 500
    }

    private lateinit var logTextView: TextView
    private lateinit var noDataView: TextView
    private lateinit var logCountText: TextView
    private lateinit var logScrollView: ScrollView

    private lateinit var filterAll: TextView
    private lateinit var filterErrors: TextView
    private lateinit var filterWarnings: TextView

    private var allEntries = listOf<LogEntry>()
    private var currentFilter = Filter.ALL

    private enum class Filter { ALL, ERROR, WARN }

    private data class LogEntry(
        val timestamp: String,
        val level: String,   // "E" or "W"
        val tag: String,
        val message: String,
        val raw: String
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_system_log)

        logTextView = findViewById(R.id.logTextView)
        noDataView = findViewById(R.id.noDataTextView)
        logCountText = findViewById(R.id.logCountText)
        logScrollView = findViewById(R.id.logScrollView)

        filterAll = findViewById(R.id.filterAll)
        filterErrors = findViewById(R.id.filterErrors)
        filterWarnings = findViewById(R.id.filterWarnings)

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }

        filterAll.setOnClickListener { setFilter(Filter.ALL) }
        filterErrors.setOnClickListener { setFilter(Filter.ERROR) }
        filterWarnings.setOnClickListener { setFilter(Filter.WARN) }

        findViewById<View>(R.id.copyButton).setOnClickListener { copyLogs() }
        findViewById<View>(R.id.shareButton).setOnClickListener { shareLogs() }

        loadLogs()
    }

    private fun setFilter(filter: Filter) {
        currentFilter = filter
        filterAll.alpha = if (filter == Filter.ALL) 1.0f else 0.5f
        filterErrors.alpha = if (filter == Filter.ERROR) 1.0f else 0.5f
        filterWarnings.alpha = if (filter == Filter.WARN) 1.0f else 0.5f

        displayFiltered()
    }

    private fun loadLogs() {
        lifecycleScope.launch {
            try {
                val entries = withContext(Dispatchers.IO) { readLogcat() }
                allEntries = entries
                setFilter(Filter.ALL)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to read logcat", e)
                noDataView.text = "Failed to read logs: ${e.message}"
                noDataView.visibility = View.VISIBLE
                logTextView.visibility = View.GONE
            }
        }
    }

    private fun displayFiltered() {
        val filtered = when (currentFilter) {
            Filter.ALL -> allEntries
            Filter.ERROR -> allEntries.filter { it.level == "E" }
            Filter.WARN -> allEntries.filter { it.level == "W" }
        }

        if (filtered.isEmpty()) {
            logTextView.visibility = View.GONE
            noDataView.visibility = View.VISIBLE
            noDataView.text = "No log entries found"
            logCountText.text = ""
            return
        }

        noDataView.visibility = View.GONE
        logTextView.visibility = View.VISIBLE

        val errorCount = filtered.count { it.level == "E" }
        val warnCount = filtered.count { it.level == "W" }
        logCountText.text = "${filtered.size} entries ($errorCount errors, $warnCount warnings)"

        val ssb = SpannableStringBuilder()
        for (entry in filtered) {
            val start = ssb.length
            ssb.append("[${entry.level}] ${entry.timestamp} ${entry.tag}\n")

            val color = if (entry.level == "E") 0xFFFF6666.toInt() else 0xFFFFAA33.toInt()
            ssb.setSpan(
                ForegroundColorSpan(color),
                start, start + 3,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
            ssb.setSpan(
                StyleSpan(Typeface.BOLD),
                start, start + 3,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )

            val msgStart = ssb.length
            ssb.append("  ${entry.message}\n\n")
            ssb.setSpan(
                ForegroundColorSpan(0xFFAAAAAA.toInt()),
                msgStart, ssb.length,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        logTextView.text = ssb

        logScrollView.post { logScrollView.fullScroll(View.FOCUS_DOWN) }
    }

    private fun readLogcat(): List<LogEntry> {
        val entries = mutableListOf<LogEntry>()
        val pid = android.os.Process.myPid().toString()

        // Use --pid to only get our app's logs (not the whole phone's system logs)
        val pb = ProcessBuilder("logcat", "-d", "-v", "time", "--pid", pid, "*:W")
        pb.redirectErrorStream(true)
        val process = pb.start()

        val reader = BufferedReader(InputStreamReader(process.inputStream))
        var line: String?
        var count = 0

        while (reader.readLine().also { line = it } != null && count < MAX_LINES) {
            val l = line ?: continue
            val parsed = parseLogLine(l) ?: continue
            entries.add(parsed)
            count++
        }

        reader.close()
        process.destroy()

        return entries
    }

    private fun parseLogLine(line: String): LogEntry? {
        // Format: "02-18 14:30:45.123 E/SomeTag( 1234): Some message"
        try {
            val parts = line.trim()
            if (parts.length < 20) return null

            val timestamp = parts.substring(0, 18).trim()

            val levelChar = parts.getOrNull(19) ?: return null
            if (levelChar != 'E' && levelChar != 'W') return null
            val level = levelChar.toString()

            val afterLevel = parts.substring(20)
            if (!afterLevel.startsWith("/")) return null

            val tagAndRest = afterLevel.substring(1)

            val parenIdx = tagAndRest.indexOf('(')
            if (parenIdx < 0) return null
            val tag = tagAndRest.substring(0, parenIdx).trim()

            val msgIdx = tagAndRest.indexOf("): ")
            if (msgIdx < 0) return null
            val message = tagAndRest.substring(msgIdx + 3)

            return LogEntry(
                timestamp = timestamp,
                level = level,
                tag = tag,
                message = message,
                raw = line
            )
        } catch (e: Exception) {
            return null
        }
    }

    private fun getPlainText(): String {
        val filtered = when (currentFilter) {
            Filter.ALL -> allEntries
            Filter.ERROR -> allEntries.filter { it.level == "E" }
            Filter.WARN -> allEntries.filter { it.level == "W" }
        }
        return buildString {
            appendLine("SecureLegion System Log")
            appendLine("Captured: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
            appendLine("Filter: ${currentFilter.name}")
            appendLine("Entries: ${filtered.size}")
            appendLine("=========================================")
            appendLine()
            for (entry in filtered) {
                appendLine("[${entry.level}] ${entry.timestamp} ${entry.tag}")
                appendLine("  ${entry.message}")
                appendLine()
            }
        }
    }

    private fun copyLogs() {
        val text = getPlainText()
        if (text.isBlank()) {
            ThemedToast.show(this, "No logs to copy")
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("SecureLegion System Log", text))
        ThemedToast.show(this, "Logs copied to clipboard")
    }

    private fun shareLogs() {
        val text = getPlainText()
        if (text.isBlank()) {
            ThemedToast.show(this, "No logs to share")
            return
        }
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "SecureLegion System Log")
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(intent, "Share log"))
    }
}
