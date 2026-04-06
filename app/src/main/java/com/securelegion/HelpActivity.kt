package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class HelpActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_help)

        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        findViewById<View>(R.id.chatSupportItem).setOnClickListener {
            startActivity(Intent(this, SupportComposerActivity::class.java))
        }

        findViewById<View>(R.id.helpCenterItem).setOnClickListener {
            startActivity(Intent(this, HelpCenterActivity::class.java))
        }

        findViewById<View>(R.id.exportLogsItem).setOnClickListener {
            exportDebugLogs()
        }
    }

    private fun exportDebugLogs() {
        ThemedToast.show(this, "Collecting logs...")
        lifecycleScope.launch {
            try {
                val logFile = withContext(Dispatchers.IO) { buildExportFile() }
                val uri = FileProvider.getUriForFile(
                    this@HelpActivity,
                    "${packageName}.fileprovider",
                    logFile
                )
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    putExtra(Intent.EXTRA_SUBJECT, "Secure Legion Debug Logs")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                startActivity(Intent.createChooser(shareIntent, "Share debug logs"))
            } catch (e: Exception) {
                Log.e("HelpActivity", "Failed to export logs", e)
                ThemedToast.show(this@HelpActivity, "Export failed: ${e.message}")
            }
        }
    }

    private fun buildExportFile(): File {
        val timestamp = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())
        val exportDir = File(cacheDir, "exports")
        if (!exportDir.exists()) exportDir.mkdirs()
        val file = File(exportDir, "secure-debug-$timestamp.txt")

        val sb = StringBuilder()
        sb.appendLine("=== Secure Legion Debug Log ===")
        sb.appendLine("Timestamp: ${Date()}")
        sb.appendLine("Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
        sb.appendLine("Android: ${android.os.Build.VERSION.RELEASE} (SDK ${android.os.Build.VERSION.SDK_INT})")
        sb.appendLine("App: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        sb.appendLine()
        sb.appendLine("=== Logcat (last 1000 lines) ===")

        try {
            val process = Runtime.getRuntime().exec(arrayOf("logcat", "-d", "-t", "1000"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            reader.useLines { lines ->
                lines.filter { line ->
                    line.contains("securelegion", ignoreCase = true) ||
                    line.contains("SecureLegion", ignoreCase = true) ||
                    line.contains("Tor", ignoreCase = false)
                }.forEach { sb.appendLine(redactSensitive(it)) }
            }
        } catch (e: Exception) {
            sb.appendLine("Failed to read logcat: ${e.message}")
        }

        file.writeText(sb.toString())
        return file
    }

    /** Redact .onion addresses, hex keys (32+ chars), and base64 key material from log lines. */
    private fun redactSensitive(line: String): String {
        var result = line
        // Redact .onion addresses (56-char v3 onion)
        result = result.replace(Regex("[a-z2-7]{56}\\.onion"), "[REDACTED].onion")
        // Redact long hex strings (likely keys/hashes — 32+ hex chars)
        result = result.replace(Regex("(?<![a-fA-F0-9])[a-fA-F0-9]{64,}(?![a-fA-F0-9])"), "[REDACTED_KEY]")
        return result
    }
}
