package com.securelegion

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.RustBridge
import com.securelegion.services.TorService

/**
 * TorHealthActivity - Real-time Tor health monitoring
 *
 * Displays:
 * - Main Tor: Healthy / Reconnecting / Offline
 * - Voice Tor: Healthy / Reconnecting / Offline
 * - Circuits: 0/1
 * - Network: Live / Dead
 * - Bootstrap: 0-100%
 *
 * Updates every 2 seconds
 */
class

TorHealthActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "TorHealthActivity"
        private const val UPDATE_INTERVAL_MS = 2000L // 2 seconds
    }

    // UI Elements
    private lateinit var mainTorStatusText: TextView
    private lateinit var mainTorStatusIndicator: View
    private lateinit var mainCircuitsText: TextView
    private lateinit var mainBootstrapText: TextView

    private lateinit var voiceTorStatusText: TextView
    private lateinit var voiceTorStatusIndicator: View

    private lateinit var networkStatusText: TextView
    private lateinit var networkStatusIndicator: View

    // Update handler
    private val updateHandler = Handler(Looper.getMainLooper())
    private val updateRunnable = object : Runnable {
        override fun run() {
            updateHealthIndicators()
            updateHandler.postDelayed(this, UPDATE_INTERVAL_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_tor_health)

        // Initialize UI elements
        mainTorStatusText = findViewById(R.id.mainTorStatusText)
        mainTorStatusIndicator = findViewById(R.id.mainTorStatusIndicator)
        mainCircuitsText = findViewById(R.id.mainCircuitsText)
        mainBootstrapText = findViewById(R.id.mainBootstrapText)

        voiceTorStatusText = findViewById(R.id.voiceTorStatusText)
        voiceTorStatusIndicator = findViewById(R.id.voiceTorStatusIndicator)

        networkStatusText = findViewById(R.id.networkStatusText)
        networkStatusIndicator = findViewById(R.id.networkStatusIndicator)

        // Set up back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        BottomNavigationHelper.setupBottomNavigation(this)
    }

    override fun onResume() {
        super.onResume()
        // Start polling health indicators
        updateHandler.post(updateRunnable)
    }

    override fun onPause() {
        super.onPause()
        // Stop polling when activity is not visible
        updateHandler.removeCallbacks(updateRunnable)
    }

    /**
     * Update all health indicators
     */
    private fun updateHealthIndicators() {
        try {
            // Main Tor Health
            val bootstrapPercent = RustBridge.getBootstrapStatus()
            val circuitsEstablished = RustBridge.getCircuitEstablished()

            // Network check first — Tor's local control socket stays alive even with WiFi dead,
            // so circuits/bootstrap can look "healthy" while the network path is actually broken.
            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            val activeNetwork = connectivityManager.activeNetwork
            val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            val hasInternet = capabilities?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true

            // Proof-based status: HS self-test passed since last network change
            val lastProofMs = try { RustBridge.getLastTorProofMs() } catch (_: Exception) { 0L }
            val lastNetworkChangeMs = com.securelegion.services.TorService.getLastNetworkChangeMs()
            val hasFreshProof = lastProofMs > 0 && lastProofMs >= lastNetworkChangeMs
            val hasTransportReady = bootstrapPercent >= 100 && circuitsEstablished == 1

            when {
                !hasInternet -> {
                    mainTorStatusText.text = "Offline"
                    mainTorStatusText.setTextColor(0xFFFF6666.toInt())
                    mainTorStatusIndicator.setBackgroundResource(R.drawable.status_error_indicator)
                }
                hasFreshProof -> {
                    mainTorStatusText.text = "Receivable"
                    mainTorStatusText.setTextColor(0xFF00CC66.toInt())
                    mainTorStatusIndicator.setBackgroundResource(R.drawable.status_healthy_indicator)
                }
                hasTransportReady -> {
                    // Outbound Tor transport is ready. Inbound proof may still be catching up.
                    mainTorStatusText.text = "Connected"
                    mainTorStatusText.setTextColor(0xFF00CC66.toInt())
                    mainTorStatusIndicator.setBackgroundResource(R.drawable.status_healthy_indicator)
                }
                else -> {
                    mainTorStatusText.text = "Connecting"
                    mainTorStatusText.setTextColor(0xFFFFAA00.toInt())
                    mainTorStatusIndicator.setBackgroundResource(R.drawable.status_warning_indicator)
                }
            }

            mainCircuitsText.text = "Circuits: $circuitsEstablished"
            mainBootstrapText.text = "Bootstrap: $bootstrapPercent%"

            // Voice Tor Health — disabled in v1
            voiceTorStatusText.text = "Disabled"
            voiceTorStatusText.setTextColor(0xFF666666.toInt())
            voiceTorStatusIndicator.setBackgroundResource(R.drawable.status_offline_indicator)

            // Network Status
            if (hasInternet) {
                networkStatusText.text = "Live"
                networkStatusText.setTextColor(0xFF00CC66.toInt())
                networkStatusIndicator.setBackgroundResource(R.drawable.status_healthy_indicator)
            } else {
                networkStatusText.text = "Dead"
                networkStatusText.setTextColor(0xFFFF6666.toInt())
                networkStatusIndicator.setBackgroundResource(R.drawable.status_error_indicator)
            }

        } catch (e: Exception) {
            // Silently handle errors (service might not be bound yet)
        }
    }
}
