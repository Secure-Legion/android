package com.securelegion

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.RustBridge
import com.securelegion.services.TorService
import com.securelegion.utils.ThemedToast
import org.json.JSONObject

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
    private lateinit var networkStatusText: TextView
    private lateinit var networkStatusIndicator: View

    private lateinit var circuitRouteContainer: LinearLayout
    private var lastRenderedCircuit: String? = null

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
        networkStatusText = findViewById(R.id.networkStatusText)
        networkStatusIndicator = findViewById(R.id.networkStatusIndicator)
        circuitRouteContainer = findViewById(R.id.circuitRouteContainer)
        renderCircuitPlaceholders()

        // Set up back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // New Circuit button — requests fresh circuits for new outbound streams (Arti: isolated_client swap; C Tor: SIGNAL NEWNYM)
        findViewById<View>(R.id.newCircuitButton).setOnClickListener { v ->
            v.isEnabled = false
            Thread {
                val ok = try { RustBridge.sendNewnym() } catch (_: Throwable) { false }
                runOnUiThread {
                    ThemedToast.show(
                        this,
                        if (ok) "New circuit requested" else "Unable to rotate circuits right now"
                    )
                    v.isEnabled = true
                }
            }.start()
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
     * Update the collapsed network status + circuit route cards.
     *
     * "Live" means the HS is receivable AND the transport is 100% bootstrapped.
     * Any weaker state ("Connecting", "Offline") is just transient noise; the user
     * only cares that the combined signal is green.
     */
    private fun updateHealthIndicators() {
        try {
            val bootstrapPercent = try { RustBridge.getBootstrapStatus() } catch (_: Throwable) { 0 }
            val circuitsEstablished = try { RustBridge.getCircuitEstablished() } catch (_: Throwable) { 0 }

            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            val activeNetwork = connectivityManager.activeNetwork
            val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            val hasInternet = capabilities?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true

            val lastProofMs = try { RustBridge.getLastTorProofMs() } catch (_: Throwable) { 0L }
            val lastNetworkChangeMs = com.securelegion.services.TorService.getLastNetworkChangeMs()
            val hasFreshProof = lastProofMs > 0 && lastProofMs >= lastNetworkChangeMs

            val isLive = hasInternet && bootstrapPercent >= 100 && hasFreshProof
            val isConnecting = hasInternet && (bootstrapPercent < 100 || circuitsEstablished != 1 || !hasFreshProof)

            when {
                !hasInternet -> {
                    networkStatusText.text = "Offline"
                    networkStatusText.setTextColor(0xFFFF6666.toInt())
                    networkStatusIndicator.setBackgroundResource(R.drawable.status_error_indicator)
                }
                isLive -> {
                    networkStatusText.text = "Live"
                    networkStatusText.setTextColor(0xFF00CC66.toInt())
                    networkStatusIndicator.setBackgroundResource(R.drawable.status_healthy_indicator)
                }
                isConnecting -> {
                    networkStatusText.text = "Connecting"
                    networkStatusText.setTextColor(0xFFFFAA00.toInt())
                    networkStatusIndicator.setBackgroundResource(R.drawable.status_warning_indicator)
                }
            }

            // Current Route
            val circuitJson = try { RustBridge.getCurrentCircuitInfo() } catch (_: Throwable) { null }
            if (circuitJson != null && circuitJson != lastRenderedCircuit) {
                renderCircuitRoute(circuitJson)
                lastRenderedCircuit = circuitJson
            }

        } catch (e: Exception) {
            // Silently handle errors (service might not be bound yet)
        }
    }

    private fun renderCircuitPlaceholders() {
        // Shown before any outbound connection has happened (or when Rust returned empty).
        // Three hops is the common Arti HS client case (Entry / Middle / Rendezvous).
        val roles = listOf("Entry Node", "Middle Node", "Rendezvous Point")
        circuitRouteContainer.removeAllViews()
        for (role in roles) {
            circuitRouteContainer.addView(makeHopCard(role, location = "—", secondary = null, fingerprint = "—"))
        }
    }

    private fun renderCircuitRoute(json: String) {
        val hops = try {
            JSONObject(json).optJSONArray("hops")
        } catch (_: Throwable) {
            null
        }
        if (hops == null || hops.length() == 0) {
            renderCircuitPlaceholders()
            return
        }

        circuitRouteContainer.removeAllViews()
        for (i in 0 until hops.length()) {
            val h = hops.optJSONObject(i) ?: continue
            val role = h.optString("role", "Hop")
            val fp = h.optString("fp", "")
            val nickname = h.optString("nickname", "").takeIf { it.isNotBlank() }
            val country = h.optString("country", "").takeIf { it.isNotBlank() }

            // Match iOS display rule: prefer country, fall back to nickname, fall back to "—".
            // When country is shown AND nickname exists, show nickname on a second muted line
            // (so the user sees both without crowding the header row).
            val location = country ?: nickname ?: "—"
            val secondary = if (country != null && nickname != null) nickname else null
            val fingerprint = if (fp.length >= 16) fp.substring(0, 16) + "…" else fp

            circuitRouteContainer.addView(makeHopCard(role, location, secondary, fingerprint))
        }
    }

    private fun makeHopCard(role: String, location: String, secondary: String?, fingerprint: String): View {
        val inflater = LayoutInflater.from(this)
        val card = inflater.inflate(R.layout.item_tor_hop_card, circuitRouteContainer, false) as ViewGroup
        card.findViewById<TextView>(R.id.hopRole).text = role
        card.findViewById<TextView>(R.id.hopLocation).text = location
        val secondaryView = card.findViewById<TextView>(R.id.hopSecondary)
        if (secondary != null) {
            secondaryView.text = secondary
            secondaryView.visibility = View.VISIBLE
        } else {
            secondaryView.visibility = View.GONE
        }
        card.findViewById<TextView>(R.id.hopFingerprint).text = fingerprint
        return card
    }
}
