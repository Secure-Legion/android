package com.securelegion

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import com.securelegion.crypto.RustBridge
import com.securelegion.services.TorService
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import org.json.JSONObject

/**
 * Tor Health screen.
 *
 * - Status dot + "Network" label reflect live transport health.
 * - Network toggle: lets the user disable Tor entirely. OFF requires confirmation
 *   (GlassDialog) because messaging won't work without Tor. The choice persists via
 *   SharedPreferences and is honored by BootReceiver + LockActivity auto-start paths.
 * - Current Route: shows the hops of the most recent outbound HS circuit.
 * - New Circuit: forces Arti to pick fresh circuits for the next outbound connection.
 */
class TorHealthActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "TorHealthActivity"
        private const val UPDATE_INTERVAL_MS = 2000L
    }

    private lateinit var networkStatusIndicator: View
    private lateinit var networkToggle: SwitchCompat
    private lateinit var circuitRouteContainer: LinearLayout
    private var lastRenderedCircuit: String? = null

    // Suppress the toggle listener while we programmatically sync the switch to
    // persisted state — otherwise we'd show the confirmation dialog for our own sync.
    private var suppressToggleListener = false

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

        networkStatusIndicator = findViewById(R.id.networkStatusIndicator)
        networkToggle = findViewById(R.id.networkToggle)
        circuitRouteContainer = findViewById(R.id.circuitRouteContainer)
        renderCircuitPlaceholders()

        syncToggleFromPrefs()
        networkToggle.setOnCheckedChangeListener { _, isChecked ->
            if (suppressToggleListener) return@setOnCheckedChangeListener
            if (isChecked) enableTorNetwork() else confirmDisableTorNetwork()
        }

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }

        // New Circuit button — requests fresh circuits for new outbound streams
        // (Arti: isolated_client swap; C Tor: SIGNAL NEWNYM).
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
        // Re-sync in case the user toggled elsewhere or the service was stopped externally.
        syncToggleFromPrefs()
        updateHandler.post(updateRunnable)
    }

    override fun onPause() {
        super.onPause()
        updateHandler.removeCallbacks(updateRunnable)
    }

    private fun syncToggleFromPrefs() {
        val enabled = !TorService.isUserDisabled(this)
        if (networkToggle.isChecked != enabled) {
            suppressToggleListener = true
            networkToggle.isChecked = enabled
            suppressToggleListener = false
        }
    }

    private fun confirmDisableTorNetwork() {
        val dialog = GlassDialog.builder(this)
            .setTitle("Disable Tor Network?")
            .setMessage("With Tor disabled, you won't be able to send or receive messages, friend requests, or calls. Your identity stays on this device but you'll be offline until you turn Tor back on.")
            .setPositiveButton("Turn Off") { _, _ ->
                disableTorNetwork()
            }
            .setNegativeButton("Cancel") { _, _ ->
                // User cancelled — flip the switch back to ON without firing this handler.
                suppressToggleListener = true
                networkToggle.isChecked = true
                suppressToggleListener = false
            }
            .setOnCancelListener {
                // Dismissed without picking a button — same as cancel.
                suppressToggleListener = true
                networkToggle.isChecked = true
                suppressToggleListener = false
            }
            .create()
        GlassDialog.show(dialog)
    }

    private fun disableTorNetwork() {
        TorService.setUserDisabled(this, true)
        try {
            stopService(Intent(this, TorService::class.java))
        } catch (_: Throwable) {
            // Already stopped — fine.
        }
        ThemedToast.show(this, "Tor network disabled")
    }

    private fun enableTorNetwork() {
        TorService.setUserDisabled(this, false)
        try {
            val intent = Intent(this, TorService::class.java).apply {
                action = TorService.ACTION_START_TOR
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            ThemedToast.show(this, "Tor network enabled")
        } catch (e: Throwable) {
            ThemedToast.show(this, "Failed to start Tor: ${e.message}")
        }
    }

    /**
     * Update the status indicator dot + circuit route cards. The toggle state is driven
     * by the user, not this polling loop — we only update the health *indicator* here.
     */
    private fun updateHealthIndicators() {
        try {
            val userDisabled = TorService.isUserDisabled(this)
            if (userDisabled) {
                networkStatusIndicator.setBackgroundResource(R.drawable.status_offline_indicator)
                // When the user opted out of Tor we don't report circuit info — hops reflect
                // pre-disable state and would be confusing.
                renderCircuitPlaceholders()
                lastRenderedCircuit = null
                return
            }

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
                !hasInternet -> networkStatusIndicator.setBackgroundResource(R.drawable.status_error_indicator)
                isLive -> networkStatusIndicator.setBackgroundResource(R.drawable.status_healthy_indicator)
                isConnecting -> networkStatusIndicator.setBackgroundResource(R.drawable.status_warning_indicator)
            }

            val circuitJson = try { RustBridge.getCurrentCircuitInfo() } catch (_: Throwable) { null }
            if (circuitJson != null && circuitJson != lastRenderedCircuit) {
                renderCircuitRoute(circuitJson)
                lastRenderedCircuit = circuitJson
            }

        } catch (_: Exception) {
            // Service may not be bound yet — indicator stays at its previous state.
        }
    }

    private fun renderCircuitPlaceholders() {
        // Three hops is the common Arti HS-client case (Entry / Middle / Rendezvous).
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

        // Arti's path can include a trailing virtual hop representing the HS endpoint,
        // which we skip in Rust (only Relay hops get pushed). That means the role
        // assigned in Rust ("Middle Node") for our final real hop is stale — the real
        // last hop is actually the rendezvous relay. We relabel it here instead of in
        // Rust so the fix doesn't require a 3-ABI rebuild on each iteration.
        val parsedHops = mutableListOf<JSONObject>()
        for (i in 0 until hops.length()) {
            hops.optJSONObject(i)?.let { parsedHops.add(it) }
        }

        circuitRouteContainer.removeAllViews()
        for ((index, h) in parsedHops.withIndex()) {
            val rawRole = h.optString("role", "Hop")
            // Last real hop on a client→HS circuit is the rendezvous relay.
            val role = if (index == parsedHops.size - 1 && parsedHops.size > 1) {
                "Rendezvous Point"
            } else {
                rawRole
            }
            val fp = h.optString("fp", "")
            val nickname = h.optString("nickname", "").takeIf { it.isNotBlank() }
            val countryCode = h.optString("country", "").takeIf { it.isNotBlank() }
            val ip = h.optString("ip", "").takeIf { it.isNotBlank() }

            // Convert 2-letter ISO code (e.g. "DE") to the user's localized country name
            // (e.g. "Germany" in en-US, "Deutschland" in de-DE). Falls back to the raw
            // code if the locale lookup returns blank or just echoes the code — which
            // happens only for unrecognized / obscure codes.
            val country = countryCode?.let { code ->
                val name = java.util.Locale("", code).displayCountry
                if (name.isNotBlank() && !name.equals(code, ignoreCase = true)) name else code
            }

            // Country slot is ALWAYS country-shaped — nicknames never leak here. "Anonymous"
            // mirrors Tor's own vocabulary ("we exclude pseudo-countries A1–An for anonymous
            // proxies") — more accurate than "Unknown" since the relay IS anonymizing.
            val location = country ?: "Anonymous"
            val secondary = nickname
            val fingerprintShort = if (fp.length >= 16) fp.substring(0, 16) + "…" else fp

            val card = makeHopCard(role, location, secondary, fingerprintShort)
            card.setOnClickListener {
                showHopDetailSheet(role, nickname, ip, location, fp)
            }
            circuitRouteContainer.addView(card)
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
        card.isClickable = true
        card.isFocusable = true
        return card
    }

    /**
     * Detail sheet mirrors iOS's "Entry Node" sheet (Relay Name, IP, Fingerprint)
     * and adds Country, which iOS omits. Missing fields render as "Anonymous" —
     * more accurate than "Unknown" since Tor relays exist to anonymize.
     */
    private fun showHopDetailSheet(
        role: String,
        nickname: String?,
        ip: String?,
        country: String,
        fullFingerprint: String
    ) {
        val sheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_hop_detail, null)
        sheet.setContentView(view)

        sheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        sheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        view.findViewById<TextView>(R.id.hopDetailRole).text = role
        view.findViewById<TextView>(R.id.hopDetailRelayName).text = nickname ?: "Anonymous"
        view.findViewById<TextView>(R.id.hopDetailIp).text = ip ?: "Anonymous"
        view.findViewById<TextView>(R.id.hopDetailCountry).text = country
        view.findViewById<TextView>(R.id.hopDetailFingerprint).text =
            if (fullFingerprint.isNotBlank()) fullFingerprint else "Anonymous"
        view.findViewById<View>(R.id.hopDetailClose).setOnClickListener { sheet.dismiss() }

        sheet.show()
    }
}
