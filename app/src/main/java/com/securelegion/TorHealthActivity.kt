package com.securelegion

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.RustBridge
import com.securelegion.services.TorService
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    private lateinit var networkStatusText: TextView
    private lateinit var networkBootstrapText: TextView
    private lateinit var networkCircuitText: TextView
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
        networkStatusText = findViewById(R.id.networkStatusText)
        networkBootstrapText = findViewById(R.id.networkBootstrapText)
        networkCircuitText = findViewById(R.id.networkCircuitText)
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
            lifecycleScope.launch {
                val ok = withContext(Dispatchers.IO) {
                    try { RustBridge.sendNewnym() } catch (_: Throwable) { false }
                }
                ThemedToast.show(
                    this@TorHealthActivity,
                    if (ok) "New circuit requested; retrying queued messages" else "Unable to rotate circuits right now"
                )
                v.isEnabled = true

                if (ok) {
                    // Failure streaks describe the old circuit graph. A manual rotation should
                    // not leave those process-local gates suppressing the first fresh attempt.
                    com.securelegion.services.MessageService.clearAllRetryableFailureState()
                    com.securelegion.network.ArtiPeerHealthGate.resetAll()

                    withContext(Dispatchers.IO) {
                        delay(1_500L)
                        val result = com.securelegion.services.MessageService(applicationContext)
                            .flushNow(aggressive = true, reason = "manual-new-circuit")
                        if (result.isSuccess) {
                            Log.i(TAG, "New Circuit queued-message retry sent=${result.getOrDefault(0)}")
                        } else {
                            Log.w(TAG, "New Circuit queued-message retry failed: ${result.exceptionOrNull()?.message}")
                        }
                    }
                }
            }
        }

        // Reset Tor State button — escalation above NEWNYM. Wipes Arti's
        // poisoned guard / circuit-timeout / dirmgr files and re-bootstraps.
        // Preserves the HS keystore so the user's .onion stays the same.
        findViewById<View>(R.id.resetTorStateButton).setOnClickListener { v ->
            confirmResetTorState(v)
        }

    }

    private fun confirmResetTorState(triggerView: View) {
        // Use create() + GlassDialog.show() so the OnShowListener strips Material3
        // inner panel backgrounds — matches the styling of confirmDisableTorNetwork
        // below. Calling the builder's own .show() leaves the panel boxing visible.
        val dialog = com.securelegion.utils.GlassDialog.builder(this)
            .setTitle("Reset Tor state?")
            .setMessage("Wipes guard / circuit-timeout state and re-bootstraps Tor. Use only if New Circuit didn't fix things. Your account, contacts, and .onion address are preserved.")
            .setPositiveButton("Reset") { _, _ -> performResetTorState(triggerView) }
            .setNegativeButton("Cancel", null)
            .create()
        com.securelegion.utils.GlassDialog.show(dialog)
    }

    private fun performResetTorState(triggerView: View) {
        triggerView.isEnabled = false
        ThemedToast.show(this, "Resetting Tor state…")
        // Delegate to TorService so the reset uses the same orchestration as
        // the auto-detector (avoids two divergent reset code paths).
        val intent = android.content.Intent(this, com.securelegion.services.TorService::class.java)
        intent.action = com.securelegion.services.TorService.ACTION_RESET_TOR_STATE
        startService(intent)
        triggerView.postDelayed({ triggerView.isEnabled = true }, 5_000)
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
        // Cancel the periodic health monitor so it doesn't keep poking a stopped
        // service and leaving stale proof/heartbeat state while the user has Tor off.
        try {
            androidx.work.WorkManager.getInstance(this).cancelUniqueWork("tor_health_monitor")
        } catch (_: Throwable) { /* best-effort */ }
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
            // Kick the health monitor IMMEDIATELY. Its first run is a OneTimeWork that
            // fires as soon as WorkManager schedules it, which runs an HS self-test +
            // calls setTorProofOk() on success. Without this kick, proof state stays
            // pre-toggle (or zero on a fresh process) and the Connected indicator
            // never turns green even though the transport is back.
            try {
                com.securelegion.workers.TorHealthMonitorWorker.schedulePeriodicCheck(this)
            } catch (e: Throwable) {
                android.util.Log.w(TAG, "Failed to kick health monitor after toggle-on", e)
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
                networkStatusText.text = "Off"
                networkStatusText.setTextColor(0xFFAAAAAA.toInt())
                networkBootstrapText.text = "—"
                networkCircuitText.text = "—"
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

            // Populate the three diagnostic rows — shows the user exactly which component
            // is lagging when the "Connected" indicator disagrees with perceived reachability.
            networkBootstrapText.text = "$bootstrapPercent%"
            networkBootstrapText.setTextColor(
                if (bootstrapPercent >= 100) 0xFF00CC66.toInt() else 0xFFFFAA00.toInt()
            )
            networkCircuitText.text = if (circuitsEstablished == 1) "Established" else "Pending"
            networkCircuitText.setTextColor(
                if (circuitsEstablished == 1) 0xFF00CC66.toInt() else 0xFFFFAA00.toInt()
            )
            when {
                !hasInternet -> {
                    networkStatusText.text = "Offline"
                    networkStatusText.setTextColor(0xFFFF6666.toInt())
                }
                isLive -> {
                    networkStatusText.text = "Connected"
                    networkStatusText.setTextColor(0xFF00CC66.toInt())
                }
                else -> {
                    networkStatusText.text = "Connecting"
                    networkStatusText.setTextColor(0xFFFFAA00.toInt())
                }
            }

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
                val name = java.util.Locale.Builder().setRegion(code).build().displayCountry
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
