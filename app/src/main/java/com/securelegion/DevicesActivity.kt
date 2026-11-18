package com.securelegion

import android.app.AlertDialog
import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.ImageView
import androidx.lifecycle.lifecycleScope
import androidx.activity.result.contract.ActivityResultContracts
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.sync.DeviceRosterAuthority
import com.securelegion.sync.DeviceEnrollmentOwnerCoordinator
import com.securelegion.sync.NearbyHistoryClient
import com.securelegion.sync.NearbyHistoryServer
import com.securelegion.utils.BrandedQrGenerator
import com.securelegion.utils.SessionManager
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Displays only devices authorized by the current account-signed roster. */
class DevicesActivity : BaseActivity() {
    private data class RosterView(val primaryId: String, val devices: List<DeviceRosterStore.DeviceView>)
    private var currentRoster: RosterView? = null
    private var busy = false
    private var shownCode: String? = null
    @Volatile private var historyClient: NearbyHistoryClient? = null
    @Volatile private var historyServer: NearbyHistoryServer? = null
    private var historyDialog: AlertDialog? = null
    private val scanHistory = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        result ->
        if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult
        val raw = result.data?.getStringExtra("SCANNED_ADDRESS") ?: return@registerForActivityResult
        AlertDialog.Builder(this).setTitle("Copy history over Wi-Fi?")
            .setMessage("Send encrypted history to your authorized Desktop on this local network?")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Copy history") { _, _ -> copyNearbyHistory(raw) }
            .show()
    }
    private val scanCandidate = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        result ->
        if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult
        val qr = result.data?.getStringExtra("SCANNED_ADDRESS") ?: return@registerForActivityResult
        lifecycleScope.launch {
            val started = withContext(Dispatchers.IO) {
                runCatching { DeviceEnrollmentOwnerCoordinator.start(this@DevicesActivity, qr) }
            }
            ThemedToast.show(this@DevicesActivity, if (started.isSuccess)
                "Waiting for the candidate device" else
                started.exceptionOrNull()?.message?.take(100) ?: "Could not start linking")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_devices)
        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<TextView>(R.id.deviceName).text = Build.MODEL ?: "Android"
        findViewById<TextView>(R.id.deviceSubtitle).text = "Secure Android ${Build.VERSION.RELEASE}"
        findViewById<View>(R.id.linkDeviceButton).setOnClickListener {
            if (DeviceEnrollmentOwnerCoordinator.state.value.phase !=
                DeviceEnrollmentOwnerCoordinator.Phase.IDLE) {
                AlertDialog.Builder(this).setTitle("Cancel device linking?")
                    .setMessage("The current comparison and approval will be discarded.")
                    .setNegativeButton("Keep waiting", null)
                    .setPositiveButton("Cancel linking") { _, _ ->
                        DeviceEnrollmentOwnerCoordinator.cancel()
                    }.show()
            } else scanCandidate.launch(Intent(this, QRScannerActivity::class.java))
        }
        findViewById<View>(R.id.copyHistoryButton).setOnClickListener {
            if (busy) {
                historyClient?.cancel()
            } else scanHistory.launch(Intent(this, QRScannerActivity::class.java))
        }
        findViewById<View>(R.id.receiveHistoryButton).setOnClickListener {
            if (busy) {
                historyServer?.close()
            } else chooseHistorySource()
        }
        lifecycleScope.launch {
            DeviceEnrollmentOwnerCoordinator.state.collect { renderEnrollment(it) }
        }
        findViewById<View>(R.id.terminateSessionsRow).setOnClickListener {
            val others = currentRoster?.devices?.filter { !it.isSelf }.orEmpty()
            if (busy || others.isEmpty()) return@setOnClickListener
            val localId = currentRoster?.devices?.firstOrNull { it.isSelf }?.deviceId
            if (currentRoster?.primaryId != localId) {
                ThemedToast.show(this, "Only the primary device can revoke others")
                return@setOnClickListener
            }
            AlertDialog.Builder(this)
                .setTitle("Revoke other devices?")
                .setMessage("This signs a new roster and stops those devices from syncing. Re-linking requires a new approval.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Revoke") { _, _ -> revokeOthers(others.map { it.deviceId }.toSet()) }
                .show()
        }
    }

    private fun renderEnrollment(state: DeviceEnrollmentOwnerCoordinator.State) {
        when (state.phase) {
            DeviceEnrollmentOwnerCoordinator.Phase.COMPARE -> {
                if (shownCode == state.comparisonCode) return
                shownCode = state.comparisonCode
                AlertDialog.Builder(this)
                    .setTitle("Compare device codes")
                    .setMessage("Confirm ${state.candidateName} shows the same code:\n\n" +
                        state.comparisonCode + "\n\nApprove only if both screens match.")
                    .setNegativeButton("Codes differ") { _, _ ->
                        DeviceEnrollmentOwnerCoordinator.cancel()
                    }
                    .setPositiveButton("Codes match") { _, _ ->
                        lifecycleScope.launch {
                            val approved = withContext(Dispatchers.IO) {
                                runCatching { DeviceEnrollmentOwnerCoordinator.approve(this@DevicesActivity) }
                            }
                            if (approved.isFailure) ThemedToast.show(this@DevicesActivity,
                                approved.exceptionOrNull()?.message?.take(100) ?: "Approval failed")
                        }
                    }.show()
            }
            DeviceEnrollmentOwnerCoordinator.Phase.COMPLETE -> {
                shownCode = null
                ThemedToast.show(this, "Device linked")
                refreshRoster()
            }
            DeviceEnrollmentOwnerCoordinator.Phase.IDLE -> shownCode = null
            else -> Unit
        }
    }

    override fun onResume() {
        super.onResume()
        refreshRoster()
    }

    override fun onStop() {
        historyClient?.cancel()
        historyServer?.close()
        historyDialog?.dismiss()
        historyDialog = null
        super.onStop()
    }

    private fun chooseHistorySource() {
        val devices = currentRoster?.devices?.filter { !it.isSelf }.orEmpty()
        if (devices.isEmpty()) {
            ThemedToast.show(this, "Link another device before receiving history")
            return
        }
        AlertDialog.Builder(this).setTitle("Receive history from")
            .setItems(devices.map { it.displayName }.toTypedArray()) { _, which ->
                receiveNearbyHistory(devices[which].deviceId)
            }.show()
    }

    private fun receiveNearbyHistory(peerId: String) {
        if (busy) return
        busy = true
        val button = findViewById<TextView>(R.id.receiveHistoryButton)
        button.text = "Preparing secure QR…"
        lifecycleScope.launch {
            val opened = withContext(Dispatchers.IO) {
                runCatching { NearbyHistoryServer.open(this@DevicesActivity, peerId) }
            }
            if (opened.isFailure || !SessionManager.isUnlocked(this@DevicesActivity)) {
                opened.getOrNull()?.close()
                busy = false
                button.text = "Receive history over Wi-Fi"
                ThemedToast.show(this@DevicesActivity,
                    opened.exceptionOrNull()?.message?.take(100) ?: "Session locked")
                return@launch
            }
            val server = opened.getOrThrow()
            historyServer = server
            val qr = ImageView(this@DevicesActivity).apply {
                setPadding(24.dp, 24.dp, 24.dp, 24.dp)
                setImageBitmap(BrandedQrGenerator.generate(this@DevicesActivity,
                    BrandedQrGenerator.QrOptions(server.offer, size = 640,
                        showLogo = false)))
                contentDescription = "Secure Nearby history QR"
            }
            historyDialog = AlertDialog.Builder(this@DevicesActivity)
                .setTitle("Scan on your other device")
                .setView(qr)
                .setMessage("Keep both devices on the same Wi-Fi network.")
                .setNegativeButton("Stop") { _, _ -> server.close() }
                .create().also { it.show() }
            val result = withContext(Dispatchers.IO) {
                runCatching { server.run { message ->
                    runOnUiThread { button.text = "Stop transfer · $message" }
                } }
            }
            historyServer = null
            server.close()
            historyDialog?.dismiss()
            historyDialog = null
            busy = false
            button.text = "Receive history over Wi-Fi"
            if (!isFinishing && !isDestroyed) {
                val message = result.fold(
                    onSuccess = { "Imported ${it.imported} updates; ${it.deferred} deferred." },
                    onFailure = { it.message?.take(120) ?: "History transfer stopped" })
                AlertDialog.Builder(this@DevicesActivity).setTitle("History transfer")
                    .setMessage(message).setPositiveButton("OK", null).show()
            }
        }
    }

    private fun store(keys: KeyManager) = DeviceRosterStore(
        SecureLegionDatabase.getInstance(this, keys.getDatabasePassphrase())
    )

    private fun refreshRoster() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    check(SessionManager.isUnlocked(this@DevicesActivity))
                    val keys = KeyManager.getInstance(this@DevicesActivity)
                    val account = keys.getSigningPublicKey()
                    val rosterStore = store(keys)
                    val roster = rosterStore.fetchSignedRoster(account) ?: return@runCatching null
                    val verified = JSONObject(RustBridge.deviceAuthorization(
                        JSONObject().put("operation", "verify_roster")
                            .put("roster", Base64.encodeToString(roster, Base64.NO_WRAP))
                            .put("pinned_account", Base64.encodeToString(account, Base64.NO_WRAP))
                            .put("previous_roster", JSONObject.NULL)
                            .put("now_ms", System.currentTimeMillis())
                            .put("authorize", JSONObject.NULL)
                            .toString().toByteArray(Charsets.UTF_8), null
                    ).toString(Charsets.UTF_8))
                    RosterView(verified.getString("primary_device_id"),
                        rosterStore.listAuthorizedDevices(account).filter { it.expiresAtMs > System.currentTimeMillis() })
                }.getOrNull()
            }
            currentRoster = result
            val others = result?.devices?.filter { !it.isSelf }.orEmpty()
            val container = findViewById<LinearLayout>(R.id.otherDevicesContainer)
            container.removeAllViews()
            for (device in others) {
                val row = TextView(this@DevicesActivity).apply {
                    text = "${device.displayName}\nAuthorized device · ${device.deviceId.take(10)}…"
                    setTextColor(android.graphics.Color.WHITE)
                    textSize = 15f
                    setPadding(16.dp, 12.dp, 16.dp, 12.dp)
                    setBackgroundResource(R.drawable.device_card_bg)
                }
                container.addView(row, LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = 8.dp })
            }
            findViewById<TextView>(R.id.noOtherDevicesText).text = when {
                result == null -> "No signed device roster is available yet."
                others.isEmpty() -> "No other devices are currently authorized."
                else -> "${others.size} other authorized ${if (others.size == 1) "device" else "devices"}."
            }
            findViewById<View>(R.id.terminateSessionsRow).isEnabled = !busy && others.isNotEmpty() &&
                result?.primaryId == result?.devices?.firstOrNull { it.isSelf }?.deviceId
        }
    }

    private fun revokeOthers(ids: Set<String>) {
        if (busy || ids.isEmpty()) return
        busy = true
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    check(SessionManager.isUnlocked(this@DevicesActivity))
                    val keys = KeyManager.getInstance(this@DevicesActivity)
                    LocalDeviceIdentity.loadExisting(this@DevicesActivity).use { identity ->
                        DeviceRosterAuthority(store(keys)).revoke(keys, identity, ids)
                    }
                }
            }
            busy = false
            ThemedToast.show(this@DevicesActivity, if (result.isSuccess) "Other devices revoked"
                else "Could not revoke devices")
            refreshRoster()
        }
    }

    private fun copyNearbyHistory(raw: String) {
        if (busy) return
        busy = true
        findViewById<TextView>(R.id.copyHistoryButton).text = "Connecting securely…"
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    check(SessionManager.isUnlocked(this@DevicesActivity))
                    val keys = KeyManager.getInstance(this@DevicesActivity)
                    val database = SecureLegionDatabase.getInstance(this@DevicesActivity,
                        keys.getDatabasePassphrase())
                    val client = NearbyHistoryClient(this@DevicesActivity, keys, database)
                    historyClient = client
                    client.run(raw) { message ->
                        runOnUiThread {
                            findViewById<TextView>(R.id.copyHistoryButton).text =
                                "Stop transfer · $message"
                        }
                    }
                }
            }
            busy = false
            historyClient = null
            findViewById<TextView>(R.id.copyHistoryButton).text = "Copy history over Wi-Fi"
            val message = result.fold(
                onSuccess = { "Copied ${it.copied} updates; ${it.remaining} remain." },
                onFailure = { it.message?.take(120) ?: "History transfer failed" })
            AlertDialog.Builder(this@DevicesActivity).setTitle("History transfer")
                .setMessage(message).setPositiveButton("OK", null).show()
        }
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
}
