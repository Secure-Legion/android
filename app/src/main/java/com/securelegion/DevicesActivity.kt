package com.securelegion

import android.app.AlertDialog
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.sync.DeviceRosterAuthority
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_devices)
        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<TextView>(R.id.deviceName).text = Build.MODEL ?: "Android"
        findViewById<TextView>(R.id.deviceSubtitle).text = "Secure Android ${Build.VERSION.RELEASE}"
        findViewById<View>(R.id.linkDeviceButton).setOnClickListener {
            ThemedToast.show(this, "Device linking is not available in this build")
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

    override fun onResume() {
        super.onResume()
        refreshRoster()
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

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
}
