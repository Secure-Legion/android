package com.securelegion

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.services.TorVpnService
import com.securelegion.utils.BiometricAuthHelper
import com.securelegion.utils.ThemedToast

class SettingsActivity : BaseActivity() {

    private lateinit var biometricHelper: BiometricAuthHelper
    private lateinit var torModeSwitch: SwitchCompat

    // VPN permission launcher
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // Permission granted, start VPN service
            startTorVpnService()
        } else {
            // Permission denied, turn off switch
            torModeSwitch.isChecked = false
            ThemedToast.show(this, "VPN permission denied")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        biometricHelper = BiometricAuthHelper(this)

        setupBottomNavigation()
        setupClickListeners()
        setupAutoWipeToggle()
        setupBiometricToggle()
        setupTorModeToggle()
    }

    private fun setupClickListeners() {
        // Back Button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Duress PIN
        findViewById<View>(R.id.duressPinItem).setOnClickListener {
            startActivity(Intent(this, DuressPinActivity::class.java))
        }

        // Device Password
        findViewById<View>(R.id.devicePasswordItem).setOnClickListener {
            startActivity(Intent(this, DevicePasswordActivity::class.java))
        }

        // Notifications
        findViewById<View>(R.id.notificationsItem).setOnClickListener {
            startActivity(Intent(this, NotificationsActivity::class.java))
        }

        // About
        findViewById<View>(R.id.aboutItem).setOnClickListener {
            startActivity(Intent(this, AboutActivity::class.java))
        }

        // Wipe Account
        findViewById<View>(R.id.wipeAccountButton).setOnClickListener {
            startActivity(Intent(this, WipeAccountActivity::class.java))
        }

        // Bridge
        findViewById<View>(R.id.bridgeItem).setOnClickListener {
            startActivity(Intent(this, BridgeActivity::class.java))
        }

        // Developer (master flavor only)
        val developerItem = findViewById<View>(R.id.developerItem)
        if (BuildConfig.ENABLE_DEVELOPER_MENU) {
            developerItem.setOnClickListener {
                startActivity(Intent(this, DeveloperActivity::class.java))
            }
        } else {
            developerItem.visibility = View.GONE
        }

        // Security Mode (includes auto-lock timer)
        findViewById<View>(R.id.securityModeItem).setOnClickListener {
            startActivity(Intent(this, SecurityModeActivity::class.java))
        }
    }

    private fun setupAutoWipeToggle() {
        val autoWipeSwitch = findViewById<SwitchCompat>(R.id.autoWipeSwitch)
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)

        // Load saved state (default off)
        autoWipeSwitch.isChecked = prefs.getBoolean("auto_wipe_enabled", false)

        // Save state when toggled
        autoWipeSwitch.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("auto_wipe_enabled", isChecked).apply()

            // Reset failed attempts counter when toggling
            if (!isChecked) {
                prefs.edit().putInt("failed_password_attempts", 0).apply()
            }
        }
    }

    private fun setupBiometricToggle() {
        val biometricItem = findViewById<LinearLayout>(R.id.biometricItem)
        val biometricSwitch = findViewById<SwitchCompat>(R.id.biometricSwitch)

        // Check if biometric hardware is available
        when (biometricHelper.isBiometricAvailable()) {
            BiometricAuthHelper.BiometricStatus.AVAILABLE -> {
                // Show biometric toggle
                biometricItem.visibility = View.VISIBLE

                // Load current state
                val isCurrentlyEnabled = biometricHelper.isBiometricEnabled()
                biometricSwitch.isChecked = isCurrentlyEnabled

                // Handle toggle - prevent listener from firing during programmatic changes
                var isUserInteraction = true
                biometricSwitch.setOnCheckedChangeListener { _, isChecked ->
                    if (!isUserInteraction) return@setOnCheckedChangeListener

                    if (isChecked) {
                        // User wants to enable - show biometric prompt
                        enableBiometric()
                    } else {
                        // User wants to disable - just disable it
                        disableBiometric()
                    }
                }
            }
            BiometricAuthHelper.BiometricStatus.NONE_ENROLLED -> {
                // Show item but disabled
                biometricItem.visibility = View.VISIBLE
                biometricSwitch.isEnabled = false
                Log.d("SettingsActivity", "Biometric not enrolled - showing disabled toggle")
            }
            else -> {
                // Hide biometric option if no hardware
                biometricItem.visibility = View.GONE
                Log.d("SettingsActivity", "No biometric hardware - hiding toggle")
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Refresh biometric toggle state when returning to settings
        refreshBiometricToggle()
    }

    private fun refreshBiometricToggle() {
        val biometricSwitch = findViewById<SwitchCompat>(R.id.biometricSwitch)
        val isEnabled = biometricHelper.isBiometricEnabled()

        // Update switch to match actual state (without triggering listener)
        biometricSwitch.setOnCheckedChangeListener(null)
        biometricSwitch.isChecked = isEnabled

        // Re-attach listener
        biometricSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                enableBiometric()
            } else {
                disableBiometric()
            }
        }
    }

    private fun enableBiometric() {
        val biometricSwitch = findViewById<SwitchCompat>(R.id.biometricSwitch)

        try {
            val keyManager = KeyManager.getInstance(this)
            val passwordHash = keyManager.getPasswordHash()

            if (passwordHash == null) {
                ThemedToast.show(this, "Password not set")
                biometricSwitch.isChecked = false
                return
            }

            biometricHelper.enableBiometric(
                passwordHash = passwordHash,
                activity = this,
                onSuccess = {
                    Log.i("SettingsActivity", "Biometric enabled successfully")
                    ThemedToast.show(this, "Biometric unlock enabled")
                },
                onError = { error ->
                    Log.e("SettingsActivity", "Failed to enable biometric: $error")
                    ThemedToast.showLong(this, "Failed to enable: $error")
                    biometricSwitch.isChecked = false
                }
            )
        } catch (e: Exception) {
            Log.e("SettingsActivity", "Error enabling biometric", e)
            ThemedToast.show(this, "Error: ${e.message}")
            biometricSwitch.isChecked = false
        }
    }

    private fun disableBiometric() {
        val biometricSwitch = findViewById<SwitchCompat>(R.id.biometricSwitch)

        try {
            biometricHelper.disableBiometric()
            Log.i("SettingsActivity", "Biometric disabled")
            ThemedToast.show(this, "Biometric unlock disabled")
        } catch (e: Exception) {
            Log.e("SettingsActivity", "Error disabling biometric", e)
            ThemedToast.show(this, "Error: ${e.message}")
            biometricSwitch.isChecked = true
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navPhone).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_PHONE", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }
    }

    private fun setupTorModeToggle() {
        torModeSwitch = findViewById(R.id.torModeSwitch)
        val prefs = getSharedPreferences("tor_prefs", MODE_PRIVATE)

        // Load current state
        val isTorModeEnabled = TorVpnService.isRunning()
        torModeSwitch.isChecked = isTorModeEnabled

        // Handle toggle
        torModeSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                // User wants to enable Tor Mode - request VPN permission
                requestVpnPermission()
            } else {
                // User wants to disable Tor Mode - stop VPN service
                stopTorVpnService()
            }
        }
    }

    private fun requestVpnPermission() {
        // Check if VPN permission is already granted
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            // Permission already granted, start VPN immediately
            startTorVpnService()
        } else {
            // Need to request permission
            vpnPermissionLauncher.launch(prepareIntent)
        }
    }

    private fun startTorVpnService() {
        try {
            Log.i("SettingsActivity", "Starting Tor VPN service...")
            val intent = Intent(this, TorVpnService::class.java).apply {
                action = TorVpnService.ACTION_START_VPN
            }
            startService(intent)
            ThemedToast.show(this, "Tor Mode enabled - All traffic routed through Tor")
        } catch (e: Exception) {
            Log.e("SettingsActivity", "Failed to start Tor VPN", e)
            ThemedToast.show(this, "Failed to start Tor Mode: ${e.message}")
            torModeSwitch.isChecked = false
        }
    }

    private fun stopTorVpnService() {
        try {
            Log.i("SettingsActivity", "Stopping Tor VPN service...")
            val intent = Intent(this, TorVpnService::class.java).apply {
                action = TorVpnService.ACTION_STOP_VPN
            }
            startService(intent)
            ThemedToast.show(this, "Tor Mode disabled")
        } catch (e: Exception) {
            Log.e("SettingsActivity", "Failed to stop Tor VPN", e)
            ThemedToast.show(this, "Failed to stop Tor Mode: ${e.message}")
        }
    }
}
