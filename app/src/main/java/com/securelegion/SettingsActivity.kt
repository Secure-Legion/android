package com.securelegion

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.appcompat.widget.SwitchCompat
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.crypto.KeyManager
import com.securelegion.services.TorVpnService
import com.securelegion.utils.BiometricAuthHelper
import com.securelegion.utils.GlassDialog
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
            // Permission denied, revert the switch without firing the listener
            // (we never started the VPN, so stopTorVpnService would be a no-op anyway)
            suppressTorModeListener = true
            torModeSwitch.isChecked = false
            suppressTorModeListener = false
            ThemedToast.show(this, "VPN permission denied")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        biometricHelper = BiometricAuthHelper(this)

        setupBottomNavigation()
        setupClickListeners()
        setupTorModeToggle()
        // setupAutoWipeToggle() and setupBiometricToggle() moved to SecurityModeActivity
    }

    private fun setupClickListeners() {
        // Back Button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Premium Features
        findViewById<View>(R.id.premiumFeaturesItem)?.setOnClickListener {
            startActivity(Intent(this, PremiumActivity::class.java))
        }

        // Help
        findViewById<View>(R.id.helpItem)?.setOnClickListener {
            startActivity(Intent(this, HelpActivity::class.java))
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

        // Communication Mode
        findViewById<View>(R.id.communicationModeItem).setOnClickListener {
            startActivity(Intent(this, CommunicationModeActivity::class.java))
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

        // Tor Health
        findViewById<View>(R.id.torHealthItem).setOnClickListener {
            startActivity(Intent(this, TorHealthActivity::class.java))
        }

        // QR Code Settings
        findViewById<View>(R.id.qrSettingsItem).setOnClickListener {
            startActivity(Intent(this, QrSettingsActivity::class.java))
        }

        // Appearance
        findViewById<View>(R.id.appearanceItem).setOnClickListener {
            startActivity(Intent(this, AppearanceActivity::class.java))
        }

        // Devices
        findViewById<View>(R.id.devicesItem).setOnClickListener {
            startActivity(Intent(this, DevicesActivity::class.java))
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
        updatePasswordLabel()
    }

    private fun updatePasswordLabel() {
        val keyManager = KeyManager.getInstance(this)
        val label = findViewById<TextView>(R.id.devicePasswordLabel)
        if (keyManager.hasUserDefinedPassword()) {
            label?.text = "Change Password"
        } else {
            label?.text = "Set Password"
        }
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
            // Need the actual password (not hash) to derive the seed-wrapping key on unlock.
            // For system-generated passwords we can retrieve it; for user-defined passwords
            // the user must re-enter it (handled by Task 8 settings flow).
            val password = keyManager.getSystemPassword()

            if (password == null) {
                ThemedToast.show(this, "Please re-enter your password to enable biometric")
                biometricSwitch.isChecked = false
                return
            }

            biometricHelper.enableBiometric(
                password = password,
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
        BottomNavigationHelper.setupBottomNavigation(this)
    }

    // Suppresses the toggle listener while we programmatically revert the switch
    // after a cancelled confirmation — otherwise revertering OFF would trigger
    // stopTorVpnService() on a VPN that was never started.
    private var suppressTorModeListener = false

    private fun setupTorModeToggle() {
        torModeSwitch = findViewById(R.id.torModeSwitch)

        // Load current state
        val isTorModeEnabled = TorVpnService.isRunning()
        torModeSwitch.isChecked = isTorModeEnabled

        // Handle toggle
        torModeSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (suppressTorModeListener) return@setOnCheckedChangeListener
            if (isChecked) {
                // Confirm intent before triggering Android's own mandatory VPN consent dialog.
                // Android's prompt ("App will monitor network traffic") is generic and scary;
                // our pre-warn explains what the switch actually does.
                confirmEnableTorVpn()
            } else {
                stopTorVpnService()
            }
        }
    }

    private fun confirmEnableTorVpn() {
        val dialog = GlassDialog.builder(this)
            .setTitle("Enable Tor VPN?")
            .setMessage("This is a system-wide VPN. Every app on your phone — browser, email, games, everything — will route through the Tor network while it's on. Other apps will be noticeably slower and some may fail to connect.\n\nAndroid will ask you to approve a VPN connection on the next screen. You can turn this off any time from Settings.")
            .setPositiveButton("Continue") { _, _ ->
                requestVpnPermission()
            }
            .setNegativeButton("Cancel") { _, _ ->
                suppressTorModeListener = true
                torModeSwitch.isChecked = false
                suppressTorModeListener = false
            }
            .setOnCancelListener {
                suppressTorModeListener = true
                torModeSwitch.isChecked = false
                suppressTorModeListener = false
            }
            .create()
        GlassDialog.show(dialog)
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
            suppressTorModeListener = true
            torModeSwitch.isChecked = false
            suppressTorModeListener = false
        }
    }

    private fun stopTorVpnService() {
        try {
            Log.i("SettingsActivity", "Stopping Tor VPN service...")
            // Send stop action so stopVpn() runs cleanup (OnionMasq.stop, etc.)
            val intent = Intent(this, TorVpnService::class.java).apply {
                action = TorVpnService.ACTION_STOP_VPN
            }
            startService(intent)
            // Also call stopService() to ensure the service is destroyed
            // onDestroy() has safety-net cleanup in case the stop action didn't complete
            stopService(Intent(this, TorVpnService::class.java))
            ThemedToast.show(this, "Tor Mode disabled")
        } catch (e: Exception) {
            Log.e("SettingsActivity", "Failed to stop Tor VPN", e)
            ThemedToast.show(this, "Failed to stop Tor Mode: ${e.message}")
        }
    }

    private fun showAppearanceSheet() {
        val sheetView = layoutInflater.inflate(R.layout.bottom_sheet_appearance, null)
        val dialog = BottomSheetDialog(this)
        dialog.setContentView(sheetView)

        val prefs = getSharedPreferences("app_settings", MODE_PRIVATE)
        val currentMode = prefs.getString("app_theme_mode", "system") ?: "system"

        val radioDark = sheetView.findViewById<RadioButton>(R.id.radioDark)
        val radioLight = sheetView.findViewById<RadioButton>(R.id.radioLight)
        val radioSystem = sheetView.findViewById<RadioButton>(R.id.radioSystem)

        when (currentMode) {
            "dark" -> radioDark.isChecked = true
            "light" -> radioLight.isChecked = true
            "system" -> radioSystem.isChecked = true
        }

        fun applyTheme(mode: String) {
            prefs.edit().putString("app_theme_mode", mode).apply()
            when (mode) {
                "dark" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
                "light" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
                "system" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
            }
            dialog.dismiss()
        }

        sheetView.findViewById<View>(R.id.optionDark).setOnClickListener {
            radioDark.isChecked = true
            applyTheme("dark")
        }
        sheetView.findViewById<View>(R.id.optionLight).setOnClickListener {
            radioLight.isChecked = true
            applyTheme("light")
        }
        sheetView.findViewById<View>(R.id.optionSystem).setOnClickListener {
            radioSystem.isChecked = true
            applyTheme("system")
        }

        dialog.show()
    }

}
