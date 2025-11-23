package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.BiometricAuthHelper
import com.securelegion.utils.ThemedToast

class SettingsActivity : BaseActivity() {

    private lateinit var biometricHelper: BiometricAuthHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        biometricHelper = BiometricAuthHelper(this)

        BottomNavigationHelper.setupBottomNavigation(this)
        setupClickListeners()
        setupAutoWipeToggle()
        setupBiometricToggle()
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Duress PIN
        findViewById<View>(R.id.duressPinItem).setOnClickListener {
            startActivity(Intent(this, DuressPinActivity::class.java))
        }

        // Wallet Identity
        findViewById<View>(R.id.walletIdentityItem).setOnClickListener {
            startActivity(Intent(this, WalletIdentityActivity::class.java))
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
        val biometricSubtext = findViewById<TextView>(R.id.biometricSubtext)

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
                // Show item but disabled with message
                biometricItem.visibility = View.VISIBLE
                biometricSwitch.isEnabled = false
                biometricSubtext.text = "No fingerprint/face enrolled on device"
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
}
