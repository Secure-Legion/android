package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.LinearLayout
import androidx.appcompat.widget.SwitchCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.BiometricAuthHelper
import com.securelegion.utils.ThemedToast

class SecurityModeActivity : BaseActivity() {

    companion object {
        const val PREF_ALLOW_INCOMING_CALLS_WHEN_CLOSED = "allow_incoming_calls_when_closed"
        const val PREF_DEVICE_PROTECTION_ENABLED = "device_protection_enabled"
    }

    private lateinit var biometricHelper: BiometricAuthHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_security_mode)

        biometricHelper = BiometricAuthHelper(this)

        setupClickListeners()
        setupAutoLock()
        setupBiometricToggle()
        setupAutoWipeToggle()
        updatePasswordLabel()
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.backButton).setOnClickListener { finish() }

        findViewById<View>(R.id.devicePasswordItem).setOnClickListener {
            startActivity(Intent(this, DevicePasswordActivity::class.java))
        }

        findViewById<View>(R.id.duressPinItem).setOnClickListener {
            startActivity(Intent(this, DuressPinActivity::class.java))
        }

        findViewById<View>(R.id.qrSettingsItem).setOnClickListener {
            startActivity(Intent(this, QrSettingsActivity::class.java))
        }
    }

    private fun updatePasswordLabel() {
        val keyManager = KeyManager.getInstance(this)
        val label = findViewById<android.widget.TextView>(R.id.devicePasswordLabel)
        label?.text = if (keyManager.hasUserDefinedPassword()) "Change Password" else "Set Password"
    }

    private fun setupAutoWipeToggle() {
        val switch = findViewById<SwitchCompat>(R.id.autoWipeSwitch) ?: return
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)
        switch.isChecked = prefs.getBoolean("auto_wipe_enabled", false)
        switch.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("auto_wipe_enabled", isChecked).apply()
            if (!isChecked) {
                prefs.edit().putInt("failed_password_attempts", 0).apply()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateAutoLockStatus()
        refreshBiometricToggle()
        updatePasswordLabel()
    }

    private fun setupAutoLock() {
        findViewById<View>(R.id.autoLockItem).setOnClickListener {
            val intent = Intent(this, AutoLockActivity::class.java)
            startActivity(intent)
        }
    }

    private fun updateAutoLockStatus() {
        val prefs = getSharedPreferences("security", MODE_PRIVATE)
        val currentTimeout = prefs.getLong(AutoLockActivity.PREF_AUTO_LOCK_TIMEOUT, AutoLockActivity.DEFAULT_TIMEOUT)

        val timeoutText = when (currentTimeout) {
            AutoLockActivity.TIMEOUT_30_SECONDS -> "30 seconds"
            AutoLockActivity.TIMEOUT_1_MINUTE -> "1 minute"
            AutoLockActivity.TIMEOUT_5_MINUTES -> "5 minutes"
            AutoLockActivity.TIMEOUT_15_MINUTES -> "15 minutes"
            AutoLockActivity.TIMEOUT_30_MINUTES -> "30 minutes"
            AutoLockActivity.TIMEOUT_NEVER -> "Never"
            else -> "5 minutes"
        }

        findViewById<android.widget.TextView>(R.id.autoLockStatus).text = timeoutText
    }

    // setupIncomingCallsToggle and setupDeviceProtectionToggle removed — views not in new layout

    private fun setupBiometricToggle() {
        val biometricItem = findViewById<LinearLayout>(R.id.biometricItem)
        val biometricSwitch = findViewById<SwitchCompat>(R.id.biometricSwitch)

        when (biometricHelper.isBiometricAvailable()) {
            BiometricAuthHelper.BiometricStatus.AVAILABLE -> {
                biometricItem.visibility = View.VISIBLE

                val isCurrentlyEnabled = biometricHelper.isBiometricEnabled()
                biometricSwitch.isChecked = isCurrentlyEnabled

                biometricSwitch.setOnCheckedChangeListener { _, isChecked ->
                    if (isChecked) {
                        enableBiometric()
                    } else {
                        disableBiometric()
                    }
                }
            }
            BiometricAuthHelper.BiometricStatus.NONE_ENROLLED -> {
                biometricItem.visibility = View.VISIBLE
                biometricSwitch.isEnabled = false
                Log.d("SecurityModeActivity", "Biometric not enrolled - showing disabled toggle")
            }
            else -> {
                biometricItem.visibility = View.GONE
                Log.d("SecurityModeActivity", "No biometric hardware - hiding toggle")
            }
        }
    }

    private fun refreshBiometricToggle() {
        val biometricSwitch = findViewById<SwitchCompat>(R.id.biometricSwitch) ?: return
        val isEnabled = biometricHelper.isBiometricEnabled()

        biometricSwitch.setOnCheckedChangeListener(null)
        biometricSwitch.isChecked = isEnabled

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
                    Log.i("SecurityModeActivity", "Biometric enabled successfully")
                    ThemedToast.show(this, "Biometric unlock enabled")
                },
                onError = { error ->
                    Log.e("SecurityModeActivity", "Failed to enable biometric: $error")
                    ThemedToast.showLong(this, "Failed to enable: $error")
                    biometricSwitch.isChecked = false
                }
            )
        } catch (e: Exception) {
            Log.e("SecurityModeActivity", "Error enabling biometric", e)
            ThemedToast.show(this, "Error: ${e.message}")
            biometricSwitch.isChecked = false
        }
    }

    private fun disableBiometric() {
        val biometricSwitch = findViewById<SwitchCompat>(R.id.biometricSwitch)

        try {
            biometricHelper.disableBiometric()
            Log.i("SecurityModeActivity", "Biometric disabled")
            ThemedToast.show(this, "Biometric unlock disabled")
        } catch (e: Exception) {
            Log.e("SecurityModeActivity", "Error disabling biometric", e)
            ThemedToast.show(this, "Error: ${e.message}")
            biometricSwitch.isChecked = true
        }
    }

    private fun setupBottomNavigation() {
        BottomNavigationHelper.setupBottomNavigation(this)
    }
}
