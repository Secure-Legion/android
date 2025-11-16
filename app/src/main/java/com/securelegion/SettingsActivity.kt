package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat

class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        BottomNavigationHelper.setupBottomNavigation(this)
        setupClickListeners()
        setupAutoWipeToggle()
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
}
