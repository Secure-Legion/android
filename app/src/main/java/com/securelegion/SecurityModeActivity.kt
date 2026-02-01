package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.widget.SwitchCompat

class SecurityModeActivity : BaseActivity() {

    companion object {
        const val PREF_ALLOW_INCOMING_CALLS_WHEN_CLOSED = "allow_incoming_calls_when_closed"
        const val PREF_DEVICE_PROTECTION_ENABLED = "device_protection_enabled"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_security_mode)

        setupClickListeners()
        // setupBottomNavigation() // REMOVED: This layout doesn't have bottom nav
        setupAutoLock()
        setupIncomingCallsToggle()
        setupDeviceProtectionToggle()
    }

    private fun setupClickListeners() {
        // Back Button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        updateAutoLockStatus()
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

    private fun setupIncomingCallsToggle() {
        val switch = findViewById<SwitchCompat>(R.id.allowIncomingCallsSwitch)
        val prefs = getSharedPreferences("security", MODE_PRIVATE)

        // Load saved state (default true - allow calls when app closed)
        switch.isChecked = prefs.getBoolean(PREF_ALLOW_INCOMING_CALLS_WHEN_CLOSED, true)

        // Save state when toggled
        switch.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean(PREF_ALLOW_INCOMING_CALLS_WHEN_CLOSED, isChecked).apply()
        }
    }

    private fun setupDeviceProtectionToggle() {
        val switch = findViewById<SwitchCompat>(R.id.deviceProtectionSwitch)
        val prefs = getSharedPreferences("security", MODE_PRIVATE)

        // Load saved state (default false - auto-download enabled by default)
        switch.isChecked = prefs.getBoolean(PREF_DEVICE_PROTECTION_ENABLED, false)

        // Save state when toggled
        switch.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean(PREF_DEVICE_PROTECTION_ENABLED, isChecked).apply()
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

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
