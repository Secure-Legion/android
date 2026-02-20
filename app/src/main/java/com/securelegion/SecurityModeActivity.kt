package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.AdapterView
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
        setupFriendRequestSecuritySettings()
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

    private fun setupFriendRequestSecuritySettings() {
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)

        // PIN Rotation Interval spinner
        val rotationSpinner = findViewById<Spinner>(R.id.pinRotationIntervalSpinner) ?: return
        val rotationOptions = arrayOf("12 hours", "24 hours", "3 days", "7 days", "Never")
        val rotationValues = longArrayOf(
            12 * 60 * 60 * 1000L,
            24 * 60 * 60 * 1000L,
            3 * 24 * 60 * 60 * 1000L,
            7 * 24 * 60 * 60 * 1000L,
            0L // Never
        )
        val rotationAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, rotationOptions)
        rotationAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        rotationSpinner.adapter = rotationAdapter

        // Load saved interval (default 24h)
        val savedInterval = prefs.getLong("pin_rotation_interval_ms", 24 * 60 * 60 * 1000L)
        val rotationIndex = rotationValues.indexOf(savedInterval).let { if (it < 0) 1 else it }
        rotationSpinner.setSelection(rotationIndex)

        rotationSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                prefs.edit().putLong("pin_rotation_interval_ms", rotationValues[position]).apply()
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // Max PIN Uses spinner
        val usesSpinner = findViewById<Spinner>(R.id.pinMaxUsesSpinner) ?: return
        val usesOptions = arrayOf("3 uses", "5 uses", "10 uses", "Unlimited")
        val usesValues = intArrayOf(3, 5, 10, 0) // 0 = unlimited
        val usesAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, usesOptions)
        usesAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        usesSpinner.adapter = usesAdapter

        // Load saved max uses (default 5)
        val savedMaxUses = prefs.getInt("pin_max_uses", 5)
        val usesIndex = usesValues.indexOf(savedMaxUses).let { if (it < 0) 1 else it }
        usesSpinner.setSelection(usesIndex)

        usesSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                prefs.edit().putInt("pin_max_uses", usesValues[position]).apply()
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // Legacy Manual Entry toggle
        val legacySwitch = findViewById<SwitchCompat>(R.id.legacyManualEntrySwitch) ?: return
        legacySwitch.isChecked = prefs.getBoolean("legacy_manual_entry", false)
        legacySwitch.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("legacy_manual_entry", isChecked).apply()
        }
    }

    private fun setupBottomNavigation() {
        BottomNavigationHelper.setupBottomNavigation(this)
    }
}
