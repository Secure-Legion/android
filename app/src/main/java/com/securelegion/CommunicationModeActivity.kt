package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import com.securelegion.utils.ThemedToast

/**
 * Communication Mode Settings Activity
 *
 * Allows users to configure SecureMesh (LoRa Meshtastic) for
 * off-grid encrypted mesh network communication.
 */
class CommunicationModeActivity : BaseActivity() {

    companion object {
        private const val TAG = "CommunicationMode"
        private const val PREFS_NAME = "communication_prefs"
        private const val KEY_SECUREMESH_ENABLED = "securemesh_enabled"
    }

    private lateinit var secureMeshSwitch: SwitchCompat
    private lateinit var secureMeshStatus: TextView
    private lateinit var connectionStatusCard: LinearLayout
    private lateinit var deviceSettingsSection: LinearLayout
    private lateinit var nodesConnected: TextView
    private lateinit var signalStrength: TextView
    private lateinit var meshChannel: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_communication_mode)

        initializeViews()
        setupClickListeners()
        loadSettings()
    }

    private fun initializeViews() {
        secureMeshSwitch = findViewById(R.id.secureMeshSwitch)
        secureMeshStatus = findViewById(R.id.secureMeshStatus)
        connectionStatusCard = findViewById(R.id.connectionStatusCard)
        deviceSettingsSection = findViewById(R.id.deviceSettingsSection)
        nodesConnected = findViewById(R.id.nodesConnected)
        signalStrength = findViewById(R.id.signalStrength)
        meshChannel = findViewById(R.id.meshChannel)
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // SecureMesh toggle
        secureMeshSwitch.setOnCheckedChangeListener { _, isChecked ->
            handleSecureMeshToggle(isChecked)
        }

        // Pair device
        findViewById<View>(R.id.pairDeviceItem).setOnClickListener {
            handlePairDevice()
        }

        // Channel settings
        findViewById<View>(R.id.channelSettingsItem).setOnClickListener {
            handleChannelSettings()
        }
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val isEnabled = prefs.getBoolean(KEY_SECUREMESH_ENABLED, false)

        secureMeshSwitch.isChecked = isEnabled
        updateUIState(isEnabled)
    }

    private fun handleSecureMeshToggle(isEnabled: Boolean) {
        Log.i(TAG, "SecureMesh toggle: $isEnabled")

        // Save preference
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        prefs.edit().putBoolean(KEY_SECUREMESH_ENABLED, isEnabled).apply()

        // Update UI
        updateUIState(isEnabled)

        if (isEnabled) {
            // TODO: Initialize Meshtastic connection
            ThemedToast.show(this, "SecureMesh enabled - Searching for devices...")
            startMeshConnection()
        } else {
            // TODO: Disconnect from Meshtastic
            ThemedToast.show(this, "SecureMesh disabled")
            stopMeshConnection()
        }
    }

    private fun updateUIState(isEnabled: Boolean) {
        if (isEnabled) {
            secureMeshStatus.text = "Searching..."
            secureMeshStatus.setTextColor(0xFFFFAA00.toInt()) // Orange for searching
            connectionStatusCard.visibility = View.VISIBLE
            deviceSettingsSection.visibility = View.VISIBLE
        } else {
            secureMeshStatus.text = "Disconnected"
            secureMeshStatus.setTextColor(0xFF666666.toInt()) // Gray for disconnected
            connectionStatusCard.visibility = View.GONE
            deviceSettingsSection.visibility = View.GONE
        }
    }

    private fun startMeshConnection() {
        // TODO: Implement Meshtastic BLE connection
        // This would:
        // 1. Scan for paired Meshtastic devices via Bluetooth
        // 2. Connect to the device
        // 3. Start receiving mesh messages
        // 4. Update UI with connection status

        Log.i(TAG, "Starting mesh connection...")

        // Simulated connection status for UI demonstration
        // In production, this would be replaced with actual Meshtastic API calls
        secureMeshStatus.postDelayed({
            if (secureMeshSwitch.isChecked) {
                // Update to connected state (placeholder)
                secureMeshStatus.text = "Connected"
                secureMeshStatus.setTextColor(0xFF4CAF50.toInt()) // Green for connected
                nodesConnected.text = "0"
                signalStrength.text = "Good"
                meshChannel.text = "LongFast"
            }
        }, 2000)
    }

    private fun stopMeshConnection() {
        // TODO: Implement Meshtastic disconnection
        Log.i(TAG, "Stopping mesh connection...")

        // Reset status
        nodesConnected.text = "0"
        signalStrength.text = "--"
        meshChannel.text = "Default"
    }

    private fun handlePairDevice() {
        // TODO: Open Bluetooth device pairing flow
        ThemedToast.show(this, "Open Bluetooth settings to pair your LoRa device")

        // Could launch system Bluetooth settings:
        // val intent = Intent(android.provider.Settings.ACTION_BLUETOOTH_SETTINGS)
        // startActivity(intent)
    }

    private fun handleChannelSettings() {
        // TODO: Open channel configuration dialog/activity
        ThemedToast.show(this, "Channel settings coming soon")
    }
}
