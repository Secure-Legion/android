package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.RadioButton
import android.widget.RadioGroup
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.services.TorService
import com.securelegion.utils.ThemedToast

class BridgeActivity : AppCompatActivity() {

    private lateinit var bridgeRadioGroup: RadioGroup
    private lateinit var customBridgeInput: EditText
    private lateinit var testnetSwitch: androidx.appcompat.widget.SwitchCompat

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_bridge)

        bridgeRadioGroup = findViewById(R.id.bridgeRadioGroup)
        customBridgeInput = findViewById(R.id.customBridgeInput)
        testnetSwitch = findViewById(R.id.testnetSwitch)

        // Hide bottom nav when opened from splash screen (first-time setup)
        val fromSplash = intent.getBooleanExtra("FROM_SPLASH", false)
        if (fromSplash) {
            findViewById<View>(R.id.bottomNav)?.visibility = View.GONE
        } else {
            BottomNavigationHelper.setupBottomNavigation(this)
        }
        setupClickListeners()
        loadSavedBridgeSettings()
        loadTestnetSetting()
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Radio group selection
        bridgeRadioGroup.setOnCheckedChangeListener { _, checkedId ->
            when (checkedId) {
                R.id.bridgeCustom -> {
                    customBridgeInput.visibility = View.VISIBLE
                }
                else -> {
                    customBridgeInput.visibility = View.GONE
                }
            }
        }

        // Save button
        findViewById<View>(R.id.saveButton).setOnClickListener {
            saveBridgeSettings()
        }
    }

    private fun loadSavedBridgeSettings() {
        val prefs = getSharedPreferences("tor_settings", MODE_PRIVATE)
        val bridgeType = prefs.getString("bridge_type", "none")
        val customBridge = prefs.getString("custom_bridge", "")

        Log.d("BridgeActivity", "Loading saved bridge settings: type=$bridgeType")

        when (bridgeType) {
            "none" -> findViewById<RadioButton>(R.id.bridgeNone).isChecked = true
            "snowflake" -> findViewById<RadioButton>(R.id.bridgeSnowflake).isChecked = true
            "obfs4" -> findViewById<RadioButton>(R.id.bridgeObfs4).isChecked = true
            "meek" -> findViewById<RadioButton>(R.id.bridgeMeek).isChecked = true
            "webtunnel" -> findViewById<RadioButton>(R.id.bridgeWebtunnel).isChecked = true
            "custom" -> {
                findViewById<RadioButton>(R.id.bridgeCustom).isChecked = true
                customBridgeInput.setText(customBridge)
                customBridgeInput.visibility = View.VISIBLE
            }
        }
    }

    private fun saveBridgeSettings() {
        val prefs = getSharedPreferences("tor_settings", MODE_PRIVATE)
        val editor = prefs.edit()

        val selectedBridgeType = when (bridgeRadioGroup.checkedRadioButtonId) {
            R.id.bridgeNone -> "none"
            R.id.bridgeSnowflake -> "snowflake"
            R.id.bridgeObfs4 -> "obfs4"
            R.id.bridgeMeek -> "meek"
            R.id.bridgeWebtunnel -> "webtunnel"
            R.id.bridgeCustom -> "custom"
            else -> "none"
        }

        editor.putString("bridge_type", selectedBridgeType)

        if (selectedBridgeType == "custom") {
            val customBridge = customBridgeInput.text.toString().trim()
            editor.putString("custom_bridge", customBridge)
            Log.i("BridgeActivity", "Saved custom bridge configuration")
        } else {
            editor.remove("custom_bridge")
            Log.i("BridgeActivity", "Saved bridge type: $selectedBridgeType")
        }

        // Save testnet mode
        val testnetEnabled = testnetSwitch.isChecked
        editor.putBoolean("testnet_mode", testnetEnabled)
        Log.i("BridgeActivity", "Testnet mode: ${if (testnetEnabled) "ENABLED" else "DISABLED"}")

        // Set flag to force Tor re-initialization on next start
        editor.putBoolean("bridge_config_changed", true)
        editor.apply()

        val fromSplash = intent.getBooleanExtra("FROM_SPLASH", false)

        if (fromSplash) {
            // Opened from splash screen (first-time setup) — just finish and return
            // SplashActivity will handle Tor start when user presses Start
            Log.i("BridgeActivity", "Bridge configured from splash - returning")
            ThemedToast.show(this, "Bridge configured! Press Start to connect.")
            finish()
        } else {
            // Opened from settings — restart Tor with new bridge settings
            Log.i("BridgeActivity", "Redirecting to SplashActivity to restart Tor...")
            ThemedToast.show(this, "Restarting Tor with new bridge settings...")

            // Stop current Tor service first
            try {
                val stopIntent = Intent(this, TorService::class.java)
                stopIntent.action = TorService.ACTION_STOP_TOR
                startService(stopIntent)
            } catch (e: Exception) {
                Log.w("BridgeActivity", "Failed to stop TorService: ${e.message}")
            }

            // Redirect to SplashActivity which will handle Tor restart
            val intent = Intent(this, SplashActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
        }
    }

    private fun loadTestnetSetting() {
        val prefs = getSharedPreferences("tor_settings", MODE_PRIVATE)
        val testnetEnabled = prefs.getBoolean("testnet_mode", false)
        testnetSwitch.isChecked = testnetEnabled
        Log.d("BridgeActivity", "Loaded testnet mode: ${if (testnetEnabled) "ENABLED" else "DISABLED"}")
    }

    companion object {
        /**
         * Check if testnet mode is enabled
         * Call this from other activities to determine which network to use
         */
        fun isTestnetEnabled(context: android.content.Context): Boolean {
            val prefs = context.getSharedPreferences("tor_settings", android.content.Context.MODE_PRIVATE)
            return prefs.getBoolean("testnet_mode", false)
        }
    }
}
