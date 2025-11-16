package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.RadioButton
import android.widget.RadioGroup
import androidx.appcompat.app.AppCompatActivity

class BridgeActivity : AppCompatActivity() {

    private lateinit var bridgeRadioGroup: RadioGroup
    private lateinit var customBridgeInput: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_bridge)

        bridgeRadioGroup = findViewById(R.id.bridgeRadioGroup)
        customBridgeInput = findViewById(R.id.customBridgeInput)

        setupClickListeners()
        loadSavedBridgeSettings()
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
                    // Show custom bridge input
                    customBridgeInput.visibility = View.VISIBLE
                }
                else -> {
                    // Hide custom bridge input for preset options
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

        editor.apply()

        // Note: Tor service will need to be restarted for changes to take effect
        // This will be implemented when TorManager is updated

        finish()
    }
}
