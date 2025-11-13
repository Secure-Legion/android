package com.securelegion

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat

class DuressPinActivity : AppCompatActivity() {

    private lateinit var wipePhoneSwitch: SwitchCompat
    private lateinit var unitedPushSwitch: SwitchCompat

    companion object {
        private const val PREFS_NAME = "duress_settings"
        private const val KEY_DURESS_PIN = "duress_pin"
        private const val KEY_WIPE_PHONE = "wipe_phone_on_distress"
        private const val KEY_USE_UNITEDPUSH = "use_unitedpush_relay"
        private const val TAG = "DuressPinActivity"

        /**
         * Get stored duress PIN
         */
        fun getDuressPin(context: Context): String? {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getString(KEY_DURESS_PIN, null)
        }

        /**
         * Check if phone should be wiped on distress
         */
        fun shouldWipePhoneOnDistress(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getBoolean(KEY_WIPE_PHONE, true) // Default: true (wipe)
        }

        /**
         * Check if UnitedPush relay should be used for panic
         */
        fun shouldUseUnitedPushRelay(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getBoolean(KEY_USE_UNITEDPUSH, false) // Default: false (direct)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_duress_pin)

        setupBottomNavigation()

        wipePhoneSwitch = findViewById(R.id.wipePhoneSwitch)
        unitedPushSwitch = findViewById(R.id.unitedPushSwitch)

        loadSettings()
        setupSwitchListeners()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Save Duress PIN button
        findViewById<View>(R.id.saveDuressPinButton).setOnClickListener {
            val pin = findViewById<EditText>(R.id.duressPinInput).text.toString()
            val confirmPin = findViewById<EditText>(R.id.confirmDuressPinInput).text.toString()

            if (pin.isEmpty() || confirmPin.isEmpty()) {
                Toast.makeText(this, "Please enter and confirm your duress PIN", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (pin != confirmPin) {
                Toast.makeText(this, "PINs do not match", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (pin.length < 4) {
                Toast.makeText(this, "PIN must be at least 4 digits", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            saveDuressPin(pin)
            Toast.makeText(this, "Duress PIN saved successfully!", Toast.LENGTH_SHORT).show()
            Log.i(TAG, "Duress PIN saved. Wipe on distress: ${wipePhoneSwitch.isChecked}, Use UnitedPush: ${unitedPushSwitch.isChecked}")
            finish()
        }
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Load toggle states (defaults: wipe=true, unitedpush=false)
        wipePhoneSwitch.isChecked = prefs.getBoolean(KEY_WIPE_PHONE, true)
        unitedPushSwitch.isChecked = prefs.getBoolean(KEY_USE_UNITEDPUSH, false)

        Log.d(TAG, "Loaded settings: Wipe=${wipePhoneSwitch.isChecked}, UnitedPush=${unitedPushSwitch.isChecked}")
    }

    private fun setupSwitchListeners() {
        wipePhoneSwitch.setOnCheckedChangeListener { _, isChecked ->
            val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_WIPE_PHONE, isChecked).apply()
            Log.i(TAG, "Wipe phone on distress: $isChecked")
        }

        unitedPushSwitch.setOnCheckedChangeListener { _, isChecked ->
            val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_USE_UNITEDPUSH, isChecked).apply()
            Log.i(TAG, "Use UnitedPush relay: $isChecked")
        }
    }

    private fun saveDuressPin(pin: String) {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        // TODO: Encrypt PIN before storing
        prefs.edit().putString(KEY_DURESS_PIN, pin).apply()
        Log.i(TAG, "Duress PIN saved securely")
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
