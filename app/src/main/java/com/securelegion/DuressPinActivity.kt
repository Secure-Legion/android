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

    companion object {
        private const val PREFS_NAME = "duress_settings"
        private const val KEY_DURESS_PIN = "duress_pin"
        private const val KEY_DURESS_SALT = "duress_salt"
        private const val KEY_WIPE_PHONE = "wipe_phone_on_distress"
        private const val TAG = "DuressPinActivity"

        /**
         * Verify if entered PIN matches stored duress PIN hash
         * @param context Application context
         * @param enteredPin PIN entered by user
         * @return true if PIN matches, false otherwise
         */
        fun verifyDuressPin(context: Context, enteredPin: String): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val storedHashB64 = prefs.getString(KEY_DURESS_PIN, null) ?: return false
            val storedSaltB64 = prefs.getString(KEY_DURESS_SALT, null) ?: return false

            try {
                // Decode stored hash and salt
                val storedHash = android.util.Base64.decode(storedHashB64, android.util.Base64.NO_WRAP)
                val salt = android.util.Base64.decode(storedSaltB64, android.util.Base64.NO_WRAP)

                // Hash entered PIN with same salt
                val enteredPinHash = com.securelegion.crypto.RustBridge.hashPassword(enteredPin, salt)

                // Constant-time comparison to prevent timing attacks
                return java.security.MessageDigest.isEqual(storedHash, enteredPinHash)
            } catch (e: Exception) {
                Log.e(TAG, "Error verifying duress PIN", e)
                return false
            }
        }

        /**
         * Check if duress PIN is set
         */
        fun isDuressPinSet(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getString(KEY_DURESS_PIN, null) != null
        }

        /**
         * Check if phone should be wiped on distress
         */
        fun shouldWipePhoneOnDistress(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getBoolean(KEY_WIPE_PHONE, true) // Default: true (wipe)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_duress_pin)

        setupBottomNavigation()

        wipePhoneSwitch = findViewById(R.id.wipePhoneSwitch)

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
            Log.i(TAG, "Duress PIN saved. Wipe on distress: ${wipePhoneSwitch.isChecked}")
            finish()
        }
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Load toggle states
        wipePhoneSwitch.isChecked = prefs.getBoolean(KEY_WIPE_PHONE, true)

        Log.d(TAG, "Loaded settings: Wipe=${wipePhoneSwitch.isChecked}")
    }

    private fun setupSwitchListeners() {
        wipePhoneSwitch.setOnCheckedChangeListener { _, isChecked ->
            val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_WIPE_PHONE, isChecked).apply()
            Log.i(TAG, "Wipe phone on distress: $isChecked")
        }
    }

    private fun saveDuressPin(pin: String) {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Hash the duress PIN using Argon2id before storing
        // Generate random 32-byte salt
        val salt = ByteArray(32)
        java.security.SecureRandom().nextBytes(salt)

        // Hash PIN with Argon2id (memory-hard, GPU-resistant)
        val pinHash = com.securelegion.crypto.RustBridge.hashPassword(pin, salt)

        // Store both hash and salt (salt is not secret, hash is)
        prefs.edit()
            .putString(KEY_DURESS_PIN, android.util.Base64.encodeToString(pinHash, android.util.Base64.NO_WRAP))
            .putString(KEY_DURESS_SALT, android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP))
            .apply()

        Log.i(TAG, "Duress PIN hash saved securely (Argon2id)")
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
