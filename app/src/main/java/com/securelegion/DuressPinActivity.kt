package com.securelegion

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.ThemedToast

class DuressPinActivity : AppCompatActivity() {

    private lateinit var wipePhoneSwitch: SwitchCompat

    companion object {
        private const val PREFS_NAME = "duress_settings_enc"
        private const val KEY_DURESS_PIN = "duress_pin"
        private const val KEY_DURESS_SALT = "duress_salt"
        private const val KEY_WIPE_PHONE = "wipe_phone_on_distress"
        private const val TAG = "DuressPinActivity"

        /** Encrypted prefs for duress PIN — hides existence of duress mechanism from disk. */
        fun getDuressPrefs(context: Context): SharedPreferences {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
            return EncryptedSharedPreferences.create(
                context, PREFS_NAME, masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }

        /**
         * Verify if entered PIN matches stored duress PIN hash
         * @param context Application context
         * @param enteredPin PIN entered by user
         * @return true if PIN matches, false otherwise
         */
        fun verifyDuressPin(context: Context, enteredPin: String): Boolean {
            val prefs = getDuressPrefs(context)
            val storedHashB64 = prefs.getString(KEY_DURESS_PIN, null) ?: return false
            val storedSaltB64 = prefs.getString(KEY_DURESS_SALT, null) ?: return false

            var storedHash: ByteArray? = null
            var salt: ByteArray? = null
            var enteredPinHash: ByteArray? = null
            try {
                // Decode stored hash and salt
                storedHash = android.util.Base64.decode(storedHashB64, android.util.Base64.NO_WRAP)
                salt = android.util.Base64.decode(storedSaltB64, android.util.Base64.NO_WRAP)

                // Hash entered PIN with same salt
                enteredPinHash = com.securelegion.crypto.RustBridge.hashPassword(enteredPin, salt)

                // Constant-time comparison to prevent timing attacks
                return java.security.MessageDigest.isEqual(storedHash, enteredPinHash)
            } catch (e: Exception) {
                Log.e(TAG, "Error verifying duress PIN", e)
                return false
            } finally {
                storedHash?.fill(0)
                salt?.fill(0)
                enteredPinHash?.fill(0)
            }
        }

        /**
         * Check if duress PIN is set
         */
        fun isDuressPinSet(context: Context): Boolean {
            val prefs = getDuressPrefs(context)
            return prefs.getString(KEY_DURESS_PIN, null) != null
        }

        /**
         * Check if phone should be wiped on distress
         */
        fun shouldWipePhoneOnDistress(context: Context): Boolean {
            val prefs = getDuressPrefs(context)
            return prefs.getBoolean(KEY_WIPE_PHONE, true) // Default: true (wipe)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_duress_pin)

        // setupBottomNavigation() // REMOVED: This layout doesn't have bottom nav
        setupBackButton()

        wipePhoneSwitch = findViewById(R.id.wipePhoneSwitch)

        loadSettings()
        setupSwitchListeners()

        // Save Duress PIN button
        findViewById<View>(R.id.saveDuressPinButton).setOnClickListener {
            val pin = findViewById<EditText>(R.id.duressPinInput).text.toString()
            val confirmPin = findViewById<EditText>(R.id.confirmDuressPinInput).text.toString()

            if (pin.isEmpty() || confirmPin.isEmpty()) {
                ThemedToast.show(this, "Please enter and confirm your duress PIN")
                return@setOnClickListener
            }

            if (pin != confirmPin) {
                ThemedToast.show(this, "PINs do not match")
                return@setOnClickListener
            }

            if (pin.length !in 6..12 || !pin.all { it.isDigit() }) {
                ThemedToast.show(this, "PIN must be 6 to 12 digits")
                return@setOnClickListener
            }

            if (KeyManager.getInstance(this).verifyDevicePassword(pin)) {
                ThemedToast.showLong(this, "Duress PIN must be different from your unlock password")
                return@setOnClickListener
            }

            saveDuressPin(pin)
            ThemedToast.show(this, "Duress PIN saved successfully!")
            Log.i(TAG, "Duress PIN saved. Wipe on distress: ${wipePhoneSwitch.isChecked}")
            finish()
        }
    }

    private fun loadSettings() {
        val prefs = getDuressPrefs(this)

        // Load toggle states
        wipePhoneSwitch.isChecked = prefs.getBoolean(KEY_WIPE_PHONE, true)

        Log.d(TAG, "Loaded settings: Wipe=${wipePhoneSwitch.isChecked}")
    }

    private fun setupSwitchListeners() {
        wipePhoneSwitch.setOnCheckedChangeListener { _, isChecked ->
            val prefs = getDuressPrefs(this)
            prefs.edit().putBoolean(KEY_WIPE_PHONE, isChecked).apply()
            Log.i(TAG, "Wipe phone on distress: $isChecked")
        }
    }

    private fun saveDuressPin(pin: String) {
        val prefs = getDuressPrefs(this)

        // Hash the duress PIN using Argon2id before storing
        // Generate random 32-byte salt
        val salt = ByteArray(32)
        java.security.SecureRandom().nextBytes(salt)

        // Hash PIN with Argon2id (memory-hard, GPU-resistant)
        val pinHash = com.securelegion.crypto.RustBridge.hashPassword(pin, salt)

        // Store both hash and salt (salt is not secret, hash is)
        val stored = prefs.edit()
            .putString(KEY_DURESS_PIN, android.util.Base64.encodeToString(pinHash, android.util.Base64.NO_WRAP))
            .putString(KEY_DURESS_SALT, android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP))
            .commit()
        pinHash.fill(0)
        salt.fill(0)
        check(stored) { "Failed to save duress PIN" }

        Log.i(TAG, "Duress PIN hash saved securely (Argon2id)")
    }

    private fun setupBackButton() {
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }

    private fun setupBottomNavigation() {
        BottomNavigationHelper.setupBottomNavigation(this)
    }
}
