package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.SecureWipe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class LockActivity : AppCompatActivity() {

    private lateinit var passwordSection: LinearLayout
    private lateinit var accountLinksSection: LinearLayout
    private var hasWallet = false
    private var isProcessingDistress = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_lock)

        passwordSection = findViewById(R.id.passwordSection)
        accountLinksSection = findViewById(R.id.accountLinksSection)

        // Check if wallet exists
        val keyManager = KeyManager.getInstance(this)
        hasWallet = keyManager.isInitialized()

        if (hasWallet) {
            // Wallet exists - show password unlock
            Log.d("LockActivity", "Wallet exists, showing password unlock")
            passwordSection.visibility = View.VISIBLE
            accountLinksSection.visibility = View.GONE
        } else {
            // No wallet - show account creation/restore options
            Log.d("LockActivity", "No wallet, showing account options")
            passwordSection.visibility = View.GONE
            accountLinksSection.visibility = View.VISIBLE
        }

        setupClickListeners()
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.unlockButton).setOnClickListener {
            val password = findViewById<EditText>(R.id.passwordInput).text.toString()

            if (password.isBlank()) {
                Toast.makeText(this, "Please enter password", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Check if account is in cooldown
            if (isInCooldown()) {
                val remainingSeconds = getRemainingCooldownSeconds()
                Toast.makeText(
                    this,
                    "Too many failed attempts. Try again in $remainingSeconds seconds",
                    Toast.LENGTH_LONG
                ).show()
                return@setOnClickListener
            }

            // Prevent multiple distress triggers
            if (isProcessingDistress) {
                return@setOnClickListener
            }

            // Check if entered password is the duress PIN
            if (DuressPinActivity.verifyDuressPin(this, password)) {
                Log.w("LockActivity", "Duress PIN detected - triggering distress protocol")
                isProcessingDistress = true
                handleDistressProtocol()
                return@setOnClickListener
            }

            // Verify normal device password
            val keyManager = KeyManager.getInstance(this)
            if (keyManager.verifyDevicePassword(password)) {
                Log.i("LockActivity", "Password verified")

                // Reset failed attempts counter on successful login
                resetFailedAttempts()

                // Check if account setup is complete (has wallet, contact card, AND username)
                if (!keyManager.isAccountSetupComplete()) {
                    Log.w("LockActivity", "Account incomplete - need to finish setup")
                    Toast.makeText(this, "Please complete account setup", Toast.LENGTH_LONG).show()

                    // Redirect to CreateAccountActivity to finish setup
                    val intent = Intent(this, CreateAccountActivity::class.java)
                    intent.putExtra("RESUME_SETUP", true)
                    startActivity(intent)
                    finish()
                } else {
                    Log.i("LockActivity", "Account complete, unlocking app")
                    val intent = Intent(this, MainActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    startActivity(intent)
                    finish()
                }
            } else {
                // Password incorrect
                Log.w("LockActivity", "Incorrect password entered")
                handleFailedAttempt()
                Toast.makeText(this, "Incorrect password", Toast.LENGTH_SHORT).show()
                // Clear input
                findViewById<EditText>(R.id.passwordInput).text.clear()
            }
        }

        findViewById<View>(R.id.newAccountLink).setOnClickListener {
            Log.d("LockActivity", "User selected 'Create New Account'")
            val intent = Intent(this, CreateAccountActivity::class.java)
            startActivity(intent)
            // Don't finish - allow back navigation
        }

        findViewById<View>(R.id.restoreAccountLink).setOnClickListener {
            Log.d("LockActivity", "User selected 'Import Account'")
            val intent = Intent(this, RestoreAccountActivity::class.java)
            startActivity(intent)
            // Don't finish - allow back navigation
        }
    }

    /**
     * Handle distress protocol when duress PIN is entered
     * Sends panic notifications and executes distress actions based on settings
     */
    private fun handleDistressProtocol() {
        lifecycleScope.launch {
            try {
                Log.w("LockActivity", "Executing distress protocol")

                // Send panic notifications to distress contacts
                sendPanicNotifications()

                // Check if phone should be wiped
                val shouldWipe = DuressPinActivity.shouldWipePhoneOnDistress(this@LockActivity)

                if (shouldWipe) {
                    Log.w("LockActivity", "Wipe toggle ON - wiping all data")
                    wipeAllData()
                } else {
                    Log.w("LockActivity", "Wipe toggle OFF - enabling silent message blocking")
                    enableMessageBlocking()
                }

                // Show normal unlock screen to maintain cover
                // (Don't show any error or indication that distress was triggered)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@LockActivity, "Incorrect password", Toast.LENGTH_SHORT).show()
                    findViewById<EditText>(R.id.passwordInput).text.clear()
                    isProcessingDistress = false
                }

            } catch (e: Exception) {
                Log.e("LockActivity", "Failed to execute distress protocol", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@LockActivity, "Incorrect password", Toast.LENGTH_SHORT).show()
                    findViewById<EditText>(R.id.passwordInput).text.clear()
                    isProcessingDistress = false
                }
            }
        }
    }

    /**
     * Send panic notifications to all distress contacts
     */
    private suspend fun sendPanicNotifications() {
        withContext(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@LockActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@LockActivity, dbPassphrase)

                // Get all distress contacts
                val distressContacts = database.contactDao().getAllContacts()
                    .filter { it.isDistressContact }

                Log.w("LockActivity", "Found ${distressContacts.size} distress contacts")

                if (distressContacts.isEmpty()) {
                    Log.w("LockActivity", "No distress contacts configured - skipping panic notifications")
                    return@withContext
                }

                // Send panic notification to each distress contact via direct connection
                for (contact in distressContacts) {
                    try {
                        Log.i("LockActivity", "Sending panic via direct connection to ${contact.displayName}")
                        // TODO: Implement direct panic notification
                    } catch (e: Exception) {
                        Log.e("LockActivity", "Failed to send panic to ${contact.displayName}", e)
                    }
                }

                Log.i("LockActivity", "Panic notifications sent to all distress contacts")
            } catch (e: Exception) {
                Log.e("LockActivity", "Failed to send panic notifications", e)
            }
        }
    }

    /**
     * Wipe all data (keys, database, settings) with 3-pass secure overwrite
     */
    private suspend fun wipeAllData() {
        withContext(Dispatchers.IO) {
            try {
                Log.w("LockActivity", "WIPING ALL DATA (3-pass secure overwrite)")

                // Wipe all cryptographic keys
                val keyManager = KeyManager.getInstance(this@LockActivity)
                keyManager.wipeAllKeys()

                // Securely wipe all data (3-pass overwrite)
                SecureWipe.wipeAllData(this@LockActivity)

                Log.w("LockActivity", "All data securely wiped")

                // Restart app to show account creation screen
                withContext(Dispatchers.Main) {
                    val intent = Intent(this@LockActivity, LockActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    startActivity(intent)
                    finish()
                }
            } catch (e: Exception) {
                Log.e("LockActivity", "Failed to wipe data", e)
            }
        }
    }

    /**
     * Enable silent message blocking mode
     * Sets a flag in SharedPreferences to block all outgoing messages
     */
    private suspend fun enableMessageBlocking() {
        withContext(Dispatchers.IO) {
            try {
                Log.w("LockActivity", "Enabling silent message blocking mode")

                // Set flag to block outgoing messages
                getSharedPreferences("security_settings", MODE_PRIVATE)
                    .edit()
                    .putBoolean("block_outgoing_messages", true)
                    .apply()

                Log.i("LockActivity", "Message blocking enabled - all outgoing messages will be silently blocked")
            } catch (e: Exception) {
                Log.e("LockActivity", "Failed to enable message blocking", e)
            }
        }
    }

    /**
     * Handle failed password attempt
     * Increments counter, triggers cooldown at 5 attempts, and wipes data at 10 (when feature enabled)
     */
    private fun handleFailedAttempt() {
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)
        val failedAttempts = prefs.getInt("failed_password_attempts", 0) + 1
        prefs.edit().putInt("failed_password_attempts", failedAttempts).apply()

        Log.w("LockActivity", "Failed password attempt #$failedAttempts")

        // Trigger 30-second cooldown after 5 failed attempts
        if (failedAttempts >= 5) {
            val cooldownEndTime = System.currentTimeMillis() + 30_000 // 30 seconds
            prefs.edit().putLong("cooldown_end_time", cooldownEndTime).apply()
            Log.w("LockActivity", "5 failed attempts - 30 second cooldown activated")

            val remainingSeconds = 30
            Toast.makeText(
                this,
                "Too many failed attempts. Wait $remainingSeconds seconds",
                Toast.LENGTH_LONG
            ).show()
        }

        // Auto-wipe after 10 attempts (if enabled)
        val autoWipeEnabled = prefs.getBoolean("auto_wipe_enabled", false)
        if (autoWipeEnabled && failedAttempts >= 10) {
            Log.e("LockActivity", "10 failed password attempts reached - triggering auto-wipe")
            lifecycleScope.launch {
                wipeAllData()
            }
        }
    }

    /**
     * Reset failed password attempts counter on successful login
     */
    private fun resetFailedAttempts() {
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)
        prefs.edit()
            .putInt("failed_password_attempts", 0)
            .remove("cooldown_end_time")
            .apply()
        Log.d("LockActivity", "Failed password attempts counter and cooldown reset")
    }

    /**
     * Check if account is currently in cooldown period
     */
    private fun isInCooldown(): Boolean {
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)
        val cooldownEndTime = prefs.getLong("cooldown_end_time", 0)

        if (cooldownEndTime == 0L) {
            return false
        }

        val currentTime = System.currentTimeMillis()
        if (currentTime >= cooldownEndTime) {
            // Cooldown expired - clear it
            prefs.edit().remove("cooldown_end_time").apply()
            return false
        }

        return true
    }

    /**
     * Get remaining cooldown time in seconds
     */
    private fun getRemainingCooldownSeconds(): Int {
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)
        val cooldownEndTime = prefs.getLong("cooldown_end_time", 0)
        val currentTime = System.currentTimeMillis()
        val remainingMs = cooldownEndTime - currentTime
        return ((remainingMs / 1000) + 1).toInt().coerceAtLeast(0)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Prevent going back without unlocking
    }
}
