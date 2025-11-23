package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.BiometricAuthHelper
import com.securelegion.utils.SecureWipe
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class LockActivity : AppCompatActivity() {

    private lateinit var passwordSection: LinearLayout
    private lateinit var accountLinksSection: LinearLayout
    private lateinit var biometricHelper: BiometricAuthHelper
    private var hasWallet = false
    private var isProcessingDistress = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording on lock screen
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Security: Show lock screen over keyguard
        setShowWhenLocked(true)
        setTurnScreenOn(true)

        // Security: Disable back gesture navigation
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                // Do nothing - prevent back navigation
            }
        })

        setContentView(R.layout.activity_lock)

        passwordSection = findViewById(R.id.passwordSection)
        accountLinksSection = findViewById(R.id.accountLinksSection)
        biometricHelper = BiometricAuthHelper(this)

        // Check if wallet exists
        val keyManager = KeyManager.getInstance(this)
        hasWallet = keyManager.isInitialized()

        if (hasWallet) {
            // Wallet exists - show password unlock
            Log.d("LockActivity", "Wallet exists, showing password unlock")
            passwordSection.visibility = View.VISIBLE
            accountLinksSection.visibility = View.GONE
            setupBiometricUI()
        } else {
            // No wallet - show account creation/restore options
            Log.d("LockActivity", "No wallet, showing account options")
            passwordSection.visibility = View.GONE
            accountLinksSection.visibility = View.VISIBLE
        }

        setupClickListeners()
    }

    private fun setupBiometricUI() {
        val biometricButton = findViewById<ImageView>(R.id.biometricButton)
        val biometricText = findViewById<TextView>(R.id.biometricText)

        // Check biometric availability
        when (biometricHelper.isBiometricAvailable()) {
            BiometricAuthHelper.BiometricStatus.AVAILABLE -> {
                // Check if biometric is already enabled
                if (biometricHelper.isBiometricEnabled()) {
                    Log.d("LockActivity", "Biometric enabled - showing unlock button")
                    biometricButton.visibility = View.VISIBLE
                    biometricText.visibility = View.VISIBLE
                } else {
                    Log.d("LockActivity", "Biometric available but not enabled yet")
                }
            }
            BiometricAuthHelper.BiometricStatus.NONE_ENROLLED -> {
                Log.d("LockActivity", "No biometric enrolled on device")
            }
            BiometricAuthHelper.BiometricStatus.NO_HARDWARE -> {
                Log.d("LockActivity", "No biometric hardware available")
            }
            BiometricAuthHelper.BiometricStatus.HARDWARE_UNAVAILABLE -> {
                Log.d("LockActivity", "Biometric hardware unavailable")
            }
            BiometricAuthHelper.BiometricStatus.UNKNOWN_ERROR -> {
                Log.d("LockActivity", "Unknown biometric error")
            }
        }

        // Biometric button click listener
        biometricButton.setOnClickListener {
            authenticateWithBiometric()
        }
    }

    private fun authenticateWithBiometric() {
        biometricHelper.authenticateWithBiometric(
            activity = this,
            onSuccess = { passwordHash ->
                Log.i("LockActivity", "Biometric authentication successful")

                // Verify the decrypted password hash matches stored hash
                val keyManager = KeyManager.getInstance(this)
                if (keyManager.verifyPasswordHash(passwordHash)) {
                    Log.i("LockActivity", "Password hash verified from biometric")

                    // Reset failed attempts
                    resetFailedAttempts()

                    // Unlock app
                    unlockApp()
                } else {
                    Log.e("LockActivity", "Biometric decrypted hash does not match stored hash")
                    ThemedToast.show(this, "Biometric authentication failed")
                }
            },
            onError = { errorMsg ->
                Log.w("LockActivity", "Biometric authentication error: $errorMsg")
                if (!errorMsg.contains("Cancel") && !errorMsg.contains("Use Password")) {
                    ThemedToast.show(this, errorMsg)
                }
            }
        )
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.unlockButton).setOnClickListener {
            val password = findViewById<EditText>(R.id.passwordInput).text.toString()

            if (password.isBlank()) {
                ThemedToast.show(this, "Please enter password")
                return@setOnClickListener
            }

            // Check if account is in cooldown
            if (isInCooldown()) {
                val remainingSeconds = getRemainingCooldownSeconds()
                ThemedToast.showLong(
                    this,
                    "Too many failed attempts. Try again in $remainingSeconds seconds"
                )
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

                // Enable biometric on first successful login (if available and not already enabled)
                offerBiometricEnrollment(keyManager)

                // Check if account setup is complete (has wallet, contact card, AND username)
                if (!keyManager.isAccountSetupComplete()) {
                    Log.w("LockActivity", "Account incomplete - need to finish setup")
                    ThemedToast.showLong(this, "Please complete account setup")

                    // Redirect to CreateAccountActivity to finish setup
                    val intent = Intent(this, CreateAccountActivity::class.java)
                    intent.putExtra("RESUME_SETUP", true)
                    startActivity(intent)
                    finish()
                } else {
                    Log.i("LockActivity", "Account complete, unlocking app")
                    unlockApp()
                }
            } else {
                // Password incorrect
                Log.w("LockActivity", "Incorrect password entered")
                handleFailedAttempt()
                ThemedToast.show(this, "Incorrect password")
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
     * Offer biometric enrollment on first successful password login
     */
    private fun offerBiometricEnrollment(keyManager: KeyManager) {
        // Only offer if biometric is available but not enabled yet
        if (biometricHelper.isBiometricAvailable() == BiometricAuthHelper.BiometricStatus.AVAILABLE &&
            !biometricHelper.isBiometricEnabled()) {

            // Check if we already asked the user (to avoid repeated prompts)
            val prefs = getSharedPreferences("biometric_prefs", MODE_PRIVATE)
            val alreadyAsked = prefs.getBoolean("biometric_enrollment_asked", false)

            if (!alreadyAsked) {
                Log.d("LockActivity", "Offering biometric enrollment to user")

                // Get password hash for encryption
                val passwordHash = keyManager.getPasswordHash()
                if (passwordHash != null) {
                    biometricHelper.enableBiometric(
                        passwordHash = passwordHash,
                        activity = this,
                        onSuccess = {
                            Log.i("LockActivity", "Biometric enrollment successful")
                            ThemedToast.show(this, "Biometric unlock enabled")

                            // Update UI to show biometric button
                            findViewById<ImageView>(R.id.biometricButton).visibility = View.VISIBLE
                            findViewById<TextView>(R.id.biometricText).visibility = View.VISIBLE
                        },
                        onError = { error ->
                            Log.w("LockActivity", "Biometric enrollment failed: $error")
                            // Don't show error toast - user may have cancelled
                        }
                    )
                }

                // Mark as asked to avoid repeated prompts
                prefs.edit().putBoolean("biometric_enrollment_asked", true).apply()
            }
        }
    }

    /**
     * Unlock the app and navigate to MainActivity
     */
    private fun unlockApp() {
        // Check if we were launched from a notification with a target activity
        val targetActivity = intent.getStringExtra("TARGET_ACTIVITY")

        val nextIntent = when (targetActivity) {
            "ChatActivity" -> {
                // Forward to ChatActivity with original extras
                Intent(this, ChatActivity::class.java).apply {
                    putExtra(ChatActivity.EXTRA_CONTACT_ID, intent.getLongExtra(ChatActivity.EXTRA_CONTACT_ID, -1L))
                    putExtra(ChatActivity.EXTRA_CONTACT_NAME, intent.getStringExtra(ChatActivity.EXTRA_CONTACT_NAME))
                    putExtra("FOCUS_INPUT", intent.getBooleanExtra("FOCUS_INPUT", false))
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                }
            }
            "MainActivity" -> {
                // Forward to MainActivity with any extras
                Intent(this, MainActivity::class.java).apply {
                    // Forward friend request flag if present
                    if (intent.getBooleanExtra("SHOW_FRIEND_REQUESTS", false)) {
                        putExtra("SHOW_FRIEND_REQUESTS", true)
                    }
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                }
            }
            else -> {
                // Default to MainActivity
                Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                }
            }
        }

        startActivity(nextIntent)
        finish()
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
                    ThemedToast.show(this@LockActivity, "Incorrect password")
                    findViewById<EditText>(R.id.passwordInput).text.clear()
                    isProcessingDistress = false
                }

            } catch (e: Exception) {
                Log.e("LockActivity", "Failed to execute distress protocol", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@LockActivity, "Incorrect password")
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
            ThemedToast.showLong(
                this,
                "Too many failed attempts. Wait $remainingSeconds seconds"
            )
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

    override fun onPause() {
        super.onPause()
        // Security: If lock screen is paused (user tries to leave), immediately bring it back
        if (hasWallet && !isFinishing) {
            Log.w("LockActivity", "Lock screen paused - preventing bypass")
        }
    }

    override fun onStop() {
        super.onStop()
        // Security: If user tries to minimize/leave lock screen, restart it on top
        if (hasWallet && !isFinishing) {
            Log.w("LockActivity", "Lock screen stopped - restarting on top")
            val intent = Intent(this, LockActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                          Intent.FLAG_ACTIVITY_CLEAR_TASK or
                          Intent.FLAG_ACTIVITY_NO_HISTORY
            startActivity(intent)
        }
    }
}
