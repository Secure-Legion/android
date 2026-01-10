package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
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
    private lateinit var biometricHelper: BiometricAuthHelper
    private var hasWallet = false
    private var isProcessingDistress = false
    private var hasAuthenticated = false  // Track if user successfully authenticated
    private var isPasswordVisible = false  // Track password visibility state

    override fun onCreate(savedInstanceState: Bundle?) {
        // Check if wallet exists BEFORE calling super.onCreate() to prevent any UI flash
        val keyManager = KeyManager.getInstance(this)
        hasWallet = keyManager.isInitialized()

        if (!hasWallet) {
            // No wallet - this shouldn't happen as SplashActivity should redirect
            // Finish immediately without showing any UI
            super.onCreate(savedInstanceState)
            Log.w("LockActivity", "No wallet found - redirecting to WelcomeActivity without showing UI")
            val intent = Intent(this, WelcomeActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            finish()  // Finish FIRST
            startActivity(intent)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            return
        }

        super.onCreate(savedInstanceState)

        // Mark app as locked (user needs to authenticate)
        com.securelegion.utils.SessionManager.setLocked(this)
        Log.d("LockActivity", "App locked - user on lock screen")

        // Security: Prevent screenshots and screen recording on lock screen
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Wallet exists - show lock screen UI
        Log.d("LockActivity", "Wallet exists, showing password unlock")

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
        biometricHelper = BiometricAuthHelper(this)

        passwordSection.visibility = View.VISIBLE
        setupBiometricUI()
        setupClickListeners()
        setupForgotPasswordText()
    }

    private fun setupBiometricUI() {
        val biometricButton = findViewById<ImageView>(R.id.biometricButton)

        // Check biometric availability
        val biometricStatus = biometricHelper.isBiometricAvailable()
        val isEnabled = biometricHelper.isBiometricEnabled()

        Log.d("LockActivity", "Biometric Status: $biometricStatus")
        Log.d("LockActivity", "Biometric Enabled in App: $isEnabled")

        when (biometricStatus) {
            BiometricAuthHelper.BiometricStatus.AVAILABLE -> {
                Log.d("LockActivity", "Biometric hardware available and enrolled")
                // Check if biometric is already enabled in app
                if (isEnabled) {
                    Log.i("LockActivity", "Biometric unlock enabled - showing button")
                    biometricButton.visibility = View.VISIBLE
                } else {
                    Log.d("LockActivity", "Biometric available but not enabled in app yet")
                }
            }
            BiometricAuthHelper.BiometricStatus.NONE_ENROLLED -> {
                Log.w("LockActivity", "No biometric enrolled on device (check Android Settings > Security)")
            }
            BiometricAuthHelper.BiometricStatus.NO_HARDWARE -> {
                Log.w("LockActivity", "No biometric hardware available on device")
            }
            BiometricAuthHelper.BiometricStatus.HARDWARE_UNAVAILABLE -> {
                Log.w("LockActivity", "Biometric hardware temporarily unavailable")
            }
            BiometricAuthHelper.BiometricStatus.UNKNOWN_ERROR -> {
                Log.e("LockActivity", "Unknown biometric error from Android system")
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

                    // Mark as authenticated to prevent onStop from restarting lock screen
                    hasAuthenticated = true

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
        // Password visibility toggle
        findViewById<ImageView>(R.id.passwordToggle).setOnClickListener {
            isPasswordVisible = !isPasswordVisible
            val passwordInput = findViewById<EditText>(R.id.passwordInput)

            if (isPasswordVisible) {
                // Show password
                passwordInput.inputType = android.text.InputType.TYPE_CLASS_TEXT or
                                          android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                // Hide password
                passwordInput.inputType = android.text.InputType.TYPE_CLASS_TEXT or
                                          android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            // Move cursor to end
            passwordInput.setSelection(passwordInput.text.length)
        }

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

                // Mark as authenticated to prevent onStop from restarting lock screen
                hasAuthenticated = true

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

                    // Offer biometric enrollment first, then unlock app
                    // If biometric dialog is shown, unlockApp() is called after user responds
                    // If no dialog shown, unlockApp() is called immediately
                    offerBiometricEnrollment(keyManager) {
                        unlockApp()
                    }
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

    }

    private fun setupForgotPasswordText() {
        val forgotPasswordTextView = findViewById<TextView>(R.id.forgotPasswordText)
        val fullText = "Forgot Password? Import Recovery"
        val spannableString = SpannableString(fullText)

        // "Forgot Password? " (with space) in gray (#888888)
        spannableString.setSpan(
            ForegroundColorSpan(0xFF888888.toInt()),
            0,
            17, // "Forgot Password?" length (without space)
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )

        // "Import Recovery" in white (#FFFFFF)
        spannableString.setSpan(
            ForegroundColorSpan(0xFFFFFFFF.toInt()),
            17, // Start at space before "Import Recovery"
            fullText.length,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )

        forgotPasswordTextView.text = spannableString

        // Make it clickable and open RestoreAccountActivity
        forgotPasswordTextView.setOnClickListener {
            Log.d("LockActivity", "Import Recovery clicked - opening RestoreAccountActivity")
            val intent = Intent(this, RestoreAccountActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
        }
    }

    /**
     * Offer biometric enrollment on first successful password login
     * @param onComplete Callback to execute after biometric dialog is handled (or immediately if not shown)
     */
    private fun offerBiometricEnrollment(keyManager: KeyManager, onComplete: () -> Unit) {
        // Only offer if biometric is available but not enabled yet
        if (biometricHelper.isBiometricAvailable() == BiometricAuthHelper.BiometricStatus.AVAILABLE &&
            !biometricHelper.isBiometricEnabled()) {

            // Check if we already asked the user (to avoid repeated prompts)
            val prefs = getSharedPreferences("biometric_prefs", MODE_PRIVATE)
            val alreadyAsked = prefs.getBoolean("biometric_enrollment_asked", false)

            if (!alreadyAsked) {
                Log.d("LockActivity", "Offering biometric enrollment to user")

                // SECURITY FIX: Show dialog first, mark as asked when user responds
                // This prevents repeated prompts even if user cancels biometric scan
                android.app.AlertDialog.Builder(this)
                    .setTitle("Enable Biometric Unlock?")
                    .setMessage("Use fingerprint or face unlock instead of typing your password every time.")
                    .setPositiveButton("Enable") { _, _ ->
                        // Get password hash for encryption
                        val passwordHash = keyManager.getPasswordHash()
                        if (passwordHash != null) {
                            biometricHelper.enableBiometric(
                                passwordHash = passwordHash,
                                activity = this,
                                onSuccess = {
                                    Log.i("LockActivity", "Biometric enrollment successful")
                                    ThemedToast.show(this, "Biometric unlock enabled")

                                    // Mark as asked ONLY after successful enrollment
                                    prefs.edit().putBoolean("biometric_enrollment_asked", true).apply()

                                    // Update UI to show biometric button
                                    findViewById<ImageView>(R.id.biometricButton).visibility = View.VISIBLE

                                    // Call completion callback
                                    onComplete()
                                },
                                onError = { error ->
                                    Log.w("LockActivity", "Biometric enrollment failed: $error")
                                    // Don't mark as asked - let user try again next login
                                    ThemedToast.show(this, "Biometric setup cancelled - try again next login")

                                    // Call completion callback even on error
                                    onComplete()
                                }
                            )
                        } else {
                            // No password hash - proceed anyway
                            onComplete()
                        }
                    }
                    .setNegativeButton("Not Now") { _, _ ->
                        // Mark as asked when user explicitly declines
                        prefs.edit().putBoolean("biometric_enrollment_asked", true).apply()
                        Log.d("LockActivity", "User declined biometric enrollment")

                        // Call completion callback
                        onComplete()
                    }
                    .setCancelable(true)
                    .setOnCancelListener {
                        // Don't mark as asked if user dismisses - let them be prompted again
                        Log.d("LockActivity", "User dismissed biometric enrollment dialog")

                        // Call completion callback
                        onComplete()
                    }
                    .show()
            } else {
                // Already asked before - proceed immediately
                onComplete()
            }
        } else {
            // Biometric not available or already enabled - proceed immediately
            onComplete()
        }
    }

    /**
     * Unlock the app and navigate to MainActivity
     */
    private fun unlockApp() {
        // Check if user has confirmed their seed phrase backup
        val setupPrefs = getSharedPreferences("account_setup", MODE_PRIVATE)
        val seedPhraseConfirmed = setupPrefs.getBoolean("seed_phrase_confirmed", true) // Default true for existing users

        if (!seedPhraseConfirmed) {
            // User has not confirmed seed phrase backup yet - redirect to AccountCreatedActivity
            Log.w("LockActivity", "User has not confirmed seed phrase backup - redirecting to AccountCreatedActivity")
            val intent = Intent(this, AccountCreatedActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
            return
        }

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

        // Clear auto-lock pause time to prevent immediate re-lock after unlock
        val lifecyclePrefs = getSharedPreferences("app_lifecycle", MODE_PRIVATE)
        lifecyclePrefs.edit().remove("last_pause_timestamp").apply()
        Log.d("LockActivity", "Cleared auto-lock pause time")

        // Mark app as unlocked (user successfully authenticated)
        com.securelegion.utils.SessionManager.setUnlocked(this)
        Log.d("LockActivity", "App unlocked - session active")

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

                // Create MessageService instance for sending
                val messageService = com.securelegion.services.MessageService(this@LockActivity)

                // Silent panic message (no UI indication)
                val panicMessage = "\uD83D\uDEA8 DISTRESS SIGNAL"

                // Send panic notification to each distress contact
                var sentCount = 0
                for (contact in distressContacts) {
                    try {
                        Log.i("LockActivity", "Sending silent distress signal to ${contact.displayName}")

                        // Send message silently (no UI callback, no read receipt)
                        val result = messageService.sendMessage(
                            contactId = contact.id,
                            plaintext = panicMessage,
                            selfDestructDurationMs = null, // No self-destruct for distress signals
                            enableReadReceipt = false,      // No read receipt for stealth
                            onMessageSaved = null            // No UI update (silent)
                        )

                        if (result.isSuccess) {
                            sentCount++
                            Log.i("LockActivity", "✓ Distress signal queued for ${contact.displayName}")
                        } else {
                            Log.e("LockActivity", "✗ Failed to queue distress signal for ${contact.displayName}: ${result.exceptionOrNull()?.message}")
                        }
                    } catch (e: Exception) {
                        Log.e("LockActivity", "Failed to send panic to ${contact.displayName}", e)
                    }
                }

                Log.w("LockActivity", "Distress protocol complete: $sentCount/${distressContacts.size} panic messages queued")
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

                // Stop TorService FIRST to prevent connection loops after wipe
                withContext(Dispatchers.Main) {
                    try {
                        val torServiceIntent = Intent(this@LockActivity, com.securelegion.services.TorService::class.java)
                        stopService(torServiceIntent)
                        Log.w("LockActivity", "Stopped TorService before wipe")
                    } catch (e: Exception) {
                        Log.e("LockActivity", "Failed to stop TorService", e)
                    }
                }

                // Wipe all cryptographic keys
                val keyManager = KeyManager.getInstance(this@LockActivity)
                keyManager.wipeAllKeys()

                // Securely wipe all data (3-pass overwrite)
                SecureWipe.wipeAllData(this@LockActivity)

                Log.w("LockActivity", "All data securely wiped")

                // Redirect to CreateAccountActivity since no account exists anymore
                withContext(Dispatchers.Main) {
                    val intent = Intent(this@LockActivity, CreateAccountActivity::class.java)
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
        // BUT: Don't restart if user successfully authenticated (prevents double login)
        if (hasWallet && !isFinishing && !hasAuthenticated) {
            Log.w("LockActivity", "Lock screen stopped without authentication - restarting on top")
            val intent = Intent(this, LockActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                          Intent.FLAG_ACTIVITY_CLEAR_TASK or
                          Intent.FLAG_ACTIVITY_NO_HISTORY
            startActivity(intent)
        }
    }
}
