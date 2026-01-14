package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.services.ZcashService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class RestoreAccountActivity : AppCompatActivity() {

    private val seedWords = mutableListOf<EditText>()
    private lateinit var usernameInput: EditText
    private lateinit var newPasswordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var togglePassword: ImageView
    private lateinit var toggleConfirmPassword: ImageView
    private lateinit var importButton: TextView

    private var isPasswordVisible = false
    private var isConfirmPasswordVisible = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Make status bar white with dark icons
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            @Suppress("DEPRECATION")
            window.statusBarColor = android.graphics.Color.WHITE
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
        }

        setContentView(R.layout.activity_restore_account)

        // Enable edge-to-edge display
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // Handle window insets for proper keyboard behavior
        val rootView = findViewById<View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(rootView) { view, windowInsets ->
            val systemInsets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout()
            )

            // Get IME (keyboard) insets
            val imeInsets = windowInsets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = windowInsets.isVisible(WindowInsetsCompat.Type.ime())

            // Apply bottom inset to root ScrollView
            // Use IME insets when keyboard is visible, otherwise use system insets
            view.setPadding(
                systemInsets.left,
                0,
                systemInsets.right,
                if (imeVisible) imeInsets.bottom else systemInsets.bottom
            )

            windowInsets
        }

        initializeViews()
        setupClickListeners()
    }

    private fun initializeViews() {
        // Initialize all 12 seed word EditTexts
        seedWords.add(findViewById(R.id.word1))
        seedWords.add(findViewById(R.id.word2))
        seedWords.add(findViewById(R.id.word3))
        seedWords.add(findViewById(R.id.word4))
        seedWords.add(findViewById(R.id.word5))
        seedWords.add(findViewById(R.id.word6))
        seedWords.add(findViewById(R.id.word7))
        seedWords.add(findViewById(R.id.word8))
        seedWords.add(findViewById(R.id.word9))
        seedWords.add(findViewById(R.id.word10))
        seedWords.add(findViewById(R.id.word11))
        seedWords.add(findViewById(R.id.word12))

        usernameInput = findViewById(R.id.usernameInput)
        newPasswordInput = findViewById(R.id.newPasswordInput)
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput)
        togglePassword = findViewById(R.id.togglePassword)
        toggleConfirmPassword = findViewById(R.id.toggleConfirmPassword)
        importButton = findViewById(R.id.importButton)
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Password visibility toggles
        togglePassword.setOnClickListener {
            isPasswordVisible = !isPasswordVisible
            if (isPasswordVisible) {
                newPasswordInput.inputType = InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                newPasswordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            newPasswordInput.setSelection(newPasswordInput.text.length)
        }

        toggleConfirmPassword.setOnClickListener {
            isConfirmPasswordVisible = !isConfirmPasswordVisible
            if (isConfirmPasswordVisible) {
                confirmPasswordInput.inputType = InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                confirmPasswordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            confirmPasswordInput.setSelection(confirmPasswordInput.text.length)
        }

        // Import button
        importButton.setOnClickListener {
            val username = usernameInput.text.toString().trim()
            val seedPhrase = collectSeedPhrase()
            val newPassword = newPasswordInput.text.toString()
            val confirmPassword = confirmPasswordInput.text.toString()

            if (username.isEmpty()) {
                ThemedToast.show(this, "Please enter your username")
                return@setOnClickListener
            }

            if (seedPhrase.isEmpty()) {
                ThemedToast.show(this, "Please enter all 12 seed words")
                return@setOnClickListener
            }

            if (newPassword.isEmpty()) {
                ThemedToast.show(this, "Please enter a new password")
                return@setOnClickListener
            }

            if (newPassword != confirmPassword) {
                ThemedToast.show(this, "Passwords do not match")
                return@setOnClickListener
            }

            // Validate password requirements
            if (newPassword.length < 9) {
                ThemedToast.show(this, "Password must be at least 9 characters")
                return@setOnClickListener
            }

            if (!newPassword.any { it.isUpperCase() }) {
                ThemedToast.show(this, "Password must contain an uppercase letter")
                return@setOnClickListener
            }

            if (!newPassword.any { it.isLowerCase() }) {
                ThemedToast.show(this, "Password must contain a lowercase letter")
                return@setOnClickListener
            }

            if (!newPassword.any { it.isDigit() }) {
                ThemedToast.show(this, "Password must contain a number")
                return@setOnClickListener
            }

            if (!newPassword.any { it in "!@#$%^&*" }) {
                ThemedToast.show(this, "Password must contain a special character (!@#$%^&*)")
                return@setOnClickListener
            }

            restoreAccount(username, seedPhrase, newPassword)
        }
    }

    private fun collectSeedPhrase(): String {
        val words = mutableListOf<String>()
        for (editText in seedWords) {
            val word = editText.text.toString().trim()
            if (word.isEmpty()) {
                return ""
            }
            words.add(word)
        }
        return words.joinToString(" ")
    }

    private fun restoreAccount(username: String, seedPhrase: String, password: String) {
        // Disable button to prevent double-tap
        importButton.isEnabled = false
        importButton.alpha = 0.5f

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    Log.d("RestoreAccount", "Restoring account from seed phrase")

                    // Step 1: Initialize KeyManager with the seed phrase
                    val keyManager = KeyManager.getInstance(this@RestoreAccountActivity)
                    keyManager.initializeFromSeed(seedPhrase)
                    Log.i("RestoreAccount", "KeyManager initialized from seed")

                    // Step 2: Set device password
                    keyManager.setDevicePassword(password)
                    Log.i("RestoreAccount", "Device password set")

                    // Step 3: Store username
                    keyManager.storeUsername(username)
                    Log.i("RestoreAccount", "Username stored: $username")

                    // Step 4: Store the seed phrase
                    keyManager.storeSeedPhrase(seedPhrase)
                    Log.i("RestoreAccount", "Seed phrase stored for display")

                    // Step 5: Store permanently for main wallet (needed for Zcash)
                    keyManager.storeMainWalletSeed(seedPhrase)
                    Log.i("RestoreAccount", "Seed phrase stored permanently for main wallet")

                    // Step 6: Get the Solana wallet address
                    val walletAddress = keyManager.getSolanaAddress()
                    Log.i("RestoreAccount", "Solana address: $walletAddress")

                    // Step 7: Initialize Zcash wallet (async)
                    Log.i("RestoreAccount", "Initializing Zcash wallet...")
                    try {
                        val zcashService = ZcashService.getInstance(this@RestoreAccountActivity)
                        val result = zcashService.initialize(
                            seedPhrase = seedPhrase,
                            useTestnet = false
                        )
                        if (result.isSuccess) {
                            val zcashAddress = result.getOrNull()
                            Log.i("RestoreAccount", "Zcash wallet initialized: $zcashAddress")
                        } else {
                            Log.e("RestoreAccount", "Failed to initialize Zcash wallet: ${result.exceptionOrNull()?.message}")
                        }
                    } catch (e: Exception) {
                        Log.e("RestoreAccount", "Error initializing Zcash wallet", e)
                        // Continue anyway - Solana will still work
                    }

                    // Step 8: Create messaging .onion address (deterministic from seed)
                    Log.i("RestoreAccount", "Restoring messaging hidden service from seed...")
                    val torManager = com.securelegion.crypto.TorManager.getInstance(this@RestoreAccountActivity)
                    val messagingOnion = withContext(Dispatchers.IO) {
                        // Wait for Tor to be ready
                        var attempts = 0
                        val maxAttempts = 30
                        while (attempts < maxAttempts) {
                            val status = com.securelegion.crypto.RustBridge.getBootstrapStatus()
                            if (status >= 100) break
                            Log.d("RestoreAccount", "Waiting for Tor bootstrap: $status%")
                            Thread.sleep(1000)
                            attempts++
                        }

                        if (attempts >= maxAttempts) {
                            throw Exception("Tor bootstrap timeout")
                        }

                        // Clear any orphaned ephemeral services from previous failed attempts
                        // This prevents "service already registered" errors in Tor
                        try {
                            Log.d("RestoreAccount", "Clearing orphaned ephemeral hidden services...")
                            val clearedCount = com.securelegion.crypto.RustBridge.clearAllEphemeralServices()
                            Log.i("RestoreAccount", "Cleared $clearedCount orphaned service(s)")
                        } catch (e: Exception) {
                            Log.w("RestoreAccount", "Failed to clear ephemeral services (continuing anyway): ${e.message}")
                        }

                        // Retry hidden service creation with exponential backoff
                        var createAttempt = 0
                        val maxCreateAttempts = 5
                        var address: String? = null
                        var lastError: Exception? = null

                        while (createAttempt < maxCreateAttempts && address == null) {
                            try {
                                createAttempt++
                                Log.d("RestoreAccount", "Restoring hidden service from seed (attempt $createAttempt/$maxCreateAttempts)...")
                                address = com.securelegion.crypto.RustBridge.createHiddenService(9150, 8080)
                                torManager.saveOnionAddress(address)
                                Log.i("RestoreAccount", "Hidden service restored from seed: $address")
                            } catch (e: Exception) {
                                lastError = e
                                Log.e("RestoreAccount", "Failed to restore hidden service (attempt $createAttempt): ${e.message}", e)
                                if (createAttempt < maxCreateAttempts) {
                                    val delayMs = 2000L * createAttempt // Exponential backoff: 2s, 4s, 6s, 8s
                                    Log.d("RestoreAccount", "Waiting ${delayMs}ms before retry...")
                                    Thread.sleep(delayMs)
                                }
                            }
                        }

                        if (address == null) {
                            throw Exception("Failed to restore hidden service after $maxCreateAttempts attempts: ${lastError?.message}")
                        }

                        address
                    }

                    // Step 9: Derive and store deterministic contact PIN
                    Log.d("RestoreAccount", "Deriving contact PIN from seed...")
                    val contactPin = keyManager.deriveContactPinFromSeed(seedPhrase)
                    keyManager.storeContactPin(contactPin)
                    Log.i("RestoreAccount", "Contact PIN derived and stored: $contactPin")

                    // Step 10: Create friend request .onion address (v2.0)
                    Log.d("RestoreAccount", "Creating friend request .onion address...")
                    val friendRequestOnion = keyManager.createFriendRequestOnion()
                    Log.i("RestoreAccount", "Friend request .onion: $friendRequestOnion")

                    // Step 11: Derive and store IPFS contact list CID (v5 architecture)
                    Log.d("RestoreAccount", "Deriving contact list CID from seed...")
                    val contactListCID = keyManager.deriveContactListCIDFromSeed(seedPhrase)
                    // Note: In v5, we don't store the old card CID, only list CID
                    Log.i("RestoreAccount", "Contact list CID: $contactListCID")

                    // Step 12: Store messaging .onion
                    keyManager.storeMessagingOnion(messagingOnion)
                    Log.i("RestoreAccount", "Messaging .onion stored")

                    // Step 13: Initialize internal wallet in database
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@RestoreAccountActivity, dbPassphrase)
                    val timestamp = System.currentTimeMillis()
                    val mainWallet = com.securelegion.database.entities.Wallet(
                        walletId = "main",
                        name = "Wallet 1",
                        solanaAddress = keyManager.getSolanaAddress(),
                        isMainWallet = true,
                        createdAt = timestamp,
                        lastUsedAt = timestamp
                    )
                    database.walletDao().insertWallet(mainWallet)
                    Log.i("RestoreAccount", "Internal wallet initialized in database")

                    // Step 14: IPFS Contact List Recovery (v5 Architecture)
                    // Attempt to recover contact list from IPFS mesh
                    Log.i("RestoreAccount", "Attempting to recover contact list from IPFS mesh...")
                    try {
                        val contactListManager = com.securelegion.services.ContactListManager.getInstance(this@RestoreAccountActivity)
                        val recoveryResult = contactListManager.recoverFromIPFS(seedPhrase)

                        if (recoveryResult.isSuccess) {
                            val contactsRecovered = recoveryResult.getOrNull()
                            if (contactsRecovered != null && contactsRecovered > 0) {
                                Log.i("RestoreAccount", "✓ Recovered $contactsRecovered contacts from IPFS mesh!")
                            } else {
                                Log.i("RestoreAccount", "No contacts found in IPFS mesh (this is normal for new accounts)")
                            }
                        } else {
                            Log.w("RestoreAccount", "Failed to recover contacts from IPFS mesh: ${recoveryResult.exceptionOrNull()?.message}")
                            // Non-critical error - continue with account restoration
                        }
                    } catch (e: Exception) {
                        Log.w("RestoreAccount", "IPFS contact list recovery error (non-critical)", e)
                        // Continue anyway - user can add friends manually
                    }
                }

                // Clear inputs
                usernameInput.text.clear()
                for (editText in seedWords) {
                    editText.text.clear()
                }
                newPasswordInput.text.clear()
                confirmPasswordInput.text.clear()

                ThemedToast.show(this@RestoreAccountActivity, "Account restored successfully!")

                // Mark seed phrase as confirmed (user restored with it, so they have it)
                val setupPrefs = getSharedPreferences("account_setup", MODE_PRIVATE)
                setupPrefs.edit().putBoolean("seed_phrase_confirmed", true).apply()

                // Navigate to MainActivity
                val intent = Intent(this@RestoreAccountActivity, MainActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                startActivity(intent)
                finish()

            } catch (e: Exception) {
                Log.e("RestoreAccount", "Failed to restore account", e)
                withContext(Dispatchers.Main) {
                    importButton.isEnabled = true
                    importButton.alpha = 1.0f
                    ThemedToast.show(this@RestoreAccountActivity, "Failed to restore account: ${e.message}")
                }
            }
        }
    }
}
