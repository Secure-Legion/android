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
    private lateinit var newPasswordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var togglePassword: ImageView
    private lateinit var toggleConfirmPassword: ImageView
    private lateinit var zcashBirthdayInput: EditText
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

        newPasswordInput = findViewById(R.id.newPasswordInput)
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput)
        togglePassword = findViewById(R.id.togglePassword)
        toggleConfirmPassword = findViewById(R.id.toggleConfirmPassword)
        zcashBirthdayInput = findViewById(R.id.zcashBirthdayInput)
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
            val seedPhrase = collectSeedPhrase()
            val newPassword = newPasswordInput.text.toString()
            val confirmPassword = confirmPasswordInput.text.toString()

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

            // Parse optional Zcash birthday height
            val birthdayHeight = zcashBirthdayInput.text.toString().toLongOrNull()

            restoreAccount(seedPhrase, newPassword, birthdayHeight)
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

    private fun restoreAccount(seedPhrase: String, password: String, zcashBirthdayHeight: Long? = null) {
        // Disable button to prevent double-tap
        importButton.isEnabled = false
        importButton.alpha = 0.5f

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    Log.d("RestoreAccount", "Restoring account from seed phrase")

                    // Initialize KeyManager with the seed phrase
                    val keyManager = KeyManager.getInstance(this@RestoreAccountActivity)
                    keyManager.initializeFromSeed(seedPhrase)
                    Log.i("RestoreAccount", "KeyManager initialized from seed")

                    // Set device password
                    keyManager.setDevicePassword(password)
                    Log.i("RestoreAccount", "Device password set")

                    // Store the seed phrase
                    keyManager.storeSeedPhrase(seedPhrase)
                    Log.i("RestoreAccount", "Seed phrase stored")

                    // Get the Solana wallet address
                    val walletAddress = keyManager.getSolanaAddress()
                    Log.i("RestoreAccount", "Solana address: $walletAddress")

                    // Initialize Zcash wallet with optional birthday height
                    Log.i("RestoreAccount", "Initializing Zcash wallet...")
                    if (zcashBirthdayHeight != null) {
                        Log.i("RestoreAccount", "Using birthday height: $zcashBirthdayHeight")
                    }
                    try {
                        val zcashService = ZcashService.getInstance(this@RestoreAccountActivity)
                        val result = zcashService.initialize(
                            seedPhrase = seedPhrase,
                            useTestnet = false,
                            birthdayHeight = zcashBirthdayHeight
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

                    // IPFS Contact List Recovery (v5 Architecture)
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
                for (editText in seedWords) {
                    editText.text.clear()
                }
                newPasswordInput.text.clear()
                confirmPasswordInput.text.clear()
                zcashBirthdayInput.text.clear()

                ThemedToast.show(this@RestoreAccountActivity, "Account restored successfully!")

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
