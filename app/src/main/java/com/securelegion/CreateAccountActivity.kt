package com.securelegion

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.text.SpannableString
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.TorManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import com.securelegion.utils.PasswordValidator
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.web3j.crypto.MnemonicUtils
import java.security.SecureRandom

class CreateAccountActivity : AppCompatActivity() {

    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var togglePassword: ImageView
    private lateinit var toggleConfirmPassword: ImageView
    private lateinit var createAccountButton: TextView
    private lateinit var loadingOverlay: FrameLayout
    private lateinit var loadingText: TextView
    private lateinit var loadingSubtext: TextView

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
        @Suppress("DEPRECATION")
        window.statusBarColor = android.graphics.Color.WHITE
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR

        setContentView(R.layout.activity_create_account)

        // Enable edge-to-edge display
        WindowCompat.setDecorFitsSystemWindows(window, false)

        initializeViews()
        setupClickListeners()

        // Handle window insets for proper keyboard behavior
        val scrollView = findViewById<View>(R.id.scrollView)
        val alreadyHaveAccountText = findViewById<View>(R.id.alreadyHaveAccountText)

        ViewCompat.setOnApplyWindowInsetsListener(scrollView) { view, windowInsets ->
            val systemInsets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout()
            )

            // Get IME (keyboard) insets
            val imeInsets = windowInsets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = windowInsets.isVisible(WindowInsetsCompat.Type.ime())

            // Apply top inset to ScrollView
            view.setPadding(
                0,
                systemInsets.top,
                0,
                if (imeVisible) imeInsets.bottom else 0
            )

            // Hide "already have account" text when keyboard is visible
            alreadyHaveAccountText.visibility = if (imeVisible) View.GONE else View.VISIBLE

            windowInsets
        }
    }

    private fun initializeViews() {
        usernameInput = findViewById(R.id.usernameInput)
        passwordInput = findViewById(R.id.passwordInput)
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput)
        togglePassword = findViewById(R.id.togglePassword)
        toggleConfirmPassword = findViewById(R.id.toggleConfirmPassword)
        createAccountButton = findViewById(R.id.createAccountButton)
        loadingOverlay = findViewById(R.id.loadingOverlay)
        loadingText = findViewById(R.id.loadingText)
        loadingSubtext = findViewById(R.id.loadingSubtext)

        // Setup "Already have an account? Import" text
        val alreadyHaveAccountText = findViewById<TextView>(R.id.alreadyHaveAccountText)
        val fullText = "Already have an account? Import"
        val spannable = SpannableString(fullText)

        val importStart = fullText.indexOf("Import")
        val importEnd = importStart + "Import".length

        // Set base text color to gray
        spannable.setSpan(ForegroundColorSpan(0xFF999999.toInt()), 0, fullText.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)

        // Make "Import" clickable and white
        val clickableSpan = object : ClickableSpan() {
            override fun onClick(widget: View) {
                // Navigate to Import Account screen
                val intent = Intent(this@CreateAccountActivity, RestoreAccountActivity::class.java)
                startActivity(intent)
            }
        }

        spannable.setSpan(clickableSpan, importStart, importEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        spannable.setSpan(ForegroundColorSpan(0xFFFFFFFF.toInt()), importStart, importEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)

        alreadyHaveAccountText.text = spannable
        alreadyHaveAccountText.movementMethod = LinkMovementMethod.getInstance()
    }

    private fun showLoading(text: String, subtext: String = "Please wait") {
        loadingText.text = text
        loadingSubtext.text = subtext
        loadingOverlay.visibility = View.VISIBLE
    }

    private fun hideLoading() {
        loadingOverlay.visibility = View.GONE
    }

    private fun setupClickListeners() {
        // Password visibility toggles
        togglePassword.setOnClickListener {
            isPasswordVisible = !isPasswordVisible
            if (isPasswordVisible) {
                passwordInput.inputType = InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                passwordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            passwordInput.setSelection(passwordInput.text.length)
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

        // Create Account button
        createAccountButton.setOnClickListener {
            val username = usernameInput.text.toString()
            val password = passwordInput.text.toString()
            val confirmPassword = confirmPasswordInput.text.toString()

            if (username.isEmpty()) {
                ThemedToast.show(this, "Please enter a username")
                return@setOnClickListener
            }

            if (password.isEmpty()) {
                ThemedToast.show(this, "Please enter a password")
                return@setOnClickListener
            }

            if (password != confirmPassword) {
                ThemedToast.show(this, "Passwords do not match")
                return@setOnClickListener
            }

            // Validate password complexity using PasswordValidator
            val validation = PasswordValidator.validate(password)
            if (!validation.isValid) {
                ThemedToast.showLong(this, validation.errorMessage ?: "Invalid password")
                return@setOnClickListener
            }

            // Hide passwords if they were visible
            if (isPasswordVisible) {
                passwordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                isPasswordVisible = false
            }
            if (isConfirmPasswordVisible) {
                confirmPasswordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                isConfirmPasswordVisible = false
            }

            // Hide keyboard
            val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
            imm.hideSoftInputFromWindow(currentFocus?.windowToken, 0)

            // Show loading immediately to prevent double-tap
            showLoading("Creating Account...", "Please wait")
            createAccountButton.isEnabled = false

            createAccount()
        }
    }

    private fun createAccount() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d("CreateAccount", "Starting account creation...")

                // Show loading overlay (stays until completion)
                // No need to update - keep simple "Creating Account..." message

                // Generate 128-bit entropy for 12-word BIP39 mnemonic
                val entropy = ByteArray(16) // 128 bits = 12 words
                SecureRandom().nextBytes(entropy)

                // Generate BIP39 mnemonic from entropy
                val mnemonic = MnemonicUtils.generateMnemonic(entropy)
                Log.d("CreateAccount", "Generated 12-word mnemonic seed phrase")

                // Initialize KeyManager with the mnemonic
                val keyManager = KeyManager.getInstance(this@CreateAccountActivity)
                keyManager.initializeFromSeed(mnemonic)
                Log.i("CreateAccount", "KeyManager initialized from seed")

                // Set device password
                val password = passwordInput.text.toString()
                keyManager.setDevicePassword(password)
                Log.i("CreateAccount", "Device password set")

                // Store username
                val username = usernameInput.text.toString()
                keyManager.storeUsername(username)
                Log.i("CreateAccount", "Username stored: $username")

                // Store the seed phrase for display on next screen
                keyManager.storeSeedPhrase(mnemonic)
                Log.i("CreateAccount", "Seed phrase stored for display")

                // Store permanently for main wallet (needed for Zcash)
                keyManager.storeMainWalletSeed(mnemonic)
                Log.i("CreateAccount", "Seed phrase stored permanently for main wallet")

                // Get the Solana wallet address
                val walletAddress = keyManager.getSolanaAddress()
                Log.i("CreateAccount", "Solana address: $walletAddress")

                // Initialize Zcash wallet (async - runs in background)
                Log.i("CreateAccount", "Starting Zcash wallet initialization in background...")
                val zcashPrefs = getSharedPreferences("zcash_init", MODE_PRIVATE)
                zcashPrefs.edit().putBoolean("initializing", true).apply()

                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val zcashService = com.securelegion.services.ZcashService.getInstance(this@CreateAccountActivity)
                        val result = zcashService.initialize(mnemonic, useTestnet = false)
                        if (result.isSuccess) {
                            val zcashAddress = result.getOrNull()
                            Log.i("CreateAccount", "Zcash wallet initialized: $zcashAddress")

                            // Create wallet entry in database now that initialization is complete
                            if (zcashAddress != null) {
                                val keyManager = KeyManager.getInstance(this@CreateAccountActivity)
                                val dbPassphrase = keyManager.getDatabasePassphrase()
                                val database = SecureLegionDatabase.getInstance(this@CreateAccountActivity, dbPassphrase)

                                // Get birthday height from ZcashService
                                val birthdayHeight = zcashService.getBirthdayHeight()
                                Log.i("CreateAccount", "Zcash birthday height: $birthdayHeight")

                                val zcashWalletId = "wallet_zcash_${System.currentTimeMillis()}"
                                val defaultZcashWallet = Wallet(
                                    walletId = zcashWalletId,
                                    name = "Wallet 2",
                                    solanaAddress = "",
                                    zcashUnifiedAddress = zcashAddress,
                                    zcashAccountIndex = 0,
                                    zcashBirthdayHeight = birthdayHeight,
                                    isActiveZcash = true,
                                    isMainWallet = false,
                                    createdAt = System.currentTimeMillis(),
                                    lastUsedAt = System.currentTimeMillis() - 1
                                )
                                database.walletDao().insertWallet(defaultZcashWallet)

                                // Store seed phrase for Zcash wallet
                                keyManager.storeWalletSeed(zcashWalletId, mnemonic)
                                Log.i("CreateAccount", "Zcash wallet entry created in database with birthday height: $birthdayHeight")
                            }
                        } else {
                            Log.e("CreateAccount", "Failed to initialize Zcash wallet: ${result.exceptionOrNull()?.message}")
                        }
                    } catch (e: Exception) {
                        Log.e("CreateAccount", "Error initializing Zcash wallet", e)
                    } finally {
                        // Mark initialization as complete
                        zcashPrefs.edit().putBoolean("initializing", false).apply()
                        Log.i("CreateAccount", "Zcash initialization complete")
                    }
                }

                // Creating hidden service (no loading update - keep "Creating Account..." message)

                // Create hidden service and wait for it to complete
                Log.i("CreateAccount", "Creating hidden service for account")
                val torManager = TorManager.getInstance(this@CreateAccountActivity)
                val onionAddress = withContext(Dispatchers.IO) {
                    // Create hidden service synchronously
                    val existingAddress = torManager.getOnionAddress()
                    if (existingAddress != null) {
                        Log.d("CreateAccount", "Hidden service already exists: $existingAddress")
                        existingAddress
                    } else {
                        // Wait for Tor to be ready and create hidden service
                        var attempts = 0
                        val maxAttempts = 30
                        while (attempts < maxAttempts) {
                            val status = com.securelegion.crypto.RustBridge.getBootstrapStatus()
                            if (status >= 100) break
                            Log.d("CreateAccount", "Waiting for Tor bootstrap: $status%")
                            Thread.sleep(1000)
                            attempts++
                        }

                        if (attempts >= maxAttempts) {
                            throw Exception("Tor bootstrap timeout")
                        }

                        Log.d("CreateAccount", "Creating hidden service...")
                        val address = com.securelegion.crypto.RustBridge.createHiddenService(9150, 8080)
                        torManager.saveOnionAddress(address)
                        Log.i("CreateAccount", "Hidden service created: $address")
                        address
                    }
                }

                // Voice onion address will be created automatically by TorService on first startup
                // (Single Onion Services must be configured in torrc, not via ADD_ONION)
                Log.i("CreateAccount", "Voice onion will be created by TorService from torrc hostname file")
                val voiceOnionAddress = "" // Will be populated by TorService on first launch

                // Generate random PIN first
                val cardManager = ContactCardManager(this@CreateAccountActivity)
                val contactCardPin = cardManager.generateRandomPin()

                // Create friend request .onion address (v2.0) - retry until success
                var friendRequestOnion = ""
                var friendRequestAttempt = 0
                while (friendRequestOnion.isEmpty()) {
                    try {
                        friendRequestAttempt++
                        Log.d("CreateAccount", "Creating friend request .onion address (attempt $friendRequestAttempt)...")
                        friendRequestOnion = keyManager.createFriendRequestOnion()
                        Log.i("CreateAccount", "Friend request .onion: $friendRequestOnion")
                    } catch (e: Exception) {
                        Log.e("CreateAccount", "Failed to create friend request .onion (attempt $friendRequestAttempt): ${e.message}", e)
                        if (friendRequestAttempt < 5) {
                            Thread.sleep(2000) // Wait 2 seconds before retry
                        } else {
                            throw Exception("Failed to create friend request .onion after $friendRequestAttempt attempts: ${e.message}")
                        }
                    }
                }

                // Derive IPFS CID from seed (v2.0) - retry until success
                var ipfsCid = ""
                var ipfsCidAttempt = 0
                while (ipfsCid.isEmpty()) {
                    try {
                        ipfsCidAttempt++
                        Log.d("CreateAccount", "Deriving IPFS CID from seed (attempt $ipfsCidAttempt)...")
                        ipfsCid = keyManager.deriveIPFSCID(mnemonic)
                        keyManager.storeIPFSCID(ipfsCid)
                        Log.i("CreateAccount", "IPFS CID: $ipfsCid")
                    } catch (e: Exception) {
                        Log.e("CreateAccount", "Failed to derive IPFS CID (attempt $ipfsCidAttempt): ${e.message}", e)
                        if (ipfsCidAttempt < 5) {
                            Thread.sleep(2000) // Wait 2 seconds before retry
                        } else {
                            throw Exception("Failed to derive IPFS CID after $ipfsCidAttempt attempts: ${e.message}")
                        }
                    }
                }

                // Create and upload contact card
                Log.d("CreateAccount", "Creating contact card...")
                val contactCard = ContactCard(
                    displayName = username,
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    kyberPublicKey = keyManager.getKyberPublicKey(),
                    solanaAddress = keyManager.getSolanaAddress(),
                    friendRequestOnion = friendRequestOnion,
                    messagingOnion = onionAddress,
                    voiceOnion = voiceOnionAddress,
                    contactPin = contactCardPin,
                    ipfsCid = ipfsCid,
                    timestamp = System.currentTimeMillis()
                )
                // Store contact card info in encrypted storage
                keyManager.storeContactPin(contactCardPin)
                keyManager.storeIPFSCID(ipfsCid)
                // Note: friendRequestOnion already stored by createFriendRequestOnion()
                keyManager.storeMessagingOnion(onionAddress)

                // Initialize internal wallet in database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@CreateAccountActivity, dbPassphrase)
                val timestamp = System.currentTimeMillis()
                val mainWallet = Wallet(
                    walletId = "main",
                    name = "Wallet 1",
                    solanaAddress = keyManager.getSolanaAddress(),
                    isMainWallet = true,
                    createdAt = timestamp,
                    lastUsedAt = timestamp
                )
                database.walletDao().insertWallet(mainWallet)
                Log.i("CreateAccount", "Internal wallet initialized in database")

                // Create default Solana wallet for user (separate from account wallet)
                Log.d("CreateAccount", "Creating default Solana wallet...")
                val (defaultSolWalletId, defaultSolAddress) = keyManager.generateNewWallet()
                val defaultSolanaWallet = Wallet(
                    walletId = defaultSolWalletId,
                    name = "Wallet 1",
                    solanaAddress = defaultSolAddress,
                    isMainWallet = false,
                    createdAt = timestamp,
                    lastUsedAt = timestamp
                )
                database.walletDao().insertWallet(defaultSolanaWallet)
                Log.i("CreateAccount", "Default Solana wallet created: $defaultSolAddress")

                // Note: Zcash wallet will be created in background when initialization completes
                Log.i("CreateAccount", "Zcash wallet will be created automatically when initialization finishes")

                Log.i("CreateAccount", "Contact card created (local only, not uploaded)")
                Log.i("CreateAccount", "CID: $ipfsCid (deterministic from seed)")
                Log.i("CreateAccount", "PIN: $contactCardPin")

                // Mark that seed phrase has NOT been confirmed yet
                val setupPrefs = getSharedPreferences("account_setup", MODE_PRIVATE)
                setupPrefs.edit().putBoolean("seed_phrase_confirmed", false).apply()
                Log.i("CreateAccount", "Set seed_phrase_confirmed = false (user must confirm backup)")

                // Navigate to Account Created screen to show CID, PIN, and seed phrase
                val intent = Intent(this@CreateAccountActivity, AccountCreatedActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                startActivity(intent)
                finish()

            } catch (e: Exception) {
                Log.e("CreateAccount", "Failed to create account", e)

                // Hide loading overlay
                hideLoading()

                ThemedToast.showLong(this@CreateAccountActivity, "Failed to create account: ${e.message}")

                // Re-enable button so user can retry
                createAccountButton.isEnabled = true
            }
        }
    }
}
