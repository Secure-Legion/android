package com.securelegion

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.SpannableString
import android.text.Spanned
import android.text.TextWatcher
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
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ComposeView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import com.securelegion.utils.PasswordValidator
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.lifecycle.lifecycleScope
import org.web3j.crypto.MnemonicUtils
import java.security.SecureRandom

class CreateAccountActivity : AppCompatActivity() {

    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var togglePassword: ImageView
    private lateinit var toggleConfirmPassword: ImageView
    private lateinit var createAccountButton: TextView
    private lateinit var loadingIndicatorView: ComposeView
    private lateinit var passwordMatchText: TextView

    private var isPasswordVisible = false
    private var isConfirmPasswordVisible = false
    private var isRestore = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        // TODO: Re-enable FLAG_SECURE after demo recording
        // window.setFlags(
        // WindowManager.LayoutParams.FLAG_SECURE,
        // WindowManager.LayoutParams.FLAG_SECURE
        // )

        // Make status bar transparent with light icons (matches dark theme)
        window.statusBarColor = android.graphics.Color.TRANSPARENT

        setContentView(R.layout.activity_create_account)

        // Enable edge-to-edge display
        WindowCompat.setDecorFitsSystemWindows(window, false)

        isRestore = intent.getBooleanExtra("is_restore", false)

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
        loadingIndicatorView = findViewById(R.id.loadingIndicatorView)
        passwordMatchText = findViewById(R.id.passwordMatchText)

        // Set up the Compose content for the M3 LoadingIndicator
        loadingIndicatorView.setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                LoadingIndicatorContent()
            }
        }

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

        // Live password match feedback
        val matchWatcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                updatePasswordMatchIndicator()
            }
        }
        passwordInput.addTextChangedListener(matchWatcher)
        confirmPasswordInput.addTextChangedListener(matchWatcher)
    }

    private fun updatePasswordMatchIndicator() {
        val password = passwordInput.text.toString()
        val confirm = confirmPasswordInput.text.toString()

        if (confirm.isEmpty()) {
            passwordMatchText.visibility = View.GONE
            return
        }

        passwordMatchText.visibility = View.VISIBLE
        if (password == confirm) {
            passwordMatchText.text = "Passwords match"
            passwordMatchText.setTextColor(0xFF00CC66.toInt())
        } else {
            passwordMatchText.text = "Passwords do not match"
            passwordMatchText.setTextColor(0xFFFF6666.toInt())
        }
    }

    private fun showLoading() {
        createAccountButton.visibility = View.INVISIBLE
        loadingIndicatorView.visibility = View.VISIBLE
    }

    private fun hideLoading() {
        loadingIndicatorView.visibility = View.GONE
        createAccountButton.visibility = View.VISIBLE
    }

    @Composable
    private fun LoadingIndicatorContent() {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            CircularProgressIndicator(
                color = Color(0xFF999999)
            )
        }
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

            // Show loading indicator on button to prevent double-tap
            showLoading()
            createAccountButton.isEnabled = false

            createAccount()
        }
    }

    private fun createAccount() {
        // Capture UI values on Main before switching to IO
        val password = passwordInput.text.toString()
        val username = usernameInput.text.toString()

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    Log.d("CreateAccount", "Starting account creation (restore=$isRestore)...")

                    // Get or generate seed phrase
                    val mnemonic: String
                    if (isRestore) {
                        val prefs = getSharedPreferences("restore_temp", MODE_PRIVATE)
                        mnemonic = prefs.getString("seed_phrase", "")!!
                        // Clear temporary storage immediately
                        prefs.edit().remove("seed_phrase").apply()
                        Log.d("CreateAccount", "Using imported seed phrase")
                    } else {
                        // Generate 128-bit entropy for 12-word BIP39 mnemonic
                        val entropy = ByteArray(16) // 128 bits = 12 words
                        SecureRandom().nextBytes(entropy)
                        mnemonic = MnemonicUtils.generateMnemonic(entropy)
                        Log.d("CreateAccount", "Generated 12-word mnemonic seed phrase")
                    }

                    // Initialize KeyManager with the mnemonic
                    val keyManager = KeyManager.getInstance(this@CreateAccountActivity)
                    keyManager.initializeFromSeed(mnemonic)
                    Log.i("CreateAccount", "KeyManager initialized from seed")

                    // Set device password
                    keyManager.setDevicePassword(password)
                    Log.i("CreateAccount", "Device password set")

                    // Store username
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
                                    val km = KeyManager.getInstance(this@CreateAccountActivity)
                                    val dbPassphrase = km.getDatabasePassphrase()
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
                                    km.storeWalletSeed(zcashWalletId, mnemonic)
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

                    // Pre-compute all 3 onion addresses from seed (no Tor needed)
                    // These are deterministic from the BIP39 seed, so they're known immediately
                    Log.i("CreateAccount", "Pre-computing onion addresses from seed...")
                    keyManager.precomputeAllOnionAddresses()
                    val onionAddress = keyManager.getMessagingOnion()!!
                    val friendRequestOnion = keyManager.getFriendRequestOnion()!!
                    val voiceOnionAddress = keyManager.getVoiceOnion() ?: ""
                    Log.i("CreateAccount", "All 3 onion addresses pre-computed offline")

                    // Generate random PIN first
                    val cardManager = ContactCardManager(this@CreateAccountActivity)
                    val contactCardPin = cardManager.generateRandomPin()

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
                                delay(2000) // Non-blocking coroutine delay
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

                    val setupPrefs = getSharedPreferences("account_setup", MODE_PRIVATE)
                    if (isRestore) {
                        // Restored from seed — user already has it
                        setupPrefs.edit().putBoolean("seed_phrase_confirmed", true).apply()

                        // Enable push recovery mode — TorService will activate beacon
                        // so friends can push our contact list when Tor comes online
                        val contactListCID = keyManager.deriveContactListCIDFromSeed(mnemonic)
                        val recoveryPrefs = getSharedPreferences("recovery_state", MODE_PRIVATE)
                        recoveryPrefs.edit()
                            .putBoolean("recovery_needed", true)
                            .putString("expected_cid", contactListCID)
                            .apply()
                        Log.i("CreateAccount", "Recovery mode enabled (CID: ${contactListCID.take(20)}...)")
                    } else {
                        // New account — user must confirm backup
                        setupPrefs.edit().putBoolean("seed_phrase_confirmed", false).apply()
                    }
                }

                // Back on Main — clean fade transition to recovery seed screen
                val intent = Intent(this@CreateAccountActivity, AccountCreatedActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                startActivity(intent)
                @Suppress("DEPRECATION")
                overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
                finish()

            } catch (e: Exception) {
                Log.e("CreateAccount", "Failed to create account", e)
                hideLoading()
                ThemedToast.showLong(this@CreateAccountActivity, "Failed to create account: ${e.message}")
                createAccountButton.isEnabled = true
            }
        }
    }
}
