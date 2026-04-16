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
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.colorResource
import androidx.core.content.ContextCompat
import androidx.compose.ui.platform.ComposeView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import com.securelegion.utils.BiometricAuthHelper
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
    private lateinit var customPasswordSwitch: SwitchCompat
    private lateinit var biometricSwitch: SwitchCompat
    private lateinit var passwordFieldsContainer: LinearLayout
    private lateinit var noPasswordHelperText: TextView
    private lateinit var biometricToggleContainer: LinearLayout
    private lateinit var biometricHelper: BiometricAuthHelper

    private var isPasswordVisible = false
    private var isConfirmPasswordVisible = false
    private var isRestore = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Make status bar transparent with light icons (matches dark theme)
        @Suppress("DEPRECATION") // edge-to-edge refactor pending
        run { window.statusBarColor = android.graphics.Color.BLACK }

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
        customPasswordSwitch = findViewById(R.id.customPasswordSwitch)
        biometricSwitch = findViewById(R.id.biometricSwitch)
        passwordFieldsContainer = findViewById(R.id.passwordFieldsContainer)
        noPasswordHelperText = findViewById(R.id.noPasswordHelperText)
        biometricToggleContainer = findViewById(R.id.biometricToggleContainer)
        biometricHelper = BiometricAuthHelper(this)

        // Show biometric toggle only if hardware available
        val biometricStatus = biometricHelper.isBiometricAvailable()
        if (biometricStatus == BiometricAuthHelper.BiometricStatus.AVAILABLE) {
            biometricToggleContainer.visibility = View.VISIBLE
        }

        // Toggle password fields visibility
        customPasswordSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                passwordFieldsContainer.visibility = View.VISIBLE
                noPasswordHelperText.visibility = View.GONE
            } else {
                passwordFieldsContainer.visibility = View.GONE
                noPasswordHelperText.visibility = View.VISIBLE
                passwordInput.text.clear()
                confirmPasswordInput.text.clear()
                passwordMatchText.visibility = View.GONE
            }
        }

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
        spannable.setSpan(ForegroundColorSpan(ContextCompat.getColor(this, R.color.lock_title_gray)), 0, fullText.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)

        // Make "Import" clickable and white
        val clickableSpan = object : ClickableSpan() {
            override fun onClick(widget: View) {
                // Navigate to Import Account screen
                val intent = Intent(this@CreateAccountActivity, RestoreAccountActivity::class.java)
                startActivity(intent)
            }
        }

        spannable.setSpan(clickableSpan, importStart, importEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        spannable.setSpan(ForegroundColorSpan(ContextCompat.getColor(this, R.color.text_primary)), importStart, importEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)

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
            passwordMatchText.setTextColor(ContextCompat.getColor(this, R.color.text_primary))
        } else {
            passwordMatchText.text = "Passwords do not match"
            passwordMatchText.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
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
                color = colorResource(R.color.lock_title_gray)
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
            val username = usernameInput.text.toString().trim()

            if (username.isEmpty()) {
                ThemedToast.show(this, "Please enter a username")
                return@setOnClickListener
            }

            // Check reserved usernames
            val reserved = setOf("support", "secure", "securelegion")
            val normalized = username.lowercase().replace(Regex("[^a-z0-9]"), "")
            if (reserved.contains(normalized)) {
                ThemedToast.show(this, "This username is reserved")
                return@setOnClickListener
            }

            val useCustomPassword = customPasswordSwitch.isChecked

            if (useCustomPassword) {
                val password = passwordInput.text.toString()
                val confirmPassword = confirmPasswordInput.text.toString()

                if (password.isEmpty()) {
                    ThemedToast.show(this, "Please enter a password")
                    return@setOnClickListener
                }
                if (password != confirmPassword) {
                    ThemedToast.show(this, "Passwords do not match")
                    return@setOnClickListener
                }
                val validation = PasswordValidator.validate(password)
                if (!validation.isValid) {
                    ThemedToast.showLong(this, validation.errorMessage ?: "Invalid password")
                    return@setOnClickListener
                }
            }

            // Hide passwords if visible
            if (isPasswordVisible) {
                passwordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                isPasswordVisible = false
            }
            if (isConfirmPasswordVisible) {
                confirmPasswordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                isConfirmPasswordVisible = false
            }

            val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
            imm.hideSoftInputFromWindow(currentFocus?.windowToken, 0)
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
                        val masterKey = androidx.security.crypto.MasterKey.Builder(this@CreateAccountActivity)
                            .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM).build()
                        val prefs = androidx.security.crypto.EncryptedSharedPreferences.create(
                            this@CreateAccountActivity, "restore_temp", masterKey,
                            androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                            androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                        )
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

                    // Auto-wipe any existing on-device account before provisioning the new one.
                    // Covers "forgot password" (user can't reach WipeAccountActivity) and
                    // seed-phrase restore (explicit overwrite). Runs AFTER the restore-seed
                    // capture above, since wipeAllData clears `restore_temp` SharedPrefs too.
                    val preCheckKeyManager = KeyManager.getInstance(this@CreateAccountActivity)
                    if (preCheckKeyManager.isAccountSetupComplete()) {
                        Log.w("CreateAccount", "Existing account detected — wiping before provisioning new one")
                        try {
                            stopService(Intent(this@CreateAccountActivity, com.securelegion.services.TorService::class.java))
                        } catch (e: Exception) {
                            Log.w("CreateAccount", "Failed to stop TorService before wipe", e)
                        }
                        SecureLegionDatabase.clearInstance()
                        preCheckKeyManager.wipeAllKeys()
                        com.securelegion.utils.SecureWipe.wipeAllData(this@CreateAccountActivity)
                        Log.i("CreateAccount", "Existing account wiped, proceeding with new account provisioning")
                    }

                    // Initialize KeyManager with the mnemonic
                    val keyManager = KeyManager.getInstance(this@CreateAccountActivity)
                    keyManager.initializeFromSeed(mnemonic)
                    Log.i("CreateAccount", "KeyManager initialized from seed")

                    // Determine password
                    val useCustomPassword = customPasswordSwitch.isChecked
                    val accountPassword = if (useCustomPassword) {
                        password  // already captured from UI
                    } else {
                        keyManager.generateSystemPasswordPublic()
                    }

                    // Set up account password (wraps seed + stores hash + manages system password)
                    keyManager.setupAccountPassword(accountPassword, isUserDefined = useCustomPassword)

                    // If biometric enabled during signup and custom password used
                    if (biometricSwitch.isChecked) {
                        val biometricHelperAccount = BiometricAuthHelper(this@CreateAccountActivity)
                        // Note: biometric enrollment requires activity context - will be prompted later
                    }

                    Log.i("CreateAccount", "Account password set (custom=$useCustomPassword)")

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
                    if (BuildConfig.ENABLE_ZCASH_WALLET) {
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
                        inviteToken = keyManager.getInviteToken() ?: keyManager.generateAndStoreInviteToken(),
                        ipfsCid = ipfsCid,
                        timestamp = System.currentTimeMillis()
                    )
                    // Store contact card info in encrypted storage
                    keyManager.storeContactPin(contactCardPin)
                    keyManager.generateAndStoreInviteToken()
                    keyManager.storePinRotationTimestamp(System.currentTimeMillis())
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

                        // Arm contact-list recovery: the first friend we re-add after
                        // this restore gets a signed 0x80 REQUEST so they push our
                        // encrypted list back. Also keeps the passive-push path working
                        // (TorService / ContactListSyncService poller consumes the blob
                        // if a friend pushes unsolicited 0x82 first). Expires in 48h.
                        val contactListCID = keyManager.deriveContactListCIDFromSeed(mnemonic)
                        com.securelegion.services.RecoveryState.setActive(
                            this@CreateAccountActivity, contactListCID
                        )
                        Log.i("CreateAccount", "Recovery mode enabled (CID: ${contactListCID.take(20)}...)")

                        // Restart TorService so it picks up new hidden service keys
                        // (if Tor was already running from before the restore)
                        com.securelegion.services.TorService.requestRestart("seed phrase restore")
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
