package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
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
import java.util.UUID

class CreateAccountActivity : AppCompatActivity() {

    private lateinit var passwordSection: LinearLayout
    private lateinit var passwordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var createWalletButton: TextView
    private lateinit var walletAddressSection: LinearLayout
    private lateinit var walletAddressText: TextView
    private lateinit var usernameSection: LinearLayout
    private lateinit var usernameInput: EditText
    private lateinit var createSection: LinearLayout
    private lateinit var createAccountButton: TextView

    private var generatedWalletAddress: String = ""
    private var contactCardCid: String = ""
    private var contactCardPin: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_account)

        initializeViews()
        setupClickListeners()

        // Check if resuming incomplete account setup
        val resumeSetup = intent.getBooleanExtra("RESUME_SETUP", false)
        if (resumeSetup) {
            Log.i("CreateAccount", "Resuming incomplete account setup")
            resumeAccountSetup()
        }
    }

    /**
     * Resume account setup from incomplete state
     * User has wallet/password but no contact card
     */
    private fun resumeAccountSetup() {
        val keyManager = KeyManager.getInstance(this)

        // Get wallet address from existing keys
        generatedWalletAddress = keyManager.getSolanaAddress()
        Log.i("CreateAccount", "Resuming with existing wallet: $generatedWalletAddress")

        // Hide password section, show wallet address and username sections
        passwordSection.visibility = View.GONE
        createWalletButton.visibility = View.GONE
        walletAddressText.text = generatedWalletAddress
        walletAddressSection.visibility = View.VISIBLE
        usernameSection.visibility = View.VISIBLE
        createSection.visibility = View.VISIBLE

        ThemedToast.showLong(this, "Enter your username to complete setup")
    }

    override fun onResume() {
        super.onResume()

        // If wallet address was generated (user returned from backup seed phrase screen)
        // Show the wallet address and username sections, hide password section
        if (generatedWalletAddress.isNotEmpty()) {
            walletAddressText.text = generatedWalletAddress
            passwordSection.visibility = View.GONE
            walletAddressSection.visibility = View.VISIBLE
            usernameSection.visibility = View.VISIBLE
            createSection.visibility = View.VISIBLE
            createWalletButton.visibility = View.GONE
        }
    }

    private fun initializeViews() {
        passwordSection = findViewById(R.id.passwordSection)
        passwordInput = findViewById(R.id.passwordInput)
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput)
        createWalletButton = findViewById(R.id.createWalletButton)
        walletAddressSection = findViewById(R.id.walletAddressSection)
        walletAddressText = findViewById(R.id.walletAddressText)
        usernameSection = findViewById(R.id.usernameSection)
        usernameInput = findViewById(R.id.usernameInput)
        createSection = findViewById(R.id.createSection)
        createAccountButton = findViewById(R.id.createAccountButton)
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Create Wallet button
        createWalletButton.setOnClickListener {
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

            // Validate password complexity
            val validation = PasswordValidator.validate(password)
            if (!validation.isValid) {
                ThemedToast.showLong(this, validation.errorMessage ?: "Invalid password")
                return@setOnClickListener
            }

            generateWalletAddress()
        }

        // Create Account button
        createAccountButton.setOnClickListener {
            val username = usernameInput.text.toString()

            if (username.isEmpty()) {
                ThemedToast.show(this, "Please enter a username")
                return@setOnClickListener
            }

            // Disable button to prevent double-click
            createAccountButton.isEnabled = false

            // Generate and upload contact card with the confirmed username
            // This is async, so we need to wait for it to complete
            generateContactCard()
        }
    }

    private fun generateWalletAddress() {
        try {
            Log.d("CreateAccount", "Generating BIP39 mnemonic and wallet...")

            // Generate 128-bit entropy for 12-word BIP39 mnemonic
            val entropy = ByteArray(16) // 128 bits = 12 words
            SecureRandom().nextBytes(entropy)

            // Generate BIP39 mnemonic from entropy
            val mnemonic = MnemonicUtils.generateMnemonic(entropy)
            Log.d("CreateAccount", "Generated 12-word mnemonic seed phrase")

            // Initialize KeyManager with the mnemonic
            val keyManager = KeyManager.getInstance(this)
            keyManager.initializeFromSeed(mnemonic)
            Log.i("CreateAccount", "KeyManager initialized from seed")

            // Set device password
            val password = passwordInput.text.toString()
            keyManager.setDevicePassword(password)
            Log.i("CreateAccount", "Device password set")

            // Get the real Solana wallet address (Base58-encoded Ed25519 public key)
            generatedWalletAddress = keyManager.getSolanaAddress()
            Log.i("CreateAccount", "Solana address: $generatedWalletAddress")

            // Create hidden service now that account exists
            Log.i("CreateAccount", "Creating hidden service for account")
            val torManager = TorManager.getInstance(this)
            torManager.createHiddenServiceIfNeeded()

            // Navigate to backup seed phrase screen first
            // When user returns, they'll see wallet address and username section
            Log.i("CreateAccount", "Navigating to backup seed phrase screen")
            val intent = Intent(this, BackupSeedPhraseActivity::class.java)
            intent.putExtra(BackupSeedPhraseActivity.EXTRA_SEED_PHRASE, mnemonic)
            startActivity(intent)

        } catch (e: Exception) {
            Log.e("CreateAccount", "Failed to generate wallet", e)
            ThemedToast.showLong(this, "Failed to create wallet: ${e.message}")
        }
    }

    private fun generateContactCard() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d("CreateAccount", "Generating contact card...")

                // Show loading state
                createAccountButton.text = "Creating Account..."

                val keyManager = KeyManager.getInstance(this@CreateAccountActivity)

                // Create contact card with user info
                val contactCard = ContactCard(
                    displayName = usernameInput.text.toString().ifEmpty { "Anonymous" },
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    solanaAddress = keyManager.getSolanaAddress(),
                    torOnionAddress = keyManager.getTorOnionAddress(),
                    timestamp = System.currentTimeMillis()
                )

                // Generate random PIN
                val cardManager = ContactCardManager(this@CreateAccountActivity)
                contactCardPin = cardManager.generateRandomPin()
                val publicKey = keyManager.getSolanaAddress() // Get Base58 public key

                Log.d("CreateAccount", "Uploading contact card to IPFS...")
                ThemedToast.show(
                    this@CreateAccountActivity,
                    "Uploading contact card..."
                )

                // Upload to IPFS with PIN encryption (tries Lighthouse first, falls back to Pinata)
                val result = withContext(Dispatchers.IO) {
                    cardManager.uploadContactCard(contactCard, contactCardPin, publicKey)
                }

                if (result.isSuccess) {
                    val (cid, size) = result.getOrThrow()
                    contactCardCid = cid

                    // Store CID, PIN, and username in encrypted storage
                    keyManager.storeContactCardInfo(contactCardCid, contactCardPin)
                    keyManager.storeUsername(usernameInput.text.toString())

                    // Initialize main wallet in database
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
                    Log.i("CreateAccount", "Main wallet initialized in database")

                    Log.i("CreateAccount", "Contact card uploaded successfully")
                    Log.i("CreateAccount", "CID: $contactCardCid")
                    Log.i("CreateAccount", "PIN: $contactCardPin")
                    Log.i("CreateAccount", "Size: $size bytes")

                    // Navigate to Account Created screen to show all info
                    val intent = Intent(this@CreateAccountActivity, AccountCreatedActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    startActivity(intent)
                    finish()
                } else {
                    throw result.exceptionOrNull()!!
                }
            } catch (e: Exception) {
                Log.e("CreateAccount", "Failed to generate contact card", e)
                ThemedToast.showLong(
                    this@CreateAccountActivity,
                    "Failed to create contact card. Please try again."
                )

                // Re-enable button so user can retry
                createAccountButton.isEnabled = true
                createAccountButton.text = "Create Account"
            }
        }
    }

}
