package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.web3j.crypto.MnemonicUtils
import java.security.SecureRandom
import java.util.UUID

class CreateAccountActivity : AppCompatActivity() {

    private lateinit var passwordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var createWalletButton: TextView
    private lateinit var walletAddressSection: LinearLayout
    private lateinit var walletAddressText: TextView
    private lateinit var usernameSection: LinearLayout
    private lateinit var usernameInput: EditText
    private lateinit var searchSection: LinearLayout
    private lateinit var searchButton: TextView
    private lateinit var usernameStatus: TextView
    private lateinit var createSection: LinearLayout
    private lateinit var createAccountButton: TextView

    private var generatedWalletAddress: String = ""
    private var isUsernameAvailable: Boolean = false
    private var contactCardCid: String = ""
    private var contactCardPin: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_account)

        initializeViews()
        setupClickListeners()
    }

    private fun initializeViews() {
        passwordInput = findViewById(R.id.passwordInput)
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput)
        createWalletButton = findViewById(R.id.createWalletButton)
        walletAddressSection = findViewById(R.id.walletAddressSection)
        walletAddressText = findViewById(R.id.walletAddressText)
        usernameSection = findViewById(R.id.usernameSection)
        usernameInput = findViewById(R.id.usernameInput)
        searchSection = findViewById(R.id.searchSection)
        searchButton = findViewById(R.id.searchButton)
        usernameStatus = findViewById(R.id.usernameStatus)
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
                Toast.makeText(this, "Please enter a password", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (password != confirmPassword) {
                Toast.makeText(this, "Passwords do not match", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (password.length < 8) {
                Toast.makeText(this, "Password must be at least 8 characters", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            generateWalletAddress()
        }

        // Search blockchain button
        searchButton.setOnClickListener {
            val username = usernameInput.text.toString()

            if (username.isEmpty()) {
                Toast.makeText(this, "Please enter a username", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            searchUsername(username)
        }

        // Create Account button
        createAccountButton.setOnClickListener {
            if (isUsernameAvailable) {
                // Disable button to prevent double-click
                createAccountButton.isEnabled = false

                // Generate and upload contact card with the confirmed username
                // This is async, so we need to wait for it to complete
                generateContactCard()
            }
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

            // Get the real Solana wallet address (Base58-encoded Ed25519 public key)
            generatedWalletAddress = keyManager.getSolanaAddress()
            Log.i("CreateAccount", "Solana address: $generatedWalletAddress")

            // Show the wallet address
            walletAddressText.text = generatedWalletAddress
            walletAddressSection.visibility = View.VISIBLE

            // Show username section
            usernameSection.visibility = View.VISIBLE
            searchSection.visibility = View.VISIBLE

            // Hide the create wallet button
            createWalletButton.visibility = View.GONE

            Toast.makeText(this, "Wallet created successfully!", Toast.LENGTH_SHORT).show()

            // Show backup seed phrase screen
            Log.i("CreateAccount", "Navigating to backup seed phrase screen")
            val intent = Intent(this, BackupSeedPhraseActivity::class.java)
            intent.putExtra(BackupSeedPhraseActivity.EXTRA_SEED_PHRASE, mnemonic)
            startActivity(intent)

        } catch (e: Exception) {
            Log.e("CreateAccount", "Failed to generate wallet", e)
            Toast.makeText(this, "Failed to create wallet: ${e.message}", Toast.LENGTH_LONG).show()
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
                    solanaAddress = keyManager.getSolanaAddress(),
                    torOnionAddress = keyManager.getTorOnionAddress(),
                    timestamp = System.currentTimeMillis()
                )

                // Generate random PIN
                val cardManager = ContactCardManager(this@CreateAccountActivity)
                contactCardPin = cardManager.generateRandomPin()

                Log.d("CreateAccount", "Uploading contact card to IPFS...")
                Toast.makeText(
                    this@CreateAccountActivity,
                    "Uploading contact card...",
                    Toast.LENGTH_SHORT
                ).show()

                // Upload to IPFS with PIN encryption
                val result = withContext(Dispatchers.IO) {
                    cardManager.uploadContactCard(contactCard, contactCardPin)
                }

                if (result.isSuccess) {
                    val (cid, size) = result.getOrThrow()
                    contactCardCid = cid

                    // Store CID, PIN, and username in encrypted storage
                    keyManager.storeContactCardInfo(contactCardCid, contactCardPin)
                    keyManager.storeUsername(usernameInput.text.toString())

                    Log.i("CreateAccount", "Contact card uploaded successfully")
                    Log.i("CreateAccount", "CID: $contactCardCid")
                    Log.i("CreateAccount", "PIN: $contactCardPin")
                    Log.i("CreateAccount", "Size: $size bytes")

                    Toast.makeText(
                        this@CreateAccountActivity,
                        "Account created successfully!",
                        Toast.LENGTH_LONG
                    ).show()

                    // Navigate to Wallet Identity screen to show CID and PIN
                    val intent = Intent(this@CreateAccountActivity, WalletIdentityActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    intent.putExtra("SHOW_CONTACT_CARD_INFO", true)
                    startActivity(intent)
                    finish()
                } else {
                    throw result.exceptionOrNull()!!
                }
            } catch (e: Exception) {
                Log.e("CreateAccount", "Failed to generate contact card", e)
                Toast.makeText(
                    this@CreateAccountActivity,
                    "Failed to create contact card: ${e.message}",
                    Toast.LENGTH_LONG
                ).show()

                // Re-enable button so user can retry
                createAccountButton.isEnabled = true
                createAccountButton.text = "Create Account"
            }
        }
    }

    private fun searchUsername(username: String) {
        // Simulate blockchain search (in production, actually query the blockchain)
        usernameStatus.text = "Searching blockchain..."

        // Simulate network delay
        usernameStatus.postDelayed({
            // For demo purposes, always return available
            isUsernameAvailable = true
            usernameStatus.text = "✓ Username is available!"
            usernameStatus.setTextColor(getColor(R.color.success_green))

            // Show create account section
            createSection.visibility = View.VISIBLE
            createAccountButton.isClickable = true
            createAccountButton.alpha = 1.0f

            Toast.makeText(this, "Click 'Create Account' to finish", Toast.LENGTH_LONG).show()
        }, 1500)
    }
}
