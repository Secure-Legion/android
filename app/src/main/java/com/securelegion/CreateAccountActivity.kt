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
                Toast.makeText(this, "Account created successfully!", Toast.LENGTH_SHORT).show()
                // TODO: Actually create the account on blockchain

                // Navigate to MainActivity and clear back stack
                val intent = Intent(this, MainActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                startActivity(intent)
                finish()
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

            // TODO: Show the mnemonic to user for backup
            Log.w("CreateAccount", "IMPORTANT: User should backup mnemonic: $mnemonic")

        } catch (e: Exception) {
            Log.e("CreateAccount", "Failed to generate wallet", e)
            Toast.makeText(this, "Failed to create wallet: ${e.message}", Toast.LENGTH_LONG).show()
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
            createAccountButton.isClickable = false
            createAccountButton.alpha = 0.5f

            // Note: User needs to fund the account first
            Toast.makeText(this, "Fund your wallet to continue", Toast.LENGTH_LONG).show()
        }, 1500)
    }
}
