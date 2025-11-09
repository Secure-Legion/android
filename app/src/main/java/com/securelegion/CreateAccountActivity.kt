package com.securelegion

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
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
                // TODO: Actually create the account
                finish()
            }
        }
    }

    private fun generateWalletAddress() {
        // Generate a mock Solana wallet address (in production, use real Solana SDK)
        val chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        generatedWalletAddress = (1..44).map { chars.random() }.joinToString("")

        // Show the wallet address
        walletAddressText.text = generatedWalletAddress
        walletAddressSection.visibility = View.VISIBLE

        // Show username section
        usernameSection.visibility = View.VISIBLE
        searchSection.visibility = View.VISIBLE

        // Hide the create wallet button
        createWalletButton.visibility = View.GONE

        Toast.makeText(this, "Wallet created successfully!", Toast.LENGTH_SHORT).show()
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
