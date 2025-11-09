package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class RestoreAccountActivity : AppCompatActivity() {

    private lateinit var privateKeyInput: EditText
    private lateinit var newPasswordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var importButton: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_restore_account)

        initializeViews()
        setupClickListeners()
    }

    private fun initializeViews() {
        privateKeyInput = findViewById(R.id.privateKeyInput)
        newPasswordInput = findViewById(R.id.newPasswordInput)
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput)
        importButton = findViewById(R.id.importButton)
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Import button
        importButton.setOnClickListener {
            val privateKey = privateKeyInput.text.toString()
            val newPassword = newPasswordInput.text.toString()
            val confirmPassword = confirmPasswordInput.text.toString()

            if (privateKey.isEmpty()) {
                Toast.makeText(this, "Please enter your private key", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (newPassword.isEmpty()) {
                Toast.makeText(this, "Please enter a new password", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (newPassword != confirmPassword) {
                Toast.makeText(this, "Passwords do not match", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (newPassword.length < 8) {
                Toast.makeText(this, "Password must be at least 8 characters", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Validate private key format (basic validation)
            if (privateKey.length < 32) {
                Toast.makeText(this, "Invalid private key format", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            restoreAccount(privateKey, newPassword)
        }
    }

    private fun restoreAccount(privateKey: String, password: String) {
        // TODO: Implement actual account restoration with Solana SDK
        // For now, simulate success

        Toast.makeText(this, "Account restored successfully!", Toast.LENGTH_SHORT).show()

        // Clear inputs
        privateKeyInput.text.clear()
        newPasswordInput.text.clear()
        confirmPasswordInput.text.clear()

        // Navigate to MainActivity
        val intent = Intent(this, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}
