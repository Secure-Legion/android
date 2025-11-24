package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.utils.ThemedToast

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
                ThemedToast.show(this, "Please enter your private key")
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

            if (newPassword.length < 8) {
                ThemedToast.show(this, "Password must be at least 8 characters")
                return@setOnClickListener
            }

            // Validate private key format (basic validation)
            if (privateKey.length < 32) {
                ThemedToast.show(this, "Invalid private key format")
                return@setOnClickListener
            }

            restoreAccount(privateKey, newPassword)
        }
    }

    private fun restoreAccount(privateKey: String, password: String) {
        // TODO: Implement actual account restoration with Solana SDK
        // For now, simulate success

        ThemedToast.show(this, "Account restored successfully!")

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
