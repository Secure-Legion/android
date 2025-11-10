package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager

class LockActivity : AppCompatActivity() {

    private lateinit var passwordSection: LinearLayout
    private lateinit var accountLinksSection: LinearLayout
    private var hasWallet = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_lock)

        passwordSection = findViewById(R.id.passwordSection)
        accountLinksSection = findViewById(R.id.accountLinksSection)

        // Check if wallet exists
        val keyManager = KeyManager.getInstance(this)
        hasWallet = keyManager.isInitialized()

        if (hasWallet) {
            // Wallet exists - show password unlock
            Log.d("LockActivity", "Wallet exists, showing password unlock")
            passwordSection.visibility = View.VISIBLE
            accountLinksSection.visibility = View.GONE
        } else {
            // No wallet - show account creation/restore options
            Log.d("LockActivity", "No wallet, showing account options")
            passwordSection.visibility = View.GONE
            accountLinksSection.visibility = View.VISIBLE
        }

        setupClickListeners()
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.unlockButton).setOnClickListener {
            val password = findViewById<EditText>(R.id.passwordInput).text.toString()

            if (password.isBlank()) {
                Toast.makeText(this, "Please enter password", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // TODO: Verify password with biometric/PIN
            // For development, accept "test" or any password
            Log.i("LockActivity", "Password accepted, unlocking app")
            Toast.makeText(this, "Unlocked!", Toast.LENGTH_SHORT).show()
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.newAccountLink).setOnClickListener {
            Log.d("LockActivity", "User selected 'Create New Account'")
            val intent = Intent(this, CreateAccountActivity::class.java)
            startActivity(intent)
            // Don't finish - allow back navigation
        }

        findViewById<View>(R.id.restoreAccountLink).setOnClickListener {
            Log.d("LockActivity", "User selected 'Import Account'")
            val intent = Intent(this, RestoreAccountActivity::class.java)
            startActivity(intent)
            // Don't finish - allow back navigation
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Prevent going back without unlocking
    }
}
