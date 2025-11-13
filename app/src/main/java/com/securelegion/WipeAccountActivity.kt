package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.SecureWipe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WipeAccountActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wipe_account)

        // Setup bottom navigation
        BottomNavigationHelper.setupBottomNavigation(this)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Wipe Account button
        findViewById<View>(R.id.wipeAccountButton).setOnClickListener {
            val password = findViewById<EditText>(R.id.wipePasswordInput).text.toString()
            val confirmText = findViewById<EditText>(R.id.wipeConfirmInput).text.toString()

            if (password.isEmpty()) {
                Toast.makeText(this, "Please enter your password", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (confirmText != "DELETE") {
                Toast.makeText(this, "Please type DELETE in capital letters", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Verify password
            val keyManager = KeyManager.getInstance(this)
            if (!keyManager.verifyDevicePassword(password)) {
                Toast.makeText(this, "Incorrect password", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Final confirmation dialog
            AlertDialog.Builder(this)
                .setTitle("FINAL WARNING")
                .setMessage("This will permanently delete ALL your data including:\n• All messages and chats\n• All contacts\n• Wallet information\n• Recovery phrases\n• All settings\n\nData will be securely overwritten 3 times to prevent forensic recovery.\n\nThis action CANNOT be undone!\n\nAre you absolutely sure?")
                .setPositiveButton("WIPE ACCOUNT") { _, _ ->
                    performSecureWipe()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    /**
     * Perform secure wipe with 3-pass overwrite
     */
    private fun performSecureWipe() {
        lifecycleScope.launch {
            try {
                // Show progress
                Toast.makeText(this@WipeAccountActivity, "Securely wiping all data...", Toast.LENGTH_LONG).show()

                withContext(Dispatchers.IO) {
                    // Clear database instance first
                    SecureLegionDatabase.clearInstance()

                    // Wipe all cryptographic keys
                    val keyManager = KeyManager.getInstance(this@WipeAccountActivity)
                    keyManager.wipeAllKeys()

                    // Securely wipe all data (3-pass overwrite)
                    SecureWipe.wipeAllData(this@WipeAccountActivity)
                }

                // Restart app to show account creation screen
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@WipeAccountActivity, "Account wiped successfully", Toast.LENGTH_SHORT).show()

                    val intent = Intent(this@WipeAccountActivity, LockActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    startActivity(intent)
                    finish()
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@WipeAccountActivity,
                        "Failed to wipe account: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }
}
