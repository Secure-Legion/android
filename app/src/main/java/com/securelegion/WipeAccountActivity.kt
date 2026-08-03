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
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.SecureWipe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WipeAccountActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wipe_account)

        // setupBottomNavigation() // REMOVED: This layout doesn't have bottom nav

        // Setup back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Hide password input for passwordless accounts
        val keyManager = KeyManager.getInstance(this)
        val isPasswordless = !keyManager.hasUserDefinedPassword()
        val passwordInput = findViewById<EditText>(R.id.wipePasswordInput)
        if (isPasswordless) {
            passwordInput.visibility = View.GONE
        }

        // Wipe Account button
        findViewById<View>(R.id.wipeAccountButton).setOnClickListener {
            val confirmText = findViewById<EditText>(R.id.wipeConfirmInput).text.toString()

            if (confirmText != "DELETE") {
                return@setOnClickListener
            }

            // For accounts with passwords, verify it
            if (!isPasswordless) {
                val password = passwordInput.text.toString()
                if (password.isEmpty()) {
                    return@setOnClickListener
                }
                if (!keyManager.verifyDevicePassword(password)) {
                    return@setOnClickListener
                }
            }

            // Final confirmation dialog with dark theme
            val wipeDialog = GlassDialog.builder(this)
                .setTitle("FINAL WARNING")
                .setMessage("This will permanently delete ALL your data including:\n• All messages and chats\n• All contacts\n• Wallet information\n• Recovery phrases\n• All settings\n\nAccount keys will be destroyed and all app-owned data will be deleted. Flash storage cannot provide a reliable overwrite-pass guarantee.\n\nThis action CANNOT be undone!\n\nAre you absolutely sure?")
                .setPositiveButton("WIPE ACCOUNT") { _, _ ->
                    performSecureWipe()
                }
                .setNegativeButton("Cancel", null)
                .create()
            GlassDialog.show(wipeDialog)
        }
    }

    /**
     * Perform cryptographic erase followed by comprehensive app-data deletion.
     */
    private fun performSecureWipe() {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    // Stop TorService first to release old onion keys
                    try {
                        val stopIntent = Intent(this@WipeAccountActivity, com.securelegion.services.TorService::class.java)
                        stopService(stopIntent)
                    } catch (e: Exception) {
                        android.util.Log.w("WipeAccount", "Failed to stop TorService", e)
                    }

                    // Clear database instance first
                    SecureLegionDatabase.clearInstance()

                    // Cryptographically erase keys and delete all app-owned data.
                    SecureWipe.wipeAllData(this@WipeAccountActivity)
                }

                // Restart app to show account creation screen
                withContext(Dispatchers.Main) {
                    // Go to WelcomeActivity — no keys exist, need to create new account
                    val intent = Intent(this@WipeAccountActivity, WelcomeActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    startActivity(intent)
                    finish()
                    // Kill the process to ensure clean restart of TorService with new keys
                    android.os.Process.killProcess(android.os.Process.myPid())
                }

            } catch (e: Exception) {
                // Silent failure - wipe completed but restart failed
                withContext(Dispatchers.Main) {
                    // Go to WelcomeActivity — no keys exist, need to create new account
                    val intent = Intent(this@WipeAccountActivity, WelcomeActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    startActivity(intent)
                    finish()
                    // Kill the process to ensure clean restart of TorService with new keys
                    android.os.Process.killProcess(android.os.Process.myPid())
                }
            }
        }
    }
}
