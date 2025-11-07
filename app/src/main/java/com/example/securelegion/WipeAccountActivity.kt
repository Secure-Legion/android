package com.example.securelegion

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

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

            // Final confirmation dialog
            AlertDialog.Builder(this)
                .setTitle("⚠️ FINAL WARNING ⚠️")
                .setMessage("This will permanently delete ALL your data including:\n• All messages and chats\n• All contacts\n• Wallet information\n• Recovery phrases\n• All settings\n\nThis action CANNOT be undone!\n\nAre you absolutely sure?")
                .setPositiveButton("WIPE ACCOUNT") { _, _ ->
                    Toast.makeText(this, "Account wiped", Toast.LENGTH_SHORT).show()
                    // TODO: Implement account wipe
                    finishAffinity()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }
}
