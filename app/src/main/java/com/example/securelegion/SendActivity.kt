package com.example.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class SendActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_send)

        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            val recipientAddress = findViewById<EditText>(R.id.recipientAddressInput).text.toString()
            val amount = findViewById<EditText>(R.id.amountInput).text.toString()

            if (recipientAddress.isEmpty()) {
                Toast.makeText(this, "Please enter recipient address", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (amount.isEmpty() || amount.toDoubleOrNull() == null || amount.toDouble() <= 0) {
                Toast.makeText(this, "Please enter a valid amount", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // TODO: Implement actual SOL sending
            Toast.makeText(this, "Sending $amount SOL to $recipientAddress", Toast.LENGTH_LONG).show()

            // Clear inputs and go back
            findViewById<EditText>(R.id.recipientAddressInput).setText("")
            findViewById<EditText>(R.id.amountInput).setText("")
            finish()
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
