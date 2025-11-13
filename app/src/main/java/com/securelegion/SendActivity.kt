package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.services.SolanaService
import kotlinx.coroutines.launch

class SendActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_send)

        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            overridePendingTransition(0, 0)
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

            // Send SOL transaction
            val sendButton = findViewById<View>(R.id.sendButton)
            sendButton.isEnabled = false // Disable during processing

            lifecycleScope.launch {
                try {
                    Log.i("SendActivity", "Initiating SOL transfer: $amount SOL to $recipientAddress")

                    val keyManager = KeyManager.getInstance(this@SendActivity)
                    val solanaService = SolanaService(this@SendActivity)

                    val result = solanaService.sendTransaction(
                        fromPublicKey = keyManager.getSolanaAddress(),
                        toPublicKey = recipientAddress,
                        amountSOL = amount.toDouble(),
                        keyManager = keyManager
                    )

                    if (result.isSuccess) {
                        val txSignature = result.getOrNull()!!
                        Log.i("SendActivity", "Transaction successful: $txSignature")
                        Toast.makeText(
                            this@SendActivity,
                            "Transaction sent!\nSignature: ${txSignature.take(8)}...",
                            Toast.LENGTH_LONG
                        ).show()

                        // Clear inputs
                        findViewById<EditText>(R.id.recipientAddressInput).setText("")
                        findViewById<EditText>(R.id.amountInput).setText("")
                        finish()
                    } else {
                        val error = result.exceptionOrNull()
                        Log.e("SendActivity", "Transaction failed", error)
                        Toast.makeText(
                            this@SendActivity,
                            "Transaction failed: ${error?.message}",
                            Toast.LENGTH_LONG
                        ).show()
                        sendButton.isEnabled = true
                    }

                } catch (e: Exception) {
                    Log.e("SendActivity", "Failed to send transaction", e)
                    Toast.makeText(
                        this@SendActivity,
                        "Error: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                    sendButton.isEnabled = true
                }
            }
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }
    }
}
