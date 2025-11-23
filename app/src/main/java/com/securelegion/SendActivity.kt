package com.securelegion

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.services.SolanaService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.launch

class SendActivity : BaseActivity() {
    private var currentWalletId: String = "main"
    private var currentWalletName: String = "Wallet 1"
    private var currentWalletAddress: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_send)

        // Get wallet info from intent
        currentWalletId = intent.getStringExtra("WALLET_ID") ?: "main"
        currentWalletName = intent.getStringExtra("WALLET_NAME") ?: "Wallet 1"
        currentWalletAddress = intent.getStringExtra("WALLET_ADDRESS") ?: ""

        // If wallet address not passed, get it from KeyManager
        if (currentWalletAddress.isEmpty()) {
            val keyManager = KeyManager.getInstance(this)
            currentWalletAddress = keyManager.getSolanaAddress()
        }

        Log.d("SendActivity", "Sending from wallet: $currentWalletName ($currentWalletAddress)")

        // Display wallet info
        findViewById<TextView>(R.id.fromWalletName).text = currentWalletName
        findViewById<TextView>(R.id.fromWalletAddress).text =
            "${currentWalletAddress.take(4)}...${currentWalletAddress.takeLast(4)}"

        loadWalletBalance()
        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            val recipientAddress = findViewById<EditText>(R.id.recipientAddressInput).text.toString()
            val amount = findViewById<EditText>(R.id.amountInput).text.toString()

            if (recipientAddress.isEmpty()) {
                ThemedToast.show(this, "Please enter recipient address")
                return@setOnClickListener
            }

            if (amount.isEmpty() || amount.toDoubleOrNull() == null || amount.toDouble() <= 0) {
                ThemedToast.show(this, "Please enter a valid amount")
                return@setOnClickListener
            }

            // Send SOL transaction
            val sendButton = findViewById<View>(R.id.sendButton)
            sendButton.isEnabled = false // Disable during processing

            lifecycleScope.launch {
                try {
                    Log.i("SendActivity", "Initiating SOL transfer: $amount SOL from $currentWalletName to $recipientAddress")

                    val keyManager = KeyManager.getInstance(this@SendActivity)
                    val solanaService = SolanaService(this@SendActivity)

                    val result = solanaService.sendTransaction(
                        fromPublicKey = currentWalletAddress,
                        toPublicKey = recipientAddress,
                        amountSOL = amount.toDouble(),
                        keyManager = keyManager,
                        walletId = currentWalletId
                    )

                    if (result.isSuccess) {
                        val txSignature = result.getOrNull()!!
                        Log.i("SendActivity", "Transaction successful: $txSignature")
                        ThemedToast.showLong(
                            this@SendActivity,
                            "Transaction sent!\nSignature: ${txSignature.take(8)}..."
                        )

                        // Clear inputs
                        findViewById<EditText>(R.id.recipientAddressInput).setText("")
                        findViewById<EditText>(R.id.amountInput).setText("")
                        finish()
                    } else {
                        val error = result.exceptionOrNull()
                        Log.e("SendActivity", "Transaction failed", error)
                        ThemedToast.showLong(
                            this@SendActivity,
                            "Transaction failed: ${error?.message}"
                        )
                        sendButton.isEnabled = true
                    }

                } catch (e: Exception) {
                    Log.e("SendActivity", "Failed to send transaction", e)
                    ThemedToast.showLong(
                        this@SendActivity,
                        "Error: ${e.message}"
                    )
                    sendButton.isEnabled = true
                }
            }
        }
    }

    private fun loadWalletBalance() {
        lifecycleScope.launch {
            try {
                val solanaService = SolanaService(this@SendActivity)

                // Use the current wallet address
                val walletAddress = currentWalletAddress

                // Fetch balance
                val balanceResult = solanaService.getBalance(walletAddress)

                if (balanceResult.isSuccess) {
                    val balanceSOL = balanceResult.getOrNull() ?: 0.0

                    // Update SOL balance
                    findViewById<TextView>(R.id.balanceSOL).text = String.format("%.4f SOL", balanceSOL)

                    // Fetch live SOL price and calculate USD value
                    val priceResult = solanaService.getSolPrice()
                    if (priceResult.isSuccess) {
                        val priceUSD = priceResult.getOrNull() ?: 0.0
                        val balanceUSD = balanceSOL * priceUSD
                        findViewById<TextView>(R.id.balanceUSD).text = String.format("≈ $%.2f USD", balanceUSD)
                    } else {
                        findViewById<TextView>(R.id.balanceUSD).text = "≈ $... USD"
                    }

                    Log.i("SendActivity", "Balance loaded: $balanceSOL SOL")
                } else {
                    Log.e("SendActivity", "Failed to load balance: ${balanceResult.exceptionOrNull()?.message}")
                    findViewById<TextView>(R.id.balanceSOL).text = "Error loading balance"
                    findViewById<TextView>(R.id.balanceUSD).text = ""
                }
            } catch (e: Exception) {
                Log.e("SendActivity", "Error loading wallet balance", e)
                findViewById<TextView>(R.id.balanceSOL).text = "Error"
                findViewById<TextView>(R.id.balanceUSD).text = ""
            }
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }
    }
}
