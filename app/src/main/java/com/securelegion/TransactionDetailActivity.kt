package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class TransactionDetailActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transaction_detail)

        // Get transaction data from intent
        val type = intent.getStringExtra("TRANSACTION_TYPE") ?: "Unknown"
        val amount = intent.getStringExtra("TRANSACTION_AMOUNT") ?: "0"
        val date = intent.getStringExtra("TRANSACTION_DATE") ?: "Unknown"

        setupTransactionDetails(type, amount, date)
        setupClickListeners()
        setupBottomNav()
    }

    private fun setupTransactionDetails(type: String, amount: String, date: String) {
        findViewById<TextView>(R.id.transactionType).text = type
        findViewById<TextView>(R.id.transactionAmount).text = amount
        findViewById<TextView>(R.id.transactionDate).text = date

        // Set color based on transaction type
        val amountView = findViewById<TextView>(R.id.transactionAmount)
        if (amount.startsWith("+")) {
            amountView.setTextColor(getColor(R.color.success_green))
        } else {
            amountView.setTextColor(getColor(R.color.text_white))
        }
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // View on Explorer button
        findViewById<View>(R.id.viewOnExplorerButton).setOnClickListener {
            // Get transaction hash from the view
            val hashView = findViewById<android.widget.TextView>(R.id.transactionHash)
            val transactionHash = hashView.text.toString()

            // Open Solana Explorer URL
            val explorerUrl = "https://explorer.solana.com/tx/$transactionHash"
            val intent = android.content.Intent(android.content.Intent.ACTION_VIEW)
            intent.data = android.net.Uri.parse(explorerUrl)
            startActivity(intent)
        }
    }

    private fun setupBottomNav() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
