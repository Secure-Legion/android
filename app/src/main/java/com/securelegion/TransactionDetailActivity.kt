package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.utils.ThemedToast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class TransactionDetailActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transaction_detail)

        // Get transaction data from intent
        val signature = intent.getStringExtra("TRANSACTION_SIGNATURE") ?: ""
        val type = intent.getStringExtra("TRANSACTION_TYPE") ?: "receive"
        val amount = intent.getDoubleExtra("TRANSACTION_AMOUNT", 0.0)
        val timestamp = intent.getLongExtra("TRANSACTION_TIMESTAMP", 0L)
        val status = intent.getStringExtra("TRANSACTION_STATUS") ?: "success"
        val otherPartyAddress = intent.getStringExtra("TRANSACTION_ADDRESS") ?: ""

        setupTransactionDetails(signature, type, amount, timestamp, status, otherPartyAddress)
        setupClickListeners(signature, otherPartyAddress)
        setupBottomNav()
    }

    private fun setupTransactionDetails(
        signature: String,
        type: String,
        amount: Double,
        timestamp: Long,
        status: String,
        otherPartyAddress: String
    ) {
        // Type
        val typeText = if (type == "send") "Sent" else "Received"
        findViewById<TextView>(R.id.transactionType).text = typeText

        // Amount
        val prefix = if (type == "send") "-" else "+"
        val formattedAmount = String.format("%.4f SOL", amount)
        val amountView = findViewById<TextView>(R.id.transactionAmount)
        amountView.text = "$prefix$formattedAmount"

        // Set color
        val color = if (type == "send") {
            getColor(R.color.text_white)
        } else {
            getColor(R.color.success_green)
        }
        amountView.setTextColor(color)

        // Status
        val statusView = findViewById<TextView>(R.id.transactionStatus)
        if (status == "success") {
            statusView.text = "✓ Confirmed"
            statusView.setTextColor(getColor(R.color.success_green))
        } else {
            statusView.text = "✗ Failed"
            statusView.setTextColor(getColor(R.color.danger_red))
        }

        // Date & Time
        val date = Date(timestamp)
        val dateFormat = SimpleDateFormat("MMM dd, yyyy 'at' h:mm a", Locale.getDefault())
        findViewById<TextView>(R.id.transactionDate).text = dateFormat.format(date)

        // From/To address
        val fromView = findViewById<TextView>(R.id.transactionFrom)
        val toView = findViewById<TextView>(R.id.transactionTo)

        if (type == "send") {
            toView.text = otherPartyAddress
        } else {
            fromView.text = otherPartyAddress
        }

        // Transaction hash (signature)
        findViewById<TextView>(R.id.transactionHash).text = signature
    }

    private fun setupClickListeners(signature: String, address: String) {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // View on Explorer button
        findViewById<View>(R.id.viewOnExplorerButton).setOnClickListener {
            // Open Solana Explorer URL
            val explorerUrl = "https://explorer.solana.com/tx/$signature"
            val intent = android.content.Intent(android.content.Intent.ACTION_VIEW)
            intent.data = android.net.Uri.parse(explorerUrl)
            startActivity(intent)
        }

        // Copy from address
        findViewById<View>(R.id.transactionFrom).setOnLongClickListener {
            val text = (it as TextView).text.toString()
            copyToClipboard(text, "From Address")
            true
        }

        // Copy to address
        findViewById<View>(R.id.transactionTo).setOnLongClickListener {
            val text = (it as TextView).text.toString()
            copyToClipboard(text, "To Address")
            true
        }

        // Copy transaction hash
        findViewById<View>(R.id.transactionHash).setOnLongClickListener {
            copyToClipboard(signature, "Transaction Hash")
            true
        }
    }

    private fun copyToClipboard(text: String, label: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clipboard.setPrimaryClip(clip)
        ThemedToast.show(this, "$label copied to clipboard")
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
