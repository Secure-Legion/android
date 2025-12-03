package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.utils.ThemedToast

class TransferDetailsActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_RECIPIENT_NAME = "RECIPIENT_NAME"
        const val EXTRA_AMOUNT = "AMOUNT"
        const val EXTRA_CURRENCY = "CURRENCY"
        const val EXTRA_FROM_WALLET = "FROM_WALLET"
        const val EXTRA_FROM_ADDRESS = "FROM_ADDRESS"
        const val EXTRA_TO_WALLET = "TO_WALLET"
        const val EXTRA_TO_ADDRESS = "TO_ADDRESS"
        const val EXTRA_TRANSACTION_NUMBER = "TRANSACTION_NUMBER"
        const val EXTRA_EXPIRY_DATETIME = "EXPIRY_DATETIME"
        const val EXTRA_TIME = "TIME"
        const val EXTRA_DATE = "DATE"
    }

    private lateinit var backButton: View
    private lateinit var menuButton: View
    private lateinit var recipientName: TextView
    private lateinit var amountSent: TextView
    private lateinit var fromWalletName: TextView
    private lateinit var fromAddress: TextView
    private lateinit var toWalletName: TextView
    private lateinit var toAddress: TextView
    private lateinit var sentSol: TextView
    private lateinit var moneySent: TextView
    private lateinit var expiryDateTime: TextView
    private lateinit var transactionNumber: TextView
    private lateinit var applicationsFee: TextView
    private lateinit var transactionTime: TextView
    private lateinit var transactionDate: TextView
    private lateinit var backToHomeButton: View
    private lateinit var shareButton: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transfer_details)

        initializeViews()
        setupClickListeners()
        loadTransferDetails()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)
        recipientName = findViewById(R.id.recipientName)
        amountSent = findViewById(R.id.amountSent)
        fromWalletName = findViewById(R.id.fromWalletName)
        fromAddress = findViewById(R.id.fromAddress)
        toWalletName = findViewById(R.id.toWalletName)
        toAddress = findViewById(R.id.toAddress)
        sentSol = findViewById(R.id.sentSol)
        moneySent = findViewById(R.id.moneySent)
        expiryDateTime = findViewById(R.id.expiryDateTime)
        transactionNumber = findViewById(R.id.transactionNumber)
        applicationsFee = findViewById(R.id.applicationsFee)
        transactionTime = findViewById(R.id.transactionTime)
        transactionDate = findViewById(R.id.transactionDate)
        backToHomeButton = findViewById(R.id.backToHomeButton)
        shareButton = findViewById(R.id.shareButton)
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener {
            finish()
        }

        menuButton.setOnClickListener {
            ThemedToast.show(this, "Menu coming soon")
        }

        backToHomeButton.setOnClickListener {
            // Go back to MainActivity
            val intent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
            }
            startActivity(intent)
            finish()
        }

        shareButton.setOnClickListener {
            shareTransferDetails()
        }
    }

    private fun loadTransferDetails() {
        val name = intent.getStringExtra(EXTRA_RECIPIENT_NAME) ?: "User"
        val amount = intent.getDoubleExtra(EXTRA_AMOUNT, 0.0)
        val currency = intent.getStringExtra(EXTRA_CURRENCY) ?: "USD"

        recipientName.text = name
        amountSent.text = if (currency == "USD") {
            "$${String.format("%.2f", amount).replace(Regex("(\\d)(?=(\\d{3})+\\.)"),"$1,")}"
        } else {
            String.format("%.4f", amount)
        }

        fromWalletName.text = intent.getStringExtra(EXTRA_FROM_WALLET) ?: "Wallet 1"
        fromAddress.text = intent.getStringExtra(EXTRA_FROM_ADDRESS) ?: "Unknown"
        toWalletName.text = intent.getStringExtra(EXTRA_TO_WALLET) ?: "Wallet 1"
        toAddress.text = intent.getStringExtra(EXTRA_TO_ADDRESS) ?: "Unknown"

        // Calculate SOL amount (placeholder conversion)
        val solAmount = amount / 125.0  // Example: $1,250 / $125 per SOL = 10 SOL
        sentSol.text = String.format("%.2f", solAmount)

        moneySent.text = "$${String.format("%.2f", amount).replace(Regex("(\\d)(?=(\\d{3})+\\.)"),"$1,")}"
        expiryDateTime.text = intent.getStringExtra(EXTRA_EXPIRY_DATETIME) ?: ""
        transactionNumber.text = intent.getStringExtra(EXTRA_TRANSACTION_NUMBER) ?: ""
        applicationsFee.text = "$00.00"
        transactionTime.text = intent.getStringExtra(EXTRA_TIME) ?: ""
        transactionDate.text = intent.getStringExtra(EXTRA_DATE) ?: ""
    }

    private fun shareTransferDetails() {
        val details = """
            Transfer Details

            Recipient: ${recipientName.text}
            Amount: ${amountSent.text}
            Transaction: ${transactionNumber.text}
            Date: ${transactionDate.text} ${transactionTime.text}
        """.trimIndent()

        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, details)
        }

        startActivity(Intent.createChooser(shareIntent, "Share Transfer Details"))
    }
}
