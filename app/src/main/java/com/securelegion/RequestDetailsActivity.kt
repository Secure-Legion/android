package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.utils.ThemedToast

class RequestDetailsActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_RECIPIENT_NAME = "RECIPIENT_NAME"
        const val EXTRA_AMOUNT = "AMOUNT"
        const val EXTRA_CURRENCY = "CURRENCY"
        const val EXTRA_TRANSACTION_NUMBER = "TRANSACTION_NUMBER"
        const val EXTRA_EXPIRY_DATETIME = "EXPIRY_DATETIME"
        const val EXTRA_TIME = "TIME"
        const val EXTRA_DATE = "DATE"
    }

    private lateinit var backButton: View
    private lateinit var menuButton: View
    private lateinit var editButton: View
    private lateinit var recipientName: TextView
    private lateinit var amountRequested: TextView
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
        setContentView(R.layout.activity_request_details)

        initializeViews()
        setupClickListeners()
        loadRequestDetails()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)
        editButton = findViewById(R.id.editButton)
        recipientName = findViewById(R.id.recipientName)
        amountRequested = findViewById(R.id.amountRequested)
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

        editButton.setOnClickListener {
            ThemedToast.show(this, "Edit recipient coming soon")
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
            shareRequestDetails()
        }
    }

    private fun loadRequestDetails() {
        val name = intent.getStringExtra(EXTRA_RECIPIENT_NAME) ?: "User"
        val amount = intent.getDoubleExtra(EXTRA_AMOUNT, 0.0)
        val currency = intent.getStringExtra(EXTRA_CURRENCY) ?: "USD"

        recipientName.text = name
        amountRequested.text = if (currency == "USD") {
            "$${String.format("%.2f", amount).replace(Regex("(\\d)(?=(\\d{3})+\\.)"), "$1,")}"
        } else {
            String.format("%.4f", amount)
        }

        // Calculate SOL amount (placeholder conversion)
        val solAmount = amount / 125.0  // Example: $1,250 / $125 per SOL = 10 SOL
        sentSol.text = String.format("%.2f", solAmount)

        moneySent.text = "$${String.format("%.2f", amount).replace(Regex("(\\d)(?=(\\d{3})+\\.)"), "$1,")}"
        expiryDateTime.text = intent.getStringExtra(EXTRA_EXPIRY_DATETIME) ?: ""
        transactionNumber.text = intent.getStringExtra(EXTRA_TRANSACTION_NUMBER) ?: ""
        applicationsFee.text = "$00.00"
        transactionTime.text = intent.getStringExtra(EXTRA_TIME) ?: ""
        transactionDate.text = intent.getStringExtra(EXTRA_DATE) ?: ""
    }

    private fun shareRequestDetails() {
        val details = """
            Request Details

            Recipient: ${recipientName.text}
            Amount: ${amountRequested.text}
            Transaction: ${transactionNumber.text}
            Date: ${transactionDate.text} ${transactionTime.text}
        """.trimIndent()

        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, details)
        }

        startActivity(Intent.createChooser(shareIntent, "Share Request Details"))
    }
}
