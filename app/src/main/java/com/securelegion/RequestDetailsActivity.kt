package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.database.entities.Message
import com.securelegion.services.SolanaService
import com.securelegion.services.ZcashService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.launch

class RequestDetailsActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_RECIPIENT_NAME = "RECIPIENT_NAME"
        const val EXTRA_AMOUNT = "AMOUNT"
        const val EXTRA_CURRENCY = "CURRENCY"
        const val EXTRA_TRANSACTION_NUMBER = "TRANSACTION_NUMBER"
        const val EXTRA_EXPIRY_DATETIME = "EXPIRY_DATETIME"
        const val EXTRA_TIME = "TIME"
        const val EXTRA_DATE = "DATE"
        const val EXTRA_QUOTE_JSON = "QUOTE_JSON"
        const val EXTRA_PAYMENT_STATUS = "PAYMENT_STATUS"
    }

    private lateinit var backButton: View
    private lateinit var menuButton: View
    private lateinit var editButton: View
    private lateinit var recipientName: TextView
    private lateinit var statusMessage: TextView
    private lateinit var amountRequested: TextView
    private lateinit var cryptoAmountLabel: TextView
    private lateinit var sentSol: TextView
    private lateinit var moneySent: TextView
    private lateinit var expiryDateTime: TextView
    private lateinit var transactionNumber: TextView
    private lateinit var applicationsFee: TextView
    private lateinit var transactionTime: TextView
    private lateinit var transactionDate: TextView
    private lateinit var backToHomeButton: View
    private lateinit var shareButton: View

    private var currency: String = "SOL"
    private var cryptoAmount: Double = 0.0

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
        statusMessage = findViewById(R.id.statusMessage)
        amountRequested = findViewById(R.id.amountRequested)
        cryptoAmountLabel = findViewById(R.id.cryptoAmountLabel)
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
        cryptoAmount = intent.getDoubleExtra(EXTRA_AMOUNT, 0.0)
        currency = intent.getStringExtra(EXTRA_CURRENCY) ?: "SOL"
        val paymentStatus = intent.getStringExtra(EXTRA_PAYMENT_STATUS) ?: Message.PAYMENT_STATUS_PENDING

        recipientName.text = name

        // Format crypto amount with smart precision
        val formattedCrypto = formatCryptoAmount(cryptoAmount, currency)
        sentSol.text = formattedCrypto

        // Update status message based on payment status
        statusMessage.text = when (paymentStatus) {
            Message.PAYMENT_STATUS_PAID -> "Request has been paid!"
            Message.PAYMENT_STATUS_EXPIRED -> "Request has expired"
            Message.PAYMENT_STATUS_CANCELLED -> "Request was cancelled"
            else -> "You have successfully requested!"
        }

        // Set expiry, transaction number, time, date
        expiryDateTime.text = intent.getStringExtra(EXTRA_EXPIRY_DATETIME) ?: ""
        transactionNumber.text = intent.getStringExtra(EXTRA_TRANSACTION_NUMBER) ?: ""
        applicationsFee.text = "$0.00"
        transactionTime.text = intent.getStringExtra(EXTRA_TIME) ?: ""
        transactionDate.text = intent.getStringExtra(EXTRA_DATE) ?: ""

        // Fetch live price and update USD values
        fetchPriceAndUpdateUsd()
    }

    private fun fetchPriceAndUpdateUsd() {
        lifecycleScope.launch {
            try {
                val price = when (currency.uppercase()) {
                    "SOL" -> {
                        val solanaService = SolanaService(this@RequestDetailsActivity)
                        val result = solanaService.getSolPrice()
                        if (result.isSuccess) result.getOrNull() ?: 0.0 else 0.0
                    }
                    "ZEC" -> {
                        val zcashService = ZcashService.getInstance(this@RequestDetailsActivity)
                        val result = zcashService.getZecPrice()
                        if (result.isSuccess) result.getOrNull() ?: 0.0 else 0.0
                    }
                    else -> 0.0
                }

                if (price > 0) {
                    val usdValue = cryptoAmount * price

                    // Update main amount display (USD)
                    amountRequested.text = String.format("$%.2f", usdValue)

                    // Update USD value row
                    moneySent.text = String.format("$%.2f", usdValue)
                } else {
                    // Fallback if price fetch fails
                    amountRequested.text = formatCryptoAmount(cryptoAmount, currency)
                    moneySent.text = "Price unavailable"
                }
            } catch (e: Exception) {
                amountRequested.text = formatCryptoAmount(cryptoAmount, currency)
                moneySent.text = "Price unavailable"
            }
        }
    }

    private fun formatCryptoAmount(amount: Double, token: String): String {
        val formatted = when {
            amount >= 1.0 -> String.format("%.2f", amount)
            amount >= 0.01 -> String.format("%.4f", amount).trimEnd('0').trimEnd('.')
            amount > 0.0 -> String.format("%.6f", amount).trimEnd('0').trimEnd('.')
            else -> "0"
        }
        return "$formatted $token"
    }

    private fun shareRequestDetails() {
        val details = """
            Request Details

            Recipient: ${recipientName.text}
            Amount: ${sentSol.text}
            USD Value: ${moneySent.text}
            Request ID: ${transactionNumber.text}
            Date: ${transactionDate.text} ${transactionTime.text}
        """.trimIndent()

        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, details)
        }

        startActivity(Intent.createChooser(shareIntent, "Share Request Details"))
    }
}
