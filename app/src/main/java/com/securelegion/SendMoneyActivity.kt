package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.utils.ThemedToast
import java.text.SimpleDateFormat
import java.util.*

class SendMoneyActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_RECIPIENT_NAME = "RECIPIENT_NAME"
        const val EXTRA_RECIPIENT_ADDRESS = "RECIPIENT_ADDRESS"
    }

    private lateinit var backButton: View
    private lateinit var menuButton: View
    private lateinit var recipientName: TextView
    private lateinit var walletNameDropdown: View
    private lateinit var walletNameText: TextView
    private lateinit var walletAddressShort: TextView
    private lateinit var expiryDateTime: TextView
    private lateinit var invoiceNumber: TextView
    private lateinit var applicationFee: TextView
    private lateinit var transactionTime: TextView
    private lateinit var transactionDate: TextView
    private lateinit var amountDropdown: View
    private lateinit var amountInput: EditText
    private lateinit var currencyLabel: TextView
    private lateinit var sendNowButton: View

    private var showUSD = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_send_money)

        initializeViews()
        setupClickListeners()
        loadRecipientInfo()
        setupTransactionDetails()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)
        recipientName = findViewById(R.id.recipientName)
        walletNameDropdown = findViewById(R.id.walletNameDropdown)
        walletNameText = findViewById(R.id.walletNameText)
        walletAddressShort = findViewById(R.id.walletAddressShort)
        expiryDateTime = findViewById(R.id.expiryDateTime)
        invoiceNumber = findViewById(R.id.invoiceNumber)
        applicationFee = findViewById(R.id.applicationFee)
        transactionTime = findViewById(R.id.transactionTime)
        transactionDate = findViewById(R.id.transactionDate)
        amountDropdown = findViewById(R.id.amountDropdown)
        amountInput = findViewById(R.id.amountInput)
        currencyLabel = findViewById(R.id.currencyLabel)
        sendNowButton = findViewById(R.id.sendNowButton)
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener {
            finish()
        }

        menuButton.setOnClickListener {
            ThemedToast.show(this, "Menu coming soon")
        }

        walletNameDropdown.setOnClickListener {
            // TODO: Show wallet selector
            ThemedToast.show(this, "Wallet selector coming soon")
        }

        amountDropdown.setOnClickListener {
            toggleCurrency()
        }

        sendNowButton.setOnClickListener {
            sendMoney()
        }
    }

    private fun loadRecipientInfo() {
        val name = intent.getStringExtra(EXTRA_RECIPIENT_NAME) ?: "User"
        recipientName.text = name
    }

    private fun setupTransactionDetails() {
        val currentTime = Calendar.getInstance()

        // Expiry time (15 minutes from now)
        val expiryTime = Calendar.getInstance().apply {
            add(Calendar.MINUTE, 15)
        }
        val expiryFormat = SimpleDateFormat("m 'Min' dd MMM yyyy", Locale.getDefault())
        expiryDateTime.text = expiryFormat.format(expiryTime.time)

        // Invoice number (timestamp-based)
        val invoiceFormat = SimpleDateFormat("yyyyMMdd", Locale.getDefault())
        invoiceNumber.text = "#${invoiceFormat.format(currentTime.time)}${(100..999).random()}"

        // Application fee
        applicationFee.text = "$0.00"

        // Time
        val timeFormat = SimpleDateFormat("hh:mm a", Locale.getDefault())
        transactionTime.text = timeFormat.format(currentTime.time)

        // Date
        val dateFormat = SimpleDateFormat("dd MMM, yyyy", Locale.getDefault())
        transactionDate.text = dateFormat.format(currentTime.time)
    }

    private fun toggleCurrency() {
        showUSD = !showUSD
        currencyLabel.text = if (showUSD) "USD" else "SOL"

        // TODO: Convert amount between currencies
    }

    private fun sendMoney() {
        val amountText = amountInput.text.toString().replace("$", "").replace(",", "")

        if (amountText.isEmpty()) {
            ThemedToast.show(this, "Please enter an amount")
            return
        }

        val amount = amountText.toDoubleOrNull()
        if (amount == null || amount <= 0) {
            ThemedToast.show(this, "Please enter a valid amount")
            return
        }

        // Show confirmation bottom sheet
        showSendConfirmationSheet(amount)
    }

    private fun showSendConfirmationSheet(amount: Double) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_send_confirm, null)
        bottomSheet.setContentView(view)

        // Populate confirmation details
        val confirmAmount = view.findViewById<TextView>(R.id.confirmAmount)
        val confirmRecipientShort = view.findViewById<TextView>(R.id.confirmRecipientShort)
        val confirmFromWallet = view.findViewById<TextView>(R.id.confirmFromWallet)
        val confirmToAddress = view.findViewById<TextView>(R.id.confirmToAddress)
        val confirmCurrency = view.findViewById<TextView>(R.id.confirmCurrency)
        val confirmNetworkFee = view.findViewById<TextView>(R.id.confirmNetworkFee)
        val confirmSendButton = view.findViewById<View>(R.id.confirmSendButton)
        val cancelSendButton = view.findViewById<View>(R.id.cancelSendButton)

        // Set values
        val currency = if (showUSD) "USD" else "SOL"
        confirmAmount.text = if (showUSD) "$$amount" else "$amount SOL"
        confirmRecipientShort.text = intent.getStringExtra(EXTRA_RECIPIENT_ADDRESS) ?: "Unknown"
        confirmFromWallet.text = walletNameText.text.toString()
        confirmToAddress.text = intent.getStringExtra(EXTRA_RECIPIENT_ADDRESS) ?: "Unknown"
        confirmCurrency.text = currency
        confirmNetworkFee.text = "~0.000005 SOL"

        // Confirm button
        confirmSendButton.setOnClickListener {
            bottomSheet.dismiss()
            proceedToTransferDetails(amount)
        }

        // Cancel button
        cancelSendButton.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun proceedToTransferDetails(amount: Double) {
        // TODO: Implement actual blockchain send functionality

        // Launch Transfer Details screen
        val intent = Intent(this, TransferDetailsActivity::class.java).apply {
            putExtra(TransferDetailsActivity.EXTRA_RECIPIENT_NAME, recipientName.text.toString())
            putExtra(TransferDetailsActivity.EXTRA_AMOUNT, amount)
            putExtra(TransferDetailsActivity.EXTRA_CURRENCY, if (showUSD) "USD" else "SOL")
            putExtra(TransferDetailsActivity.EXTRA_FROM_WALLET, walletNameText.text.toString())
            putExtra(TransferDetailsActivity.EXTRA_FROM_ADDRESS, walletAddressShort.text.toString())
            putExtra(TransferDetailsActivity.EXTRA_TO_WALLET, "Wallet 1") // TODO: Get actual recipient wallet
            putExtra(TransferDetailsActivity.EXTRA_TO_ADDRESS, getIntent().getStringExtra(EXTRA_RECIPIENT_ADDRESS) ?: "Unknown")
            putExtra(TransferDetailsActivity.EXTRA_TRANSACTION_NUMBER, invoiceNumber.text.toString())
            putExtra(TransferDetailsActivity.EXTRA_EXPIRY_DATETIME, expiryDateTime.text.toString())
            putExtra(TransferDetailsActivity.EXTRA_TIME, transactionTime.text.toString())
            putExtra(TransferDetailsActivity.EXTRA_DATE, transactionDate.text.toString())
        }
        startActivity(intent)
        finish()
    }
}
