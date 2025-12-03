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

class RequestMoneyActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_RECIPIENT_NAME = "RECIPIENT_NAME"
        const val EXTRA_RECIPIENT_ADDRESS = "RECIPIENT_ADDRESS"
    }

    private lateinit var backButton: View
    private lateinit var menuButton: View
    private lateinit var editButton: View
    private lateinit var recipientName: TextView
    private lateinit var fromWalletDropdown: View
    private lateinit var fromWalletNameText: TextView
    private lateinit var fromAddressShort: TextView
    private lateinit var toDropdownIcon: ImageView
    private lateinit var toAddressShort: TextView
    private lateinit var amountDropdown: View
    private lateinit var amountInput: EditText
    private lateinit var currencyLabel: TextView
    private lateinit var requestNowButton: View

    private var showUSD = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_request_money)

        initializeViews()
        setupClickListeners()
        loadRecipientInfo()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)
        editButton = findViewById(R.id.editButton)
        recipientName = findViewById(R.id.recipientName)
        fromWalletDropdown = findViewById(R.id.fromWalletDropdown)
        fromWalletNameText = findViewById(R.id.fromWalletNameText)
        fromAddressShort = findViewById(R.id.fromAddressShort)
        toDropdownIcon = findViewById(R.id.toDropdownIcon)
        toAddressShort = findViewById(R.id.toAddressShort)
        amountDropdown = findViewById(R.id.amountDropdown)
        amountInput = findViewById(R.id.amountInput)
        currencyLabel = findViewById(R.id.currencyLabel)
        requestNowButton = findViewById(R.id.requestNowButton)
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

        fromWalletDropdown.setOnClickListener {
            // TODO: Show wallet selector
            ThemedToast.show(this, "Wallet selector coming soon")
        }

        toDropdownIcon.setOnClickListener {
            // TODO: Show recipient selector
            ThemedToast.show(this, "Recipient selector coming soon")
        }

        amountDropdown.setOnClickListener {
            toggleCurrency()
        }

        requestNowButton.setOnClickListener {
            requestMoney()
        }
    }

    private fun loadRecipientInfo() {
        val name = intent.getStringExtra(EXTRA_RECIPIENT_NAME) ?: "User"
        val address = intent.getStringExtra(EXTRA_RECIPIENT_ADDRESS) ?: "Unknown"

        recipientName.text = name
        toAddressShort.text = if (address.length > 15) {
            "${address.take(5)}.....${address.takeLast(6)}"
        } else {
            address
        }
    }

    private fun toggleCurrency() {
        showUSD = !showUSD
        currencyLabel.text = if (showUSD) "USD" else "SOL"

        // TODO: Convert amount between currencies
    }

    private fun requestMoney() {
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

        // Show confirmation dialog
        showRequestConfirmation(amount)
    }

    private fun showRequestConfirmation(amount: Double) {
        // Create bottom sheet dialog
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_request_confirm, null)

        // Set minimum height on the view itself
        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        val desiredHeight = (screenHeight * 0.7).toInt()
        view.minimumHeight = desiredHeight

        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make all backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        // Remove the white background box
        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Populate confirmation details
        val confirmRequestAmount = view.findViewById<TextView>(R.id.confirmRequestAmount)
        val confirmRequestFrom = view.findViewById<TextView>(R.id.confirmRequestFrom)
        val confirmRequestRecipient = view.findViewById<TextView>(R.id.confirmRequestRecipient)
        val confirmRequestToWallet = view.findViewById<TextView>(R.id.confirmRequestToWallet)
        val confirmRequestCurrency = view.findViewById<TextView>(R.id.confirmRequestCurrency)

        // Set values
        val currency = if (showUSD) "USD" else "SOL"
        val formattedAmount = if (showUSD) {
            String.format("$%.2f", amount)
        } else {
            String.format("%.4f %s", amount, currency)
        }

        confirmRequestAmount.text = formattedAmount
        confirmRequestFrom.text = recipientName.text
        confirmRequestRecipient.text = recipientName.text
        confirmRequestToWallet.text = fromWalletNameText.text
        confirmRequestCurrency.text = currency

        // Confirm button
        val confirmButton = view.findViewById<View>(R.id.confirmRequestButton)
        confirmButton.setOnClickListener {
            bottomSheet.dismiss()
            proceedWithRequest(amount)
        }

        // Cancel button
        val cancelButton = view.findViewById<View>(R.id.cancelRequestButton)
        cancelButton.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun proceedWithRequest(amount: Double) {
        // Generate transaction details
        val currentTime = Calendar.getInstance()
        val expiryTime = Calendar.getInstance().apply {
            add(Calendar.MINUTE, 15)
        }
        val expiryFormat = SimpleDateFormat("m 'Min' dd MMM yyyy", Locale.getDefault())
        val expiryDateTime = expiryFormat.format(expiryTime.time)

        val invoiceFormat = SimpleDateFormat("yyyyMMdd", Locale.getDefault())
        val transactionNumber = "#${invoiceFormat.format(currentTime.time)}${(100..999).random()}"

        val timeFormat = SimpleDateFormat("hh:mm a", Locale.getDefault())
        val time = timeFormat.format(currentTime.time)

        val dateFormat = SimpleDateFormat("dd MMM, yyyy", Locale.getDefault())
        val date = dateFormat.format(currentTime.time)

        // Launch Request Details screen
        val intent = Intent(this, RequestDetailsActivity::class.java).apply {
            putExtra(RequestDetailsActivity.EXTRA_RECIPIENT_NAME, recipientName.text.toString())
            putExtra(RequestDetailsActivity.EXTRA_AMOUNT, amount)
            putExtra(RequestDetailsActivity.EXTRA_CURRENCY, if (showUSD) "USD" else "SOL")
            putExtra(RequestDetailsActivity.EXTRA_TRANSACTION_NUMBER, transactionNumber)
            putExtra(RequestDetailsActivity.EXTRA_EXPIRY_DATETIME, expiryDateTime)
            putExtra(RequestDetailsActivity.EXTRA_TIME, time)
            putExtra(RequestDetailsActivity.EXTRA_DATE, date)
        }
        startActivity(intent)
        finish()
    }
}
