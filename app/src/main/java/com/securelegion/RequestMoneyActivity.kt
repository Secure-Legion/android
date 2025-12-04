package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.NLx402Manager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.services.MessageService
import com.securelegion.services.SolanaService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal
import java.text.SimpleDateFormat
import java.util.*

class RequestMoneyActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "RequestMoneyActivity"
        const val EXTRA_RECIPIENT_NAME = "RECIPIENT_NAME"
        const val EXTRA_RECIPIENT_ADDRESS = "RECIPIENT_ADDRESS"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
    }

    private lateinit var backButton: View
    private lateinit var menuButton: View
    private lateinit var recipientName: TextView
    private lateinit var fromWalletDropdown: View
    private lateinit var fromWalletNameText: TextView
    private lateinit var fromAddressShort: TextView
    private lateinit var amountInput: EditText
    private lateinit var currencyLabel: TextView
    private lateinit var currencyDropdown: View
    private lateinit var expiryDropdown: View
    private lateinit var expiryText: TextView
    private lateinit var requestNowButton: View

    private var selectedToken = "SOL"  // SOL or ZEC
    private var selectedExpirySecs = NLx402Manager.EXPIRY_24_HOURS
    private var currentSolPrice: Double = 0.0

    // Wallet selection
    private var currentWalletId: String = ""
    private var currentWalletName: String = "Wallet 1"
    private var currentWalletAddress: String = ""
    private var currentZcashAddress: String? = null

    private lateinit var keyManager: KeyManager
    private lateinit var solanaService: SolanaService
    private var contactId: Long = -1

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_request_money)

        keyManager = KeyManager.getInstance(this)
        solanaService = SolanaService(this)
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)

        // Get wallet info from intent if available
        currentWalletId = intent.getStringExtra("WALLET_ID") ?: ""
        currentWalletName = intent.getStringExtra("WALLET_NAME") ?: "Wallet 1"
        currentWalletAddress = intent.getStringExtra("WALLET_ADDRESS") ?: ""

        initializeViews()
        setupClickListeners()
        loadRecipientInfo()
        loadWalletInfo()
        fetchSolPrice()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)
        recipientName = findViewById(R.id.recipientName)
        fromWalletDropdown = findViewById(R.id.fromWalletDropdown)
        fromWalletNameText = findViewById(R.id.fromWalletNameText)
        fromAddressShort = findViewById(R.id.fromAddressShort)
        amountInput = findViewById(R.id.amountInput)
        currencyLabel = findViewById(R.id.currencyLabel)
        currencyDropdown = findViewById(R.id.currencyDropdown)
        expiryDropdown = findViewById(R.id.expiryDropdown)
        expiryText = findViewById(R.id.expiryText)
        requestNowButton = findViewById(R.id.requestNowButton)
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener {
            finish()
        }

        menuButton.setOnClickListener {
            ThemedToast.show(this, "Menu coming soon")
        }

        fromWalletDropdown.setOnClickListener {
            showWalletSelector()
        }

        currencyDropdown.setOnClickListener {
            showCurrencySelector()
        }

        expiryDropdown.setOnClickListener {
            showExpirySelector()
        }

        requestNowButton.setOnClickListener {
            requestMoney()
        }
    }

    private fun showCurrencySelector() {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_currency_selector, null)
        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)
        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Get check marks
        val checkSOL = view.findViewById<ImageView>(R.id.checkSOL)
        val checkZEC = view.findViewById<ImageView>(R.id.checkZEC)

        // Show current selection
        checkSOL.visibility = if (selectedToken == "SOL") View.VISIBLE else View.GONE
        checkZEC.visibility = if (selectedToken == "ZEC") View.VISIBLE else View.GONE

        // Set click listeners
        view.findViewById<View>(R.id.optionSOL).setOnClickListener {
            if (selectedToken != "SOL") {
                selectedToken = "SOL"
                currencyLabel.text = selectedToken
                // Reload wallet list for SOL chain
                loadWalletInfoForChain("SOL")
            }
            bottomSheet.dismiss()
        }
        view.findViewById<View>(R.id.optionZEC).setOnClickListener {
            if (selectedToken != "ZEC") {
                selectedToken = "ZEC"
                currencyLabel.text = selectedToken
                // Reload wallet list for ZEC chain
                loadWalletInfoForChain("ZEC")
            }
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun loadWalletInfoForChain(chain: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@RequestMoneyActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter wallets that have the appropriate address for this chain
                val wallets = allWallets.filter { wallet ->
                    wallet.walletId != "main" && when (chain) {
                        "ZEC" -> !wallet.zcashAddress.isNullOrEmpty()
                        else -> wallet.solanaAddress.isNotEmpty()
                    }
                }

                if (wallets.isNotEmpty()) {
                    val firstWallet = wallets.first()
                    currentWalletId = firstWallet.walletId
                    currentWalletName = firstWallet.name
                    currentWalletAddress = firstWallet.solanaAddress
                    currentZcashAddress = firstWallet.zcashAddress

                    val displayAddress = when (chain) {
                        "ZEC" -> firstWallet.zcashAddress ?: ""
                        else -> firstWallet.solanaAddress
                    }

                    withContext(Dispatchers.Main) {
                        fromWalletNameText.text = currentWalletName
                        fromAddressShort.text = formatAddressShort(displayAddress)
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        fromWalletNameText.text = "No wallet"
                        fromAddressShort.text = "Set up $chain wallet"
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallets for chain $chain", e)
            }
        }
    }

    private fun showExpirySelector() {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_expiry_selector, null)
        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)
        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Get all check marks
        val check15Min = view.findViewById<ImageView>(R.id.check15Min)
        val check1Hour = view.findViewById<ImageView>(R.id.check1Hour)
        val check6Hours = view.findViewById<ImageView>(R.id.check6Hours)
        val check24Hours = view.findViewById<ImageView>(R.id.check24Hours)
        val check48Hours = view.findViewById<ImageView>(R.id.check48Hours)
        val check7Days = view.findViewById<ImageView>(R.id.check7Days)

        // Helper to update check marks
        fun updateChecks(selected: Long) {
            check15Min.visibility = if (selected == NLx402Manager.EXPIRY_15_MIN) View.VISIBLE else View.GONE
            check1Hour.visibility = if (selected == NLx402Manager.EXPIRY_1_HOUR) View.VISIBLE else View.GONE
            check6Hours.visibility = if (selected == NLx402Manager.EXPIRY_6_HOURS) View.VISIBLE else View.GONE
            check24Hours.visibility = if (selected == NLx402Manager.EXPIRY_24_HOURS) View.VISIBLE else View.GONE
            check48Hours.visibility = if (selected == NLx402Manager.EXPIRY_48_HOURS) View.VISIBLE else View.GONE
            check7Days.visibility = if (selected == NLx402Manager.EXPIRY_7_DAYS) View.VISIBLE else View.GONE
        }

        // Show current selection
        updateChecks(selectedExpirySecs)

        // Set click listeners
        view.findViewById<View>(R.id.option15Min).setOnClickListener {
            selectedExpirySecs = NLx402Manager.EXPIRY_15_MIN
            expiryText.text = "15 minutes"
            bottomSheet.dismiss()
        }
        view.findViewById<View>(R.id.option1Hour).setOnClickListener {
            selectedExpirySecs = NLx402Manager.EXPIRY_1_HOUR
            expiryText.text = "1 hour"
            bottomSheet.dismiss()
        }
        view.findViewById<View>(R.id.option6Hours).setOnClickListener {
            selectedExpirySecs = NLx402Manager.EXPIRY_6_HOURS
            expiryText.text = "6 hours"
            bottomSheet.dismiss()
        }
        view.findViewById<View>(R.id.option24Hours).setOnClickListener {
            selectedExpirySecs = NLx402Manager.EXPIRY_24_HOURS
            expiryText.text = "24 hours"
            bottomSheet.dismiss()
        }
        view.findViewById<View>(R.id.option48Hours).setOnClickListener {
            selectedExpirySecs = NLx402Manager.EXPIRY_48_HOURS
            expiryText.text = "48 hours"
            bottomSheet.dismiss()
        }
        view.findViewById<View>(R.id.option7Days).setOnClickListener {
            selectedExpirySecs = NLx402Manager.EXPIRY_7_DAYS
            expiryText.text = "7 days"
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@RequestMoneyActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter wallets: exclude "main" and only show wallets with address for selected chain
                val wallets = allWallets.filter { wallet ->
                    wallet.walletId != "main" && when (selectedToken) {
                        "ZEC" -> !wallet.zcashAddress.isNullOrEmpty()
                        else -> wallet.solanaAddress.isNotEmpty()
                    }
                }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@RequestMoneyActivity, "No $selectedToken wallets found")
                        return@withContext
                    }

                    val bottomSheet = BottomSheetDialog(this@RequestMoneyActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)

                    val displayMetrics = resources.displayMetrics
                    val screenHeight = displayMetrics.heightPixels
                    val desiredHeight = (screenHeight * 0.6).toInt()
                    view.minimumHeight = desiredHeight

                    bottomSheet.setContentView(view)

                    bottomSheet.behavior.isDraggable = true
                    bottomSheet.behavior.isFitToContents = true
                    bottomSheet.behavior.skipCollapsed = true

                    bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
                    bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

                    view.post {
                        val parentView = view.parent as? View
                        parentView?.setBackgroundResource(android.R.color.transparent)
                    }

                    val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)

                    for (wallet in wallets) {
                        val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                        val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                        val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
                        val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

                        // Show appropriate address based on chain
                        val displayAddress = when (selectedToken) {
                            "ZEC" -> wallet.zcashAddress ?: ""
                            else -> wallet.solanaAddress
                        }

                        walletName.text = wallet.name
                        walletBalance.text = formatAddressShort(displayAddress)

                        walletItemView.setOnClickListener {
                            switchToWallet(wallet)
                            bottomSheet.dismiss()
                        }

                        settingsBtn.setOnClickListener {
                            val intent = Intent(this@RequestMoneyActivity, WalletSettingsActivity::class.java)
                            intent.putExtra("WALLET_ID", wallet.walletId)
                            intent.putExtra("WALLET_NAME", wallet.name)
                            intent.putExtra("IS_MAIN_WALLET", wallet.walletId == "main")
                            startActivity(intent)
                            bottomSheet.dismiss()
                        }

                        walletListContainer.addView(walletItemView)
                    }

                    bottomSheet.show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@RequestMoneyActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun switchToWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i(TAG, "Switching to wallet: ${wallet.name}")

                currentWalletId = wallet.walletId
                currentWalletName = wallet.name
                currentWalletAddress = wallet.solanaAddress
                currentZcashAddress = wallet.zcashAddress

                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@RequestMoneyActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                // Display appropriate address based on selected chain
                val displayAddress = when (selectedToken) {
                    "ZEC" -> wallet.zcashAddress ?: ""
                    else -> wallet.solanaAddress
                }

                withContext(Dispatchers.Main) {
                    fromWalletNameText.text = currentWalletName
                    fromAddressShort.text = formatAddressShort(displayAddress)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to switch wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@RequestMoneyActivity, "Failed to switch wallet")
                }
            }
        }
    }

    private fun loadRecipientInfo() {
        val name = intent.getStringExtra(EXTRA_RECIPIENT_NAME) ?: "User"
        recipientName.text = name
    }

    private fun loadWalletInfo() {
        // If wallet info was passed in intent, use it
        if (currentWalletAddress.isNotEmpty()) {
            fromWalletNameText.text = currentWalletName
            fromAddressShort.text = formatAddressShort(currentWalletAddress)
            return
        }

        // Otherwise, load first available wallet from database
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@RequestMoneyActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                if (wallets.isNotEmpty()) {
                    val firstWallet = wallets.first()
                    currentWalletId = firstWallet.walletId
                    currentWalletName = firstWallet.name
                    currentWalletAddress = firstWallet.solanaAddress
                    currentZcashAddress = firstWallet.zcashAddress

                    // Detect wallet type and sync currency selector
                    val isZcashWallet = !firstWallet.zcashAddress.isNullOrEmpty() && firstWallet.solanaAddress.isEmpty()
                    selectedToken = if (isZcashWallet) "ZEC" else "SOL"

                    val displayAddress = if (isZcashWallet) {
                        firstWallet.zcashAddress ?: ""
                    } else {
                        firstWallet.solanaAddress
                    }

                    withContext(Dispatchers.Main) {
                        fromWalletNameText.text = currentWalletName
                        fromAddressShort.text = formatAddressShort(displayAddress)
                        currencyLabel.text = selectedToken
                    }
                } else {
                    // Fallback to KeyManager address
                    val solanaAddress = keyManager.getSolanaAddress()
                    currentWalletAddress = solanaAddress

                    withContext(Dispatchers.Main) {
                        fromWalletNameText.text = "Wallet"
                        fromAddressShort.text = formatAddressShort(solanaAddress)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallet info", e)
                withContext(Dispatchers.Main) {
                    fromWalletNameText.text = "Wallet"
                    fromAddressShort.text = "..."
                }
            }
        }
    }

    private fun fetchSolPrice() {
        lifecycleScope.launch {
            try {
                val result = solanaService.getSolPrice()
                if (result.isSuccess) {
                    currentSolPrice = result.getOrNull() ?: 0.0
                    Log.d(TAG, "SOL price: $currentSolPrice")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch SOL price", e)
            }
        }
    }

    private fun formatAddressShort(address: String): String {
        return if (address.length > 12) {
            "${address.take(6)}...${address.takeLast(4)}"
        } else {
            address
        }
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
        val confirmRequestExpiry = view.findViewById<TextView>(R.id.confirmRequestExpiry)

        // Set values using the selected token
        val formattedAmount = String.format("%.4f %s", amount, selectedToken)

        confirmRequestAmount.text = formattedAmount
        confirmRequestFrom.text = recipientName.text
        confirmRequestRecipient.text = recipientName.text
        confirmRequestToWallet.text = currentWalletName
        confirmRequestCurrency.text = selectedToken
        confirmRequestExpiry.text = NLx402Manager.getExpiryLabel(selectedExpirySecs)

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
        // Show loading state
        requestNowButton.isEnabled = false
        ThemedToast.show(this, "Creating payment request...")

        lifecycleScope.launch {
            try {
                // Get appropriate wallet address based on token from selected wallet
                val myAddress = when (selectedToken) {
                    "ZEC" -> {
                        // Use Zcash address from selected wallet, or fallback to KeyManager
                        currentZcashAddress ?: keyManager.getZcashAddress() ?: run {
                            withContext(Dispatchers.Main) {
                                requestNowButton.isEnabled = true
                                ThemedToast.show(this@RequestMoneyActivity, "Zcash wallet not set up for $currentWalletName")
                            }
                            return@launch
                        }
                    }
                    else -> {
                        // Use Solana address from selected wallet
                        if (currentWalletAddress.isNotEmpty()) {
                            currentWalletAddress
                        } else {
                            keyManager.getSolanaAddress()
                        }
                    }
                }

                // Create NLx402 quote with selected token and expiry
                val quote = NLx402Manager.createQuoteFromAmount(
                    recipientAddress = myAddress, // I receive the money
                    amount = BigDecimal(amount),
                    token = selectedToken,
                    description = "Payment request",
                    senderHandle = intent.getStringExtra(EXTRA_RECIPIENT_NAME),
                    recipientHandle = null,
                    expirySecs = selectedExpirySecs
                )

                if (quote == null) {
                    withContext(Dispatchers.Main) {
                        requestNowButton.isEnabled = true
                        ThemedToast.show(this@RequestMoneyActivity, "Failed to create payment request")
                    }
                    return@launch
                }

                Log.d(TAG, "Created payment request quote: ${quote.quoteId} for ${quote.formattedAmount}")
                Log.i(TAG, "╔════════════════════════════════════════")
                Log.i(TAG, "║ SENDING PAYMENT REQUEST")
                Log.i(TAG, "║ Contact ID: $contactId")
                Log.i(TAG, "║ Quote: ${quote.formattedAmount}")
                Log.i(TAG, "╚════════════════════════════════════════")

                // Send payment request message to contact via MessageService
                if (contactId > 0) {
                    val messageService = MessageService(this@RequestMoneyActivity)
                    Log.d(TAG, "Calling messageService.sendPaymentRequest...")
                    val sendResult = messageService.sendPaymentRequest(contactId, quote)

                    if (sendResult.isSuccess) {
                        Log.i(TAG, "✓ Payment request message sent successfully")
                    } else {
                        Log.e(TAG, "✗ Failed to send payment request message: ${sendResult.exceptionOrNull()?.message}")
                        sendResult.exceptionOrNull()?.printStackTrace()
                        // Continue anyway - the quote was created successfully
                    }
                } else {
                    Log.e(TAG, "✗ No contact ID provided (contactId=$contactId) - payment request NOT sent as message!")
                }

                // Generate transaction details for display
                val currentTime = Calendar.getInstance()
                val expiryLabel = NLx402Manager.getExpiryLabel(selectedExpirySecs)

                val timeFormat = SimpleDateFormat("hh:mm a", Locale.getDefault())
                val time = timeFormat.format(currentTime.time)

                val dateFormat = SimpleDateFormat("dd MMM, yyyy", Locale.getDefault())
                val date = dateFormat.format(currentTime.time)

                withContext(Dispatchers.Main) {
                    // Launch Request Details screen
                    val detailsIntent = Intent(this@RequestMoneyActivity, RequestDetailsActivity::class.java).apply {
                        putExtra(RequestDetailsActivity.EXTRA_RECIPIENT_NAME, recipientName.text.toString())
                        putExtra(RequestDetailsActivity.EXTRA_AMOUNT, amount)
                        putExtra(RequestDetailsActivity.EXTRA_CURRENCY, selectedToken)
                        putExtra(RequestDetailsActivity.EXTRA_TRANSACTION_NUMBER, quote.quoteId)
                        putExtra(RequestDetailsActivity.EXTRA_QUOTE_JSON, quote.rawJson)
                        putExtra(RequestDetailsActivity.EXTRA_EXPIRY_DATETIME, "Expires in $expiryLabel")
                        putExtra(RequestDetailsActivity.EXTRA_TIME, time)
                        putExtra(RequestDetailsActivity.EXTRA_DATE, date)
                    }
                    startActivity(detailsIntent)
                    finish()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create payment request", e)
                withContext(Dispatchers.Main) {
                    requestNowButton.isEnabled = true
                    ThemedToast.show(this@RequestMoneyActivity, "Error: ${e.message}")
                }
            }
        }
    }
}
