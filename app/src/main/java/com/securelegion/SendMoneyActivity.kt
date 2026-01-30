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
import com.securelegion.services.ZcashService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal

class SendMoneyActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "SendMoneyActivity"
        const val EXTRA_RECIPIENT_NAME = "RECIPIENT_NAME"
        const val EXTRA_RECIPIENT_ADDRESS = "RECIPIENT_ADDRESS"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        // Payment request extras (when paying someone's request)
        const val EXTRA_PAYMENT_QUOTE_JSON = "PAYMENT_QUOTE_JSON"
        const val EXTRA_PAYMENT_AMOUNT = "PAYMENT_AMOUNT"
        const val EXTRA_PAYMENT_TOKEN = "PAYMENT_TOKEN"
        const val EXTRA_IS_PAYMENT_REQUEST = "IS_PAYMENT_REQUEST"
    }

    private lateinit var backButton: View
    private lateinit var menuButton: View
    private lateinit var recipientName: TextView
    private lateinit var walletNameDropdown: View
    private lateinit var walletNameText: TextView
    private lateinit var walletAddressShort: TextView
    private lateinit var amountInput: EditText
    private lateinit var currencyIcon: ImageView
    private lateinit var expiryDropdown: View
    private lateinit var expiryText: TextView
    private lateinit var sendNowButton: View

    private var selectedToken = "SOL"
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

    // Payment request mode (paying someone's request)
    private var isPayingRequest = false
    private var paymentRequestQuote: NLx402Manager.PaymentQuote? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_send_money)

        keyManager = KeyManager.getInstance(this)
        solanaService = SolanaService(this)
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)

        // Check if we're paying a payment request
        isPayingRequest = intent.getBooleanExtra(EXTRA_IS_PAYMENT_REQUEST, false)

        // Get the token from the payment request BEFORE loading wallet
        val requestToken = intent.getStringExtra(EXTRA_PAYMENT_TOKEN)
        if (requestToken != null) {
            selectedToken = requestToken
        }

        initializeViews()
        setupClickListeners()
        loadRecipientInfo()
        loadWalletInfo()
        fetchSolPrice()

        // If paying a request, pre-fill the amount
        if (isPayingRequest) {
            loadPaymentRequestDetails()
        }
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)
        recipientName = findViewById(R.id.recipientName)
        walletNameDropdown = findViewById(R.id.walletNameDropdown)
        walletNameText = findViewById(R.id.walletNameText)
        walletAddressShort = findViewById(R.id.walletAddressShort)
        amountInput = findViewById(R.id.amountInput)
        currencyIcon = findViewById(R.id.currencyIcon)
        expiryDropdown = findViewById(R.id.expiryDropdown)
        expiryText = findViewById(R.id.expiryText)
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
            showWalletSelector()
        }

        expiryDropdown.setOnClickListener {
            showExpirySelector()
        }

        sendNowButton.setOnClickListener {
            sendMoney()
        }
    }

    private fun loadPaymentRequestDetails() {
        val quoteJson = intent.getStringExtra(EXTRA_PAYMENT_QUOTE_JSON)
        val amount = intent.getLongExtra(EXTRA_PAYMENT_AMOUNT, 0)
        val token = intent.getStringExtra(EXTRA_PAYMENT_TOKEN) ?: "SOL"

        if (quoteJson != null) {
            paymentRequestQuote = NLx402Manager.PaymentQuote.fromJson(quoteJson)

            // Pre-fill the amount (convert from smallest unit to decimal)
            val decimals = when (token.uppercase()) {
                "SOL" -> 9
                "ZEC" -> 8
                "USDC", "USDT" -> 6
                else -> 9
            }
            val divisor = Math.pow(10.0, decimals.toDouble())
            val humanAmount = amount.toDouble() / divisor

            amountInput.setText(String.format("%.4f", humanAmount))
            selectedToken = token
            currencyIcon.setImageResource(if (token == "ZEC") R.drawable.ic_zcash else R.drawable.ic_solana)

            // Disable editing when paying a request
            amountInput.isEnabled = false
            amountInput.alpha = 0.7f
            expiryDropdown.isEnabled = false
            expiryDropdown.alpha = 0.7f

            Log.d(TAG, "Loaded payment request: ${paymentRequestQuote?.formattedAmount}")
        }
    }

    private fun loadRecipientInfo() {
        val name = intent.getStringExtra(EXTRA_RECIPIENT_NAME) ?: "User"
        recipientName.text = name
    }

    private fun loadWalletInfo() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@SendMoneyActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet, sort by most recently used
                val availableWallets = allWallets
                    .filter { it.walletId != "main" }
                    .sortedByDescending { it.lastUsedAt }

                if (availableWallets.isNotEmpty()) {
                    val firstWallet = availableWallets.first()

                    // Only auto-detect token if not already set by payment request
                    if (!isPayingRequest) {
                        val isZcashWallet = (!firstWallet.zcashAddress.isNullOrEmpty() || !firstWallet.zcashUnifiedAddress.isNullOrEmpty()) && firstWallet.solanaAddress.isEmpty()
                        selectedToken = if (isZcashWallet) "ZEC" else "SOL"
                    }

                    currentWalletId = firstWallet.walletId
                    currentWalletName = firstWallet.name
                    currentWalletAddress = firstWallet.solanaAddress
                    currentZcashAddress = firstWallet.zcashAddress

                    val displayAddress = when (selectedToken) {
                        "ZEC" -> firstWallet.zcashAddress ?: ""
                        else -> firstWallet.solanaAddress
                    }

                    withContext(Dispatchers.Main) {
                        walletNameText.text = currentWalletName
                        walletAddressShort.text = formatAddressShort(displayAddress)
                        currencyIcon.setImageResource(if (selectedToken == "ZEC") R.drawable.ic_zcash else R.drawable.ic_solana)
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        walletNameText.text = "No wallet"
                        walletAddressShort.text = "Create a wallet first"

                        sendNowButton.isEnabled = false
                        sendNowButton.alpha = 0.5f

                        ThemedToast.show(this@SendMoneyActivity, "You need a $selectedToken wallet to send")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallet info", e)
                withContext(Dispatchers.Main) {
                    walletNameText.text = "Wallet"
                    walletAddressShort.text = "..."
                }
            }
        }
    }

    private fun loadWalletInfoForChain(chain: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@SendMoneyActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                val wallets = allWallets.filter { wallet ->
                    wallet.walletId != "main" && when (chain) {
                        "ZEC" -> !wallet.zcashAddress.isNullOrEmpty() || !wallet.zcashUnifiedAddress.isNullOrEmpty()
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
                        walletNameText.text = currentWalletName
                        walletAddressShort.text = formatAddressShort(displayAddress)
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        walletNameText.text = "No wallet"
                        walletAddressShort.text = "Set up $chain wallet"
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

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)
        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        val check15Min = view.findViewById<ImageView>(R.id.check15Min)
        val check1Hour = view.findViewById<ImageView>(R.id.check1Hour)
        val check6Hours = view.findViewById<ImageView>(R.id.check6Hours)
        val check24Hours = view.findViewById<ImageView>(R.id.check24Hours)
        val check48Hours = view.findViewById<ImageView>(R.id.check48Hours)
        val check7Days = view.findViewById<ImageView>(R.id.check7Days)

        fun updateChecks(selected: Long) {
            check15Min.visibility = if (selected == NLx402Manager.EXPIRY_15_MIN) View.VISIBLE else View.GONE
            check1Hour.visibility = if (selected == NLx402Manager.EXPIRY_1_HOUR) View.VISIBLE else View.GONE
            check6Hours.visibility = if (selected == NLx402Manager.EXPIRY_6_HOURS) View.VISIBLE else View.GONE
            check24Hours.visibility = if (selected == NLx402Manager.EXPIRY_24_HOURS) View.VISIBLE else View.GONE
            check48Hours.visibility = if (selected == NLx402Manager.EXPIRY_48_HOURS) View.VISIBLE else View.GONE
            check7Days.visibility = if (selected == NLx402Manager.EXPIRY_7_DAYS) View.VISIBLE else View.GONE
        }

        updateChecks(selectedExpirySecs)

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
                val database = SecureLegionDatabase.getInstance(this@SendMoneyActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                withContext(Dispatchers.Main) {
                    val bottomSheet = BottomSheetDialog(this@SendMoneyActivity)
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
                    val solanaChainBtn = view.findViewById<View>(R.id.solanaChainButton)
                    val zcashChainBtn = view.findViewById<View>(R.id.zcashChainButton)

                    // Track showing USD vs native per wallet item
                    val showingUsdMap = mutableMapOf<String, Boolean>()

                    fun populateWallets(chain: String) {
                        walletListContainer.removeAllViews()

                        val wallets = allWallets.filter { wallet ->
                            wallet.walletId != "main" && when (chain) {
                                "ZEC" -> !wallet.zcashAddress.isNullOrEmpty() || !wallet.zcashUnifiedAddress.isNullOrEmpty()
                                else -> wallet.solanaAddress.isNotEmpty()
                            }
                        }

                        // Update chain button backgrounds to show selection
                        solanaChainBtn.setBackgroundResource(
                            if (chain == "SOL") R.drawable.swap_button_bg else R.drawable.wallet_dropdown_bg
                        )
                        zcashChainBtn.setBackgroundResource(
                            if (chain == "ZEC") R.drawable.swap_button_bg else R.drawable.wallet_dropdown_bg
                        )

                        if (wallets.isEmpty()) {
                            val emptyText = TextView(this@SendMoneyActivity).apply {
                                text = "No $chain wallets found"
                                setTextColor(0xFF888888.toInt())
                                textSize = 14f
                                setPadding(0, 32, 0, 32)
                            }
                            walletListContainer.addView(emptyText)
                            return
                        }

                        for (wallet in wallets) {
                            val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                            val walletNameView = walletItemView.findViewById<TextView>(R.id.walletName)
                            val walletBalanceView = walletItemView.findViewById<TextView>(R.id.walletBalance)
                            val walletIcon = walletItemView.findViewById<ImageView>(R.id.walletIcon)
                            val toggleBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

                            // Set chain icon
                            walletIcon.setImageResource(
                                if (chain == "ZEC") R.drawable.ic_zcash else R.drawable.ic_solana
                            )

                            walletNameView.text = wallet.name
                            showingUsdMap[wallet.walletId] = true

                            // Load balance async
                            walletBalanceView.text = "Loading..."
                            lifecycleScope.launch {
                                try {
                                    val balance: Double
                                    val price: Double
                                    val symbol: String
                                    if (chain == "ZEC") {
                                        val zcashService = ZcashService.getInstance(this@SendMoneyActivity)
                                        val balResult = zcashService.getBalance()
                                        balance = balResult.getOrDefault(0.0)
                                        price = 0.0 // Will show native amount
                                        symbol = "ZEC"
                                    } else {
                                        val balResult = solanaService.getBalance(wallet.solanaAddress)
                                        balance = balResult.getOrDefault(0.0)
                                        price = currentSolPrice
                                        symbol = "SOL"
                                    }
                                    walletBalanceView.text = if (price > 0) {
                                        String.format("$%,.2f", balance * price)
                                    } else {
                                        String.format("%.4f %s", balance, symbol)
                                    }

                                    // Toggle button switches between USD and native
                                    toggleBtn.setOnClickListener {
                                        val isUsd = showingUsdMap[wallet.walletId] ?: true
                                        if (isUsd) {
                                            walletBalanceView.text = String.format("%.4f %s", balance, symbol)
                                        } else {
                                            if (price > 0) {
                                                walletBalanceView.text = String.format("$%,.2f", balance * price)
                                            }
                                        }
                                        showingUsdMap[wallet.walletId] = !isUsd
                                    }
                                } catch (e: Exception) {
                                    walletBalanceView.text = "Balance unavailable"
                                }
                            }

                            walletItemView.setOnClickListener {
                                selectedToken = chain
                                currencyIcon.setImageResource(if (selectedToken == "ZEC") R.drawable.ic_zcash else R.drawable.ic_solana)
                                switchToWallet(wallet)
                                bottomSheet.dismiss()
                            }

                            walletListContainer.addView(walletItemView)
                        }
                    }

                    // Wire up chain selector buttons
                    solanaChainBtn.setOnClickListener {
                        populateWallets("SOL")
                    }
                    zcashChainBtn.setOnClickListener {
                        populateWallets("ZEC")
                    }

                    // Populate with current selected chain
                    populateWallets(selectedToken)

                    bottomSheet.show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@SendMoneyActivity, "Failed to load wallets")
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
                val database = SecureLegionDatabase.getInstance(this@SendMoneyActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                val displayAddress = when (selectedToken) {
                    "ZEC" -> wallet.zcashAddress ?: ""
                    else -> wallet.solanaAddress
                }

                withContext(Dispatchers.Main) {
                    walletNameText.text = currentWalletName
                    walletAddressShort.text = formatAddressShort(displayAddress)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to switch wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@SendMoneyActivity, "Failed to switch wallet")
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

        showSendConfirmation(amount)
    }

    private fun showSendConfirmation(amount: Double) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_send_confirm, null)

        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        val desiredHeight = (screenHeight * 0.7).toInt()
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

        val confirmAmount = view.findViewById<TextView>(R.id.confirmSendAmount)
        val confirmAmountUSD = view.findViewById<TextView>(R.id.confirmSendAmountUSD)
        val confirmTo = view.findViewById<TextView>(R.id.confirmSendTo)
        val confirmFromWallet = view.findViewById<TextView>(R.id.confirmSendFromWallet)
        val confirmCurrency = view.findViewById<TextView>(R.id.confirmSendCurrency)
        val confirmNetworkFee = view.findViewById<TextView>(R.id.confirmSendNetworkFee)

        val formattedAmount = String.format("%.4f %s", amount, selectedToken)

        confirmAmount.text = formattedAmount
        confirmTo.text = recipientName.text
        confirmFromWallet.text = currentWalletName
        confirmCurrency.text = selectedToken

        // Fetch and display network fee
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val feeResult = when (selectedToken) {
                    "SOL" -> solanaService.getTransactionFee()
                    "ZEC" -> {
                        val zcashService = ZcashService.getInstance(this@SendMoneyActivity)
                        zcashService.getTransactionFee()
                    }
                    else -> Result.success(0.0)
                }

                val fee = feeResult.getOrDefault(0.0)
                withContext(Dispatchers.Main) {
                    confirmNetworkFee.text = "~${String.format("%.8f", fee)} $selectedToken"
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch network fee", e)
                withContext(Dispatchers.Main) {
                    confirmNetworkFee.text = "~0.00 $selectedToken"
                }
            }
        }

        val confirmButton = view.findViewById<View>(R.id.confirmSendButton)
        confirmButton.setOnClickListener {
            bottomSheet.dismiss()
            proceedWithSend(amount)
        }

        val cancelButton = view.findViewById<View>(R.id.cancelSendButton)
        cancelButton.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun proceedWithSend(amount: Double) {
        sendNowButton.isEnabled = false

        if (isPayingRequest && paymentRequestQuote != null) {
            // Paying someone's request - execute blockchain transaction
            executePayment(amount)
        } else {
            // Sending money - create a payment request for them to accept
            createPaymentRequest(amount)
        }
    }

    private fun createPaymentRequest(amount: Double) {
        ThemedToast.show(this, "Creating payment request...")

        lifecycleScope.launch {
            try {
                val recipientAddress = intent.getStringExtra(EXTRA_RECIPIENT_ADDRESS) ?: ""

                val myAddress = when (selectedToken) {
                    "ZEC" -> currentZcashAddress ?: keyManager.getZcashAddress() ?: run {
                        withContext(Dispatchers.Main) {
                            sendNowButton.isEnabled = true
                            ThemedToast.show(this@SendMoneyActivity, "Zcash wallet not set up")
                        }
                        return@launch
                    }
                    else -> if (currentWalletAddress.isNotEmpty()) currentWalletAddress else keyManager.getSolanaAddress()
                }

                // For "Send Money" offers, use empty recipient - recipient will provide their wallet when accepting
                // This distinguishes it from "Request Money" where sender puts their own wallet
                val quote = NLx402Manager.createQuoteFromAmount(
                    recipientAddress = "",  // Empty = sender will pay to recipient's chosen wallet
                    amount = BigDecimal(amount),
                    token = selectedToken,
                    description = "Payment to ${recipientName.text}",
                    senderHandle = null,
                    recipientHandle = intent.getStringExtra(EXTRA_RECIPIENT_NAME),
                    expirySecs = selectedExpirySecs
                )

                if (quote == null) {
                    withContext(Dispatchers.Main) {
                        sendNowButton.isEnabled = true
                        ThemedToast.show(this@SendMoneyActivity, "Failed to create payment request")
                    }
                    return@launch
                }

                Log.d(TAG, "Created send quote: ${quote.quoteId} for ${quote.formattedAmount}")

                if (contactId > 0) {
                    val messageService = MessageService(this@SendMoneyActivity)
                    val sendResult = messageService.sendPaymentRequest(contactId, quote)

                    if (sendResult.isSuccess) {
                        Log.i(TAG, "Payment request message sent successfully")
                    } else {
                        Log.e(TAG, "Failed to send payment request: ${sendResult.exceptionOrNull()?.message}")
                    }
                }

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@SendMoneyActivity, "Payment request sent!")
                    finish()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create payment request", e)
                withContext(Dispatchers.Main) {
                    sendNowButton.isEnabled = true
                    ThemedToast.show(this@SendMoneyActivity, "Error: ${e.message}")
                }
            }
        }
    }

    private fun executePayment(amount: Double) {
        ThemedToast.show(this, "Processing payment...")

        lifecycleScope.launch {
            try {
                val quote = paymentRequestQuote!!
                val recipientAddress = quote.recipient

                // Get my wallet address to send FROM
                val fromAddress = when (selectedToken) {
                    "ZEC" -> currentZcashAddress ?: keyManager.getZcashAddress() ?: run {
                        withContext(Dispatchers.Main) {
                            sendNowButton.isEnabled = true
                            ThemedToast.show(this@SendMoneyActivity, "Zcash wallet not set up")
                        }
                        return@launch
                    }
                    else -> if (currentWalletAddress.isNotEmpty()) currentWalletAddress else keyManager.getSolanaAddress()
                }

                Log.d(TAG, "Executing payment: $amount $selectedToken from $fromAddress to $recipientAddress")

                // Execute blockchain transaction based on token type
                val result = when (selectedToken) {
                    "ZEC" -> {
                        val zcashService = ZcashService.getInstance(this@SendMoneyActivity)
                        zcashService.sendTransaction(
                            toAddress = recipientAddress,
                            amountZEC = amount,
                            memo = quote.memo
                        )
                    }
                    else -> {
                        // SOL, USDC, USDT, etc.
                        solanaService.sendTransaction(
                            fromPublicKey = fromAddress,
                            toPublicKey = recipientAddress,
                            amountSOL = amount,
                            keyManager = keyManager,
                            walletId = currentWalletId.ifEmpty { "main" },
                            memo = quote.memo
                        )
                    }
                }

                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        val txSignature = result.getOrNull()!!
                        Log.i(TAG, "Payment successful: $txSignature")

                        // Send payment confirmation message to the requester
                        if (contactId > 0) {
                            sendPaymentConfirmation(quote, txSignature)
                        }

                        ThemedToast.show(this@SendMoneyActivity, "Payment sent successfully!")

                        // Open payment details
                        val detailsIntent = Intent(this@SendMoneyActivity, TransferDetailsActivity::class.java).apply {
                            putExtra(TransferDetailsActivity.EXTRA_RECIPIENT_NAME, recipientName.text.toString())
                            putExtra(TransferDetailsActivity.EXTRA_AMOUNT, amount)
                            putExtra(TransferDetailsActivity.EXTRA_CURRENCY, selectedToken)
                            putExtra(TransferDetailsActivity.EXTRA_FROM_WALLET, currentWalletName)
                            putExtra(TransferDetailsActivity.EXTRA_FROM_ADDRESS, fromAddress)
                            putExtra(TransferDetailsActivity.EXTRA_TO_WALLET, "Recipient")
                            putExtra(TransferDetailsActivity.EXTRA_TO_ADDRESS, recipientAddress)
                            putExtra(TransferDetailsActivity.EXTRA_TRANSACTION_NUMBER, quote.quoteId)
                            putExtra(TransferDetailsActivity.EXTRA_TX_SIGNATURE, txSignature)
                            putExtra(TransferDetailsActivity.EXTRA_SUCCESS, true)
                        }
                        startActivity(detailsIntent)
                        finish()
                    } else {
                        sendNowButton.isEnabled = true
                        val error = result.exceptionOrNull()?.message ?: "Unknown error"
                        Log.e(TAG, "Payment failed: $error")
                        ThemedToast.show(this@SendMoneyActivity, "Payment failed: $error")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Payment error", e)
                withContext(Dispatchers.Main) {
                    sendNowButton.isEnabled = true
                    ThemedToast.show(this@SendMoneyActivity, "Error: ${e.message}")
                }
            }
        }
    }

    private fun sendPaymentConfirmation(quote: NLx402Manager.PaymentQuote, txSignature: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val messageService = MessageService(this@SendMoneyActivity)
                val result = messageService.sendPaymentConfirmation(contactId, quote, txSignature)

                if (result.isSuccess) {
                    Log.i(TAG, "Payment confirmation sent")
                } else {
                    Log.e(TAG, "Failed to send payment confirmation: ${result.exceptionOrNull()?.message}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error sending payment confirmation", e)
            }
        }
    }
}

