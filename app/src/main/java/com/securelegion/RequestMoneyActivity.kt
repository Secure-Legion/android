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
import com.securelegion.services.ShadowWireService
import com.securelegion.services.SolanaService
import com.securelegion.services.ZcashService
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
    private lateinit var fromWalletDropdown: View
    private lateinit var fromWalletNameText: TextView
    private lateinit var fromAddressShort: TextView
    private lateinit var amountInput: EditText
    private lateinit var currencyIcon: ImageView
    private lateinit var requestNowButton: View
    private lateinit var sendNowButton: View
    private lateinit var toggleCurrency: ImageView
    private lateinit var paymentTypeIcon: ImageView
    private lateinit var paymentTypeText: TextView
    private lateinit var paymentTypeDropdown: View

    private var selectedToken = "SOL"  // SOL or ZEC
    private var showingUsd = false  // false = native token, true = USD
    // SOL: "private" or "anonymous" | ZEC: "transparent" or "shielded"
    private var selectedPaymentType = "private"
    private var currentSolPrice: Double = 0.0
    private var currentZecPrice: Double = 0.0

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
        currentWalletName = intent.getStringExtra("WALLET_NAME") ?: ""
        currentWalletAddress = intent.getStringExtra("WALLET_ADDRESS") ?: ""

        initializeViews()
        setupClickListeners()
        setupAmountInput()
        updatePaymentTypeUI()
        loadWalletInfo()
        fetchTokenPrices()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)
        fromWalletDropdown = findViewById(R.id.fromWalletDropdown)
        fromWalletNameText = findViewById(R.id.fromWalletNameText)
        fromAddressShort = findViewById(R.id.fromAddressShort)
        amountInput = findViewById(R.id.amountInput)
        currencyIcon = findViewById(R.id.currencyIcon)
        requestNowButton = findViewById(R.id.requestNowButton)
        sendNowButton = findViewById(R.id.sendNowButton)
        toggleCurrency = findViewById(R.id.toggleCurrency)
        paymentTypeIcon = findViewById(R.id.paymentTypeIcon)
        paymentTypeText = findViewById(R.id.paymentTypeText)
        paymentTypeDropdown = findViewById(R.id.paymentTypeDropdown)
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

        requestNowButton.setOnClickListener {
            requestMoney()
        }

        sendNowButton.setOnClickListener {
            sendMoney()
        }

        paymentTypeDropdown.setOnClickListener {
            showPaymentTypeSelector()
        }

        toggleCurrency.setOnClickListener {
            toggleAmountDisplay()
        }
    }

    private fun toggleAmountDisplay() {
        val currentText = amountInput.text.toString()
        val currentAmount = currentText.toDoubleOrNull() ?: 0.0
        val price = when (selectedToken) {
            "SOL" -> currentSolPrice
            "ZEC" -> currentZecPrice
            else -> 0.0
        }

        showingUsd = !showingUsd

        if (showingUsd) {
            // Convert native → USD
            if (currentAmount > 0 && price > 0) {
                amountInput.setText(String.format("%.2f", currentAmount * price))
            } else {
                amountInput.text.clear()
            }
            amountInput.hint = "$0.00"
        } else {
            // Convert USD → native
            if (currentAmount > 0 && price > 0) {
                amountInput.setText(String.format("%.4f", currentAmount / price))
            } else {
                amountInput.text.clear()
            }
            amountInput.hint = "0.00"
        }

        amountInput.setSelection(amountInput.text.length)
        updateCurrencyLabel()
    }

    private fun updateCurrencyLabel() {
        // No-op: icon already set by token selection
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
                        "ZEC" -> !wallet.zcashAddress.isNullOrEmpty() || !wallet.zcashUnifiedAddress.isNullOrEmpty()
                        else -> wallet.solanaAddress.isNotEmpty()
                    }
                }

                if (wallets.isNotEmpty()) {
                    val firstWallet = wallets.first()
                    currentWalletId = firstWallet.walletId
                    currentWalletName = firstWallet.name
                    currentWalletAddress = firstWallet.solanaAddress
                    currentZcashAddress = firstWallet.zcashAddress ?: firstWallet.zcashUnifiedAddress

                    val displayAddress = when (chain) {
                        "ZEC" -> firstWallet.zcashAddress ?: firstWallet.zcashUnifiedAddress ?: ""
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

    private fun updatePaymentTypeUI() {
        if (selectedToken == "ZEC") {
            paymentTypeIcon.setImageResource(R.drawable.ic_shield)
            paymentTypeIcon.clearColorFilter()
            // Map SOL types to ZEC equivalents
            if (selectedPaymentType == "normal" || selectedPaymentType == "private" || selectedPaymentType == "anonymous") {
                selectedPaymentType = "transparent"
            }
            paymentTypeText.text = if (selectedPaymentType == "shielded") "Shielded" else "Transparent"
        } else {
            paymentTypeIcon.setImageResource(R.drawable.ic_radr_logo)
            paymentTypeIcon.clearColorFilter()
            // Map ZEC types to SOL equivalents
            if (selectedPaymentType == "transparent" || selectedPaymentType == "shielded") {
                selectedPaymentType = "private"
            }
            paymentTypeText.text = when (selectedPaymentType) {
                "normal" -> "Normal"
                "anonymous" -> "Anonymous"
                else -> "Private"
            }
        }
    }

    private fun showPaymentTypeSelector() {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_payment_type, null)
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

        val option1Check = view.findViewById<ImageView>(R.id.option1Check)
        val option2Check = view.findViewById<ImageView>(R.id.option2Check)
        val option3Check = view.findViewById<ImageView>(R.id.option3Check)
        val option1Title = view.findViewById<TextView>(R.id.option1Title)
        val option2Title = view.findViewById<TextView>(R.id.option2Title)
        val option3Title = view.findViewById<TextView>(R.id.option3Title)
        val option1Desc = view.findViewById<TextView>(R.id.option1Desc)
        val option2Desc = view.findViewById<TextView>(R.id.option2Desc)
        val option3Desc = view.findViewById<TextView>(R.id.option3Desc)
        val option1Icon = view.findViewById<ImageView>(R.id.option1Icon)
        val option2Icon = view.findViewById<ImageView>(R.id.option2Icon)
        val option3Icon = view.findViewById<ImageView>(R.id.option3Icon)
        val option3View = view.findViewById<View>(R.id.paymentTypeOption3)

        if (selectedToken == "ZEC") {
            // Zcash: Transparent / Shielded (2 options)
            option1Icon.setImageResource(R.drawable.ic_shield)
            option2Icon.setImageResource(R.drawable.ic_shield)
            option1Title.text = "Transparent"
            option2Title.text = "Shielded"
            option1Desc.text = "Standard Zcash transaction"
            option2Desc.text = "Fully shielded Zcash transaction"
            option1Check.visibility = if (selectedPaymentType == "transparent") View.VISIBLE else View.GONE
            option2Check.visibility = if (selectedPaymentType == "shielded") View.VISIBLE else View.GONE
            option3View.visibility = View.GONE
        } else {
            // Solana: Normal / Private / Anonymous (3 options)
            option1Icon.setImageResource(R.drawable.ic_solana)
            option2Icon.setImageResource(R.drawable.ic_radr_logo)
            option3Icon.setImageResource(R.drawable.ic_radr_logo)
            option1Title.text = "Normal"
            option2Title.text = "Private"
            option3Title.text = "Anonymous"
            option1Desc.text = "Standard Solana transaction"
            option2Desc.text = "Powered by Radr · 0.5% fee"
            option3Desc.text = "Powered by Radr · 0.5% fee"
            option1Check.visibility = if (selectedPaymentType == "normal") View.VISIBLE else View.GONE
            option2Check.visibility = if (selectedPaymentType == "private") View.VISIBLE else View.GONE
            option3Check.visibility = if (selectedPaymentType == "anonymous") View.VISIBLE else View.GONE
            option3View.visibility = View.VISIBLE
        }

        view.findViewById<View>(R.id.paymentTypeOption1).setOnClickListener {
            selectedPaymentType = if (selectedToken == "ZEC") "transparent" else "normal"
            updatePaymentTypeUI()
            bottomSheet.dismiss()
        }

        view.findViewById<View>(R.id.paymentTypeOption2).setOnClickListener {
            selectedPaymentType = if (selectedToken == "ZEC") "shielded" else "private"
            updatePaymentTypeUI()
            bottomSheet.dismiss()
        }

        view.findViewById<View>(R.id.paymentTypeOption3).setOnClickListener {
            selectedPaymentType = "anonymous"
            updatePaymentTypeUI()
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

                withContext(Dispatchers.Main) {
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
                    val solanaChainBtn = view.findViewById<View>(R.id.solanaChainButton)
                    val zcashChainBtn = view.findViewById<View>(R.id.zcashChainButton)

                    // Track showing USD vs native per wallet item
                    val showingUsdMap = mutableMapOf<String, Boolean>()

                    // Helper to populate wallet list for a given chain
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
                            val emptyText = TextView(this@RequestMoneyActivity).apply {
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
                                        val zcashService = ZcashService.getInstance(this@RequestMoneyActivity)
                                        val balResult = zcashService.getBalance()
                                        balance = balResult.getOrDefault(0.0)
                                        price = currentZecPrice
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
                                    walletBalanceView.tag = balance // Store balance for toggle

                                    // Toggle button switches between USD and native
                                    toggleBtn.setOnClickListener { toggleView ->
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
                                // Update selected token to match the chain tab
                                selectedToken = chain
                                currencyIcon.setImageResource(if (selectedToken == "ZEC") R.drawable.ic_zcash else R.drawable.ic_solana)
                                updatePaymentTypeUI()
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
                currentZcashAddress = wallet.zcashAddress ?: wallet.zcashUnifiedAddress

                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@RequestMoneyActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                // Display appropriate address based on selected chain
                val displayAddress = when (selectedToken) {
                    "ZEC" -> wallet.zcashAddress ?: wallet.zcashUnifiedAddress ?: ""
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

    private fun loadWalletInfo() {
        // If wallet info was passed in intent, use it
        if (currentWalletAddress.isNotEmpty()) {
            fromWalletNameText.text = currentWalletName
            fromAddressShort.text = formatAddressShort(currentWalletAddress)
            return
        }

        // Set KeyManager address immediately as fallback while DB loads
        val fallbackAddress = keyManager.getSolanaAddress()
        currentWalletAddress = fallbackAddress
        fromWalletNameText.text = "Wallet"
        fromAddressShort.text = formatAddressShort(fallbackAddress)

        // Load most recently used wallet from database
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@RequestMoneyActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet, sort by last used (most recent first)
                val wallets = allWallets
                    .filter { it.walletId != "main" }
                    .sortedByDescending { it.lastUsedAt }

                if (wallets.isNotEmpty()) {
                    val firstWallet = wallets.first()
                    currentWalletId = firstWallet.walletId
                    currentWalletName = firstWallet.name
                    currentWalletAddress = firstWallet.solanaAddress
                    currentZcashAddress = firstWallet.zcashAddress ?: firstWallet.zcashUnifiedAddress

                    // Detect wallet type and sync currency selector
                    val isZcashWallet = (!firstWallet.zcashAddress.isNullOrEmpty() || !firstWallet.zcashUnifiedAddress.isNullOrEmpty()) && firstWallet.solanaAddress.isEmpty()
                    selectedToken = if (isZcashWallet) "ZEC" else "SOL"

                    val displayAddress = if (isZcashWallet) {
                        firstWallet.zcashAddress ?: firstWallet.zcashUnifiedAddress ?: ""
                    } else {
                        firstWallet.solanaAddress
                    }

                    // Only update if we got a real address
                    val finalAddress = displayAddress.ifEmpty { fallbackAddress }
                    val finalName = currentWalletName.ifEmpty { "Wallet" }

                    withContext(Dispatchers.Main) {
                        fromWalletNameText.text = finalName
                        fromAddressShort.text = formatAddressShort(finalAddress)
                        currencyIcon.setImageResource(if (selectedToken == "ZEC") R.drawable.ic_zcash else R.drawable.ic_solana)
                        updatePaymentTypeUI()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallet info", e)
            }
        }
    }

    private fun fetchTokenPrices() {
        lifecycleScope.launch {
            try {
                // Fetch SOL price
                val solResult = solanaService.getSolPrice()
                if (solResult.isSuccess) {
                    currentSolPrice = solResult.getOrNull() ?: 0.0
                    Log.d(TAG, "SOL price: $currentSolPrice")
                }

                // Fetch ZEC price
                val zcashService = ZcashService.getInstance(this@RequestMoneyActivity)
                val zecResult = zcashService.getZecPrice()
                if (zecResult.isSuccess) {
                    currentZecPrice = zecResult.getOrNull() ?: 0.0
                    Log.d(TAG, "ZEC price: $currentZecPrice")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch token prices", e)
            }
        }
    }

    private fun setupAmountInput() {
        // Amount input is now direct — toggle button switches between USD and native
    }

    private fun formatAddressShort(address: String): String {
        return if (address.length > 20) {
            "${address.take(10)}...${address.takeLast(8)}"
        } else {
            address
        }
    }


    private fun getNativeAmount(): Double? {
        val amountText = amountInput.text.toString().replace("$", "").replace(",", "")
        val amount = amountText.toDoubleOrNull() ?: return null
        if (amount <= 0) return null

        return if (showingUsd) {
            val price = when (selectedToken) {
                "SOL" -> currentSolPrice
                "ZEC" -> currentZecPrice
                else -> 0.0
            }
            if (price > 0) amount / price else null
        } else {
            amount
        }
    }

    private fun requestMoney() {
        val amount = getNativeAmount()

        if (amount == null) {
            ThemedToast.show(this, "Please enter a valid amount")
            return
        }

        // Show confirmation dialog
        showRequestConfirmation(amount)
    }

    private fun sendMoney() {
        val amount = getNativeAmount()

        if (amount == null) {
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

        // Populate confirmation details
        val confirmSendAmount = view.findViewById<TextView>(R.id.confirmSendAmount)
        val confirmSendAmountUSD = view.findViewById<TextView>(R.id.confirmSendAmountUSD)
        val confirmSendTo = view.findViewById<TextView>(R.id.confirmSendTo)
        val confirmSendFromWallet = view.findViewById<TextView>(R.id.confirmSendFromWallet)
        val confirmSendCurrency = view.findViewById<TextView>(R.id.confirmSendCurrency)
        val confirmSendPaymentType = view.findViewById<TextView>(R.id.confirmSendPaymentType)
        val confirmSendNetworkFee = view.findViewById<TextView>(R.id.confirmSendNetworkFee)

        val formattedAmount = String.format("%.4f %s", amount, selectedToken)
        confirmSendAmount.text = formattedAmount

        // USD equivalent
        val price = when (selectedToken) {
            "SOL" -> currentSolPrice
            "ZEC" -> currentZecPrice
            else -> 0.0
        }
        if (price > 0) {
            confirmSendAmountUSD.text = String.format("≈ $%,.2f USD", amount * price)
            confirmSendAmountUSD.visibility = View.VISIBLE
        } else {
            confirmSendAmountUSD.visibility = View.GONE
        }

        val recipientAddress = intent.getStringExtra(EXTRA_RECIPIENT_ADDRESS) ?: ""
        confirmSendTo.text = formatAddressShort(recipientAddress)
        confirmSendFromWallet.text = currentWalletName
        confirmSendCurrency.text = if (selectedToken == "ZEC") "Zcash" else "Solana"

        // Payment type
        confirmSendPaymentType.text = when (selectedPaymentType) {
            "normal" -> "Normal"
            "private" -> "Private"
            "anonymous" -> "Anonymous"
            "transparent" -> "Transparent"
            "shielded" -> "Shielded"
            else -> selectedPaymentType.replaceFirstChar { it.uppercase() }
        }

        // Network fee — add 0.5% Radr fee for private/anonymous on SOL
        val isPrivacyFee = selectedPaymentType == "private" || selectedPaymentType == "anonymous"
        if (selectedToken == "ZEC") {
            confirmSendNetworkFee.text = "~0.0001 ZEC"
        } else if (isPrivacyFee) {
            val radrFee = amount * 0.005
            confirmSendNetworkFee.text = String.format("~%.6f SOL + %.4f SOL (0.5%%)", 0.000005, radrFee)
        } else {
            confirmSendNetworkFee.text = "~0.000005 SOL"
        }

        // Confirm button
        view.findViewById<View>(R.id.confirmSendButton).setOnClickListener {
            bottomSheet.dismiss()
            proceedWithSend(amount)
        }

        // Cancel button
        view.findViewById<View>(R.id.cancelSendButton).setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun proceedWithSend(amount: Double) {
        sendNowButton.isEnabled = false
        ThemedToast.show(this, "Sending payment...")

        lifecycleScope.launch {
            try {
                val recipientAddress = intent.getStringExtra(EXTRA_RECIPIENT_ADDRESS) ?: ""
                if (recipientAddress.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        sendNowButton.isEnabled = true
                        ThemedToast.show(this@RequestMoneyActivity, "No recipient address")
                    }
                    return@launch
                }

                val myAddress = when (selectedToken) {
                    "ZEC" -> currentZcashAddress ?: keyManager.getZcashAddress() ?: run {
                        withContext(Dispatchers.Main) {
                            sendNowButton.isEnabled = true
                            ThemedToast.show(this@RequestMoneyActivity, "Zcash wallet not set up")
                        }
                        return@launch
                    }
                    else -> currentWalletAddress.ifEmpty { keyManager.getSolanaAddress() }
                }

                val txSignature: String
                when {
                    selectedToken == "ZEC" -> {
                        val zcashService = ZcashService.getInstance(this@RequestMoneyActivity)
                        val result = zcashService.sendTransaction(recipientAddress, amount)
                        if (result.isFailure) {
                            withContext(Dispatchers.Main) {
                                sendNowButton.isEnabled = true
                                ThemedToast.show(this@RequestMoneyActivity, "Failed to send: ${result.exceptionOrNull()?.message}")
                            }
                            return@launch
                        }
                        txSignature = result.getOrNull() ?: "unknown"
                    }
                    selectedPaymentType == "private" -> {
                        // ShadowWire internal transfer (hidden amount + hidden sender)
                        val shadowWire = ShadowWireService(this@RequestMoneyActivity, currentWalletId.ifEmpty { "main" })
                        val amountLamports = (amount * 1_000_000_000L).toLong()
                        val result = shadowWire.internalTransfer(recipientAddress, amountLamports)
                        if (result.isFailure) {
                            withContext(Dispatchers.Main) {
                                sendNowButton.isEnabled = true
                                ThemedToast.show(this@RequestMoneyActivity, "Private send failed: ${result.exceptionOrNull()?.message}")
                            }
                            return@launch
                        }
                        txSignature = result.getOrNull()?.txSignature ?: "unknown"
                    }
                    selectedPaymentType == "anonymous" -> {
                        // ShadowWire external transfer (hidden sender, visible amount)
                        val shadowWire = ShadowWireService(this@RequestMoneyActivity, currentWalletId.ifEmpty { "main" })
                        val amountLamports = (amount * 1_000_000_000L).toLong()
                        val result = shadowWire.externalTransfer(recipientAddress, amountLamports)
                        if (result.isFailure) {
                            withContext(Dispatchers.Main) {
                                sendNowButton.isEnabled = true
                                ThemedToast.show(this@RequestMoneyActivity, "Anonymous send failed: ${result.exceptionOrNull()?.message}")
                            }
                            return@launch
                        }
                        txSignature = result.getOrNull()?.txSignature ?: "unknown"
                    }
                    else -> {
                        // Normal Solana transfer
                        val result = solanaService.sendTransaction(myAddress, recipientAddress, amount, keyManager, currentWalletId)
                        if (result.isFailure) {
                            withContext(Dispatchers.Main) {
                                sendNowButton.isEnabled = true
                                ThemedToast.show(this@RequestMoneyActivity, "Failed to send: ${result.exceptionOrNull()?.message}")
                            }
                            return@launch
                        }
                        txSignature = result.getOrNull() ?: "unknown"
                    }
                }

                Log.i(TAG, "Send successful: $txSignature (type: $selectedPaymentType)")

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@RequestMoneyActivity, "Payment sent successfully")
                    finish()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Send error", e)
                withContext(Dispatchers.Main) {
                    sendNowButton.isEnabled = true
                    ThemedToast.show(this@RequestMoneyActivity, "Error: ${e.message}")
                }
            }
        }
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
        val confirmRequestRecipient = view.findViewById<TextView>(R.id.confirmRequestRecipient)
        val confirmRequestToWallet = view.findViewById<TextView>(R.id.confirmRequestToWallet)
        val confirmRequestCurrency = view.findViewById<TextView>(R.id.confirmRequestCurrency)
        val confirmRequestExpiry = view.findViewById<TextView>(R.id.confirmRequestExpiry)

        // Set values using the selected token
        val formattedAmount = String.format("%.4f %s", amount, selectedToken)

        val displayName = intent.getStringExtra(EXTRA_RECIPIENT_NAME) ?: "User"
        confirmRequestAmount.text = formattedAmount
        confirmRequestRecipient.text = displayName
        confirmRequestToWallet.text = currentWalletName
        confirmRequestCurrency.text = selectedToken
        confirmRequestExpiry.text = when (selectedPaymentType) {
            "normal" -> "Normal"
            "private" -> "Private"
            "anonymous" -> "Anonymous"
            "transparent" -> "Transparent"
            "shielded" -> "Shielded"
            else -> selectedPaymentType.replaceFirstChar { it.uppercase() }
        }

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
                    expirySecs = 0L
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
                val timeFormat = SimpleDateFormat("hh:mm a", Locale.getDefault())
                val time = timeFormat.format(currentTime.time)

                val dateFormat = SimpleDateFormat("dd MMM, yyyy", Locale.getDefault())
                val date = dateFormat.format(currentTime.time)

                withContext(Dispatchers.Main) {
                    requestNowButton.isEnabled = true
                    showRequestDetailsBottomSheet(amount, quote.quoteId, time, date)
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

    private fun showRequestDetailsBottomSheet(amount: Double, requestId: String, time: String, date: String) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_request_details, null)

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

        val detailsAmount = view.findViewById<TextView>(R.id.detailsAmount)
        val detailsCryptoAmount = view.findViewById<TextView>(R.id.detailsCryptoAmount)
        val detailsUsdValue = view.findViewById<TextView>(R.id.detailsUsdValue)
        val detailsPaymentType = view.findViewById<TextView>(R.id.detailsPaymentType)
        val detailsNetworkFee = view.findViewById<TextView>(R.id.detailsNetworkFee)
        val detailsRequestId = view.findViewById<TextView>(R.id.detailsRequestId)
        val detailsTime = view.findViewById<TextView>(R.id.detailsTime)
        val detailsDate = view.findViewById<TextView>(R.id.detailsDate)

        // Crypto amount
        val formattedCrypto = String.format("%.4f %s", amount, selectedToken)
        detailsCryptoAmount.text = formattedCrypto

        // USD value from cached price
        val price = when (selectedToken) {
            "SOL" -> currentSolPrice
            "ZEC" -> currentZecPrice
            else -> 0.0
        }
        if (price > 0) {
            val usdValue = amount * price
            detailsAmount.text = String.format("$%,.2f", usdValue)
            detailsUsdValue.text = String.format("$%,.2f", usdValue)
        } else {
            detailsAmount.text = formattedCrypto
            detailsUsdValue.text = "Price unavailable"
        }

        // Payment type
        detailsPaymentType.text = when (selectedPaymentType) {
            "normal" -> "Normal"
            "private" -> "Private"
            "anonymous" -> "Anonymous"
            "transparent" -> "Transparent"
            "shielded" -> "Shielded"
            else -> selectedPaymentType.replaceFirstChar { it.uppercase() }
        }

        // Network fee
        val isPrivacyFee = selectedPaymentType == "private" || selectedPaymentType == "anonymous"
        if (selectedToken == "ZEC") {
            detailsNetworkFee.text = "~0.0001 ZEC"
        } else if (isPrivacyFee) {
            val radrFee = amount * 0.005
            detailsNetworkFee.text = String.format("~%.6f SOL + %.4f SOL (0.5%%)", 0.000005, radrFee)
        } else {
            detailsNetworkFee.text = "~0.000005 SOL"
        }

        detailsRequestId.text = requestId
        detailsTime.text = time
        detailsDate.text = date

        // Share button
        view.findViewById<View>(R.id.detailsShareButton).setOnClickListener {
            val details = """
                Request Details

                Amount: $formattedCrypto
                USD Value: ${detailsUsdValue.text}
                Payment Type: ${detailsPaymentType.text}
                Request ID: $requestId
                Date: $date $time
            """.trimIndent()

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, details)
            }
            startActivity(Intent.createChooser(shareIntent, "Share Request Details"))
        }

        // Done button
        view.findViewById<View>(R.id.detailsDoneButton).setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }
}
