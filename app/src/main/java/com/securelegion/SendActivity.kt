package com.securelegion

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.text.Editable
import android.text.TextWatcher
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.LinearLayout
import android.widget.ProgressBar
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.services.SolanaService
import com.securelegion.services.ZcashService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet

class SendActivity : BaseActivity() {
    private var currentWalletId: String = "main"
    private var currentWalletName: String = "Wallet 1"
    private var currentWalletAddress: String = ""
    private var selectedCurrency = "SOL" // Default to Solana
    private var currentTokenPrice: Double = 0.0 // Cached price for live conversion
    private var showingUSD = false // Track if displaying USD or token
    private var availableBalance: Double = 0.0 // Track available balance for validation

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_send)

        // Get wallet info from intent
        currentWalletId = intent.getStringExtra("WALLET_ID") ?: "main"
        currentWalletName = intent.getStringExtra("WALLET_NAME") ?: "Wallet 1"
        currentWalletAddress = intent.getStringExtra("WALLET_ADDRESS") ?: ""

        // Get token info from intent (if provided by token selector)
        val tokenSymbol = intent.getStringExtra("TOKEN_SYMBOL")
        val tokenName = intent.getStringExtra("TOKEN_NAME")

        // Use token symbol from intent, or detect from address as fallback
        selectedCurrency = tokenSymbol ?: if (currentWalletAddress.startsWith("t1") ||
                               currentWalletAddress.startsWith("u1") ||
                               currentWalletAddress.startsWith("utest")) {
            "ZEC"
        } else {
            "SOL"
        }

        Log.d("SendActivity", "Sending from wallet: $currentWalletName ($currentWalletAddress), Token: $selectedCurrency (${tokenName ?: "auto-detected"})")

        // setupCurrencySelector() // Removed - no currency selector in new layout
        setupQRScanner()
        // setupWalletSelector() // Removed - wallet already selected from token selector
        // setupNumberPad() // Removed - using system keyboard
        // setupAmountInput() // Removed - using system keyboard
        selectCurrency(selectedCurrency) // Set initial currency UI

        // Load last known price from cache immediately
        loadCachedPrice()

        // Only load current wallet if no wallet was passed via intent
        if (currentWalletAddress.isEmpty()) {
            loadCurrentWallet()
        } else {
            // Wallet info already provided via intent, just load the UI
            loadWalletInfo()
        }

        // Load fresh balance and price in background
        loadWalletBalance()
        // setupPriceRefresh() // Removed - no toggle currency button
        // setupBottomNavigation() // Removed - no bottom nav in new layout

        // Auto-focus amount input to show keyboard
        val balanceAmountInput = findViewById<EditText>(R.id.balanceAmount)
        val recipientAddressInput = findViewById<EditText>(R.id.recipientAddressInput)
        val toggleCurrencyButton = findViewById<View>(R.id.toggleCurrencyDisplay)
        val backButton = findViewById<View>(R.id.backButton)
        val nextButton = findViewById<View>(R.id.nextButton)

        balanceAmountInput?.requestFocus()

        // Show keyboard automatically
        balanceAmountInput?.postDelayed({
            val imm = getSystemService(INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager
            imm?.showSoftInput(balanceAmountInput, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
        }, 200)

        // Toggle currency display (USD <-> Token)
        toggleCurrencyButton?.setOnClickListener {
            toggleCurrencyDisplay()
        }

        // Back button
        backButton?.setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Next button - shows send confirmation
        nextButton?.setOnClickListener {
            val recipientAddress = recipientAddressInput?.text.toString() ?: ""
            val amountText = balanceAmountInput?.text.toString() ?: "0"

            // Parse the amount
            var amount = amountText.toDoubleOrNull() ?: 0.0

            // If showing USD, convert back to token amount for the transaction
            if (showingUSD && currentTokenPrice > 0) {
                amount = amount / currentTokenPrice
            }

            if (recipientAddress.isEmpty()) {
                ThemedToast.show(this, "Please enter recipient address")
                return@setOnClickListener
            }

            if (amount <= 0) {
                ThemedToast.show(this, "Please enter an amount")
                return@setOnClickListener
            }

            // Check if balance is still loading (availableBalance hasn't been set yet)
            if (availableBalance == 0.0) {
                ThemedToast.show(this, "Loading balance... Please wait")
                // Trigger a refresh
                loadWalletBalance()
                return@setOnClickListener
            }

            // Check for Solana rent-exempt reserve
            if (selectedCurrency == "SOL") {
                val rentReserve = 0.00089088 // Solana rent-exempt minimum
                val remainingBalance = availableBalance - amount

                if (remainingBalance < rentReserve) {
                    val maxSendable = availableBalance - rentReserve - 0.000005 // minus rent and fee
                    ThemedToast.show(
                        this,
                        "Cannot send that much. Solana accounts must keep ~0.00089 SOL. Max sendable: ${formatBalance(maxSendable)} SOL"
                    )
                    return@setOnClickListener
                }
            }

            // Check if amount exceeds available balance
            if (amount > availableBalance) {
                ThemedToast.show(this, "Insufficient funds. Available: ${formatBalance(availableBalance)} $selectedCurrency")
                return@setOnClickListener
            }

            // Show confirmation dialog before sending
            showSendConfirmation(recipientAddress, amount)
        }

        // Max button - fills in maximum available balance minus network fee and rent
        findViewById<View>(R.id.maxButton)?.setOnClickListener {
            // Subtract estimated network fee and rent-exempt reserve from available balance
            val (estimatedFee, rentReserve) = when (selectedCurrency) {
                "SOL" -> Pair(0.000005, 0.00089088)  // Solana: network fee + rent-exempt minimum
                "ZEC" -> Pair(0.0001, 0.0)           // Zcash: network fee only
                else -> Pair(0.0, 0.0)
            }

            val maxSendable = (availableBalance - estimatedFee - rentReserve).coerceAtLeast(0.0)

            if (maxSendable <= 0) {
                if (selectedCurrency == "SOL") {
                    ThemedToast.show(this, "Insufficient balance. Solana accounts must maintain ~0.00089 SOL rent-exempt reserve")
                } else {
                    ThemedToast.show(this, "Insufficient balance to cover network fees")
                }
                return@setOnClickListener
            }

            findViewById<EditText>(R.id.balanceAmount)?.setText(String.format("%.6f", maxSendable))
        }

        // Click on available balance to refresh
        findViewById<TextView>(R.id.availableBalance)?.setOnClickListener {
            ThemedToast.show(this, "Refreshing balance...")
            loadWalletBalance()
        }
    }

    override fun onResume() {
        super.onResume()
        // Auto-refresh balance when returning to this page
        loadWalletBalance()
    }

    private fun setupCurrencySelector() {
        val currencyDropdown = findViewById<View>(R.id.currencyDropdown)

        currencyDropdown.setOnClickListener {
            // Toggle between SOL and ZEC
            if (selectedCurrency == "SOL") {
                selectCurrency("ZEC")
            } else {
                selectCurrency("SOL")
            }
        }
    }

    private fun setupQRScanner() {
        findViewById<View>(R.id.scanQRButton).setOnClickListener {
            startQRScanner()
        }
    }

    private fun startQRScanner() {
        val intent = Intent(this, QRScannerActivity::class.java)
        startActivityForResult(intent, QR_SCANNER_REQUEST_CODE)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == QR_SCANNER_REQUEST_CODE && resultCode == RESULT_OK) {
            val scannedAddress = data?.getStringExtra("SCANNED_ADDRESS")
            if (scannedAddress != null) {
                findViewById<EditText>(R.id.recipientAddressInput).setText(scannedAddress)
                ThemedToast.show(this, "Address scanned successfully")
            }
        }
    }

    private fun toggleCurrencyDisplay() {
        val balanceAmountInput = findViewById<EditText>(R.id.balanceAmount)
        val currencySymbol = findViewById<TextView>(R.id.currencySymbol)
        val currentText = balanceAmountInput?.text.toString()

        Log.d("SendActivity", "Toggle currency - currentText: $currentText, currentTokenPrice: $currentTokenPrice, showingUSD: $showingUSD")

        // If no price available, just toggle the symbol but don't convert
        if (currentTokenPrice <= 0) {
            showingUSD = !showingUSD
            currencySymbol?.text = if (showingUSD) "USD" else selectedCurrency
            Log.d("SendActivity", "No price available, just toggled symbol to: ${currencySymbol?.text}")
            return
        }

        // If no amount entered, just toggle the symbol
        if (currentText.isEmpty()) {
            showingUSD = !showingUSD
            currencySymbol?.text = if (showingUSD) "USD" else selectedCurrency
            Log.d("SendActivity", "No amount entered, just toggled symbol to: ${currencySymbol?.text}")
            return
        }

        val currentAmount = currentText.toDoubleOrNull() ?: 0.0

        // If amount is 0, just toggle the symbol
        if (currentAmount <= 0) {
            showingUSD = !showingUSD
            currencySymbol?.text = if (showingUSD) "USD" else selectedCurrency
            Log.d("SendActivity", "Amount is 0, just toggled symbol to: ${currencySymbol?.text}")
            return
        }

        if (showingUSD) {
            // Convert from USD back to token
            val tokenAmount = currentAmount / currentTokenPrice
            Log.d("SendActivity", "Converting USD $currentAmount to token: $tokenAmount (price: $currentTokenPrice)")
            balanceAmountInput?.setText(String.format("%.6f", tokenAmount))
            currencySymbol?.text = selectedCurrency
            showingUSD = false
        } else {
            // Convert from token to USD
            val usdAmount = currentAmount * currentTokenPrice
            Log.d("SendActivity", "Converting token $currentAmount to USD: $usdAmount (price: $currentTokenPrice)")
            balanceAmountInput?.setText(String.format("%.2f", usdAmount))
            currencySymbol?.text = "USD"
            showingUSD = true
        }
    }

    companion object {
        private const val QR_SCANNER_REQUEST_CODE = 100

        private fun formatBalance(balance: Double): String {
            return when {
                balance >= 1.0 -> String.format("%.2f", balance)
                balance >= 0.01 -> String.format("%.4f", balance).trimEnd('0').trimEnd('.')
                balance > 0.0 -> String.format("%.6f", balance).trimEnd('0').trimEnd('.')
                else -> "0"
            }
        }
    }

    private fun setupWalletSelector() {
        val walletNameDropdown = findViewById<View>(R.id.walletNameDropdown)

        walletNameDropdown?.setOnClickListener {
            showWalletSelector()
        }
    }

    private fun setupAmountInput() {
        val amountInput = findViewById<EditText>(R.id.amountInput)
        val amountUsdValue = findViewById<TextView>(R.id.amountUsdValue)

        amountInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val amountText = s?.toString() ?: ""
                val amount = amountText.toDoubleOrNull() ?: 0.0

                if (currentTokenPrice > 0 && amount > 0) {
                    val usdValue = amount * currentTokenPrice
                    amountUsdValue.text = String.format("≈ $%,.2f USD", usdValue)
                } else {
                    amountUsdValue.text = "≈ $0.00 USD"
                }
            }
        })

        // Click on USD value to refresh price
        amountUsdValue.setOnClickListener {
            ThemedToast.show(this, "Refreshing price...")
            loadWalletBalance()
        }
    }


    private fun updateAmountUsdValue() {
        val amountInput = findViewById<EditText>(R.id.amountInput)
        val amountUsdValue = findViewById<TextView>(R.id.amountUsdValue)
        val amountText = amountInput.text?.toString() ?: ""
        val amount = amountText.toDoubleOrNull() ?: 0.0

        if (currentTokenPrice > 0 && amount > 0) {
            val usdValue = amount * currentTokenPrice
            amountUsdValue.text = String.format("≈ $%,.2f USD", usdValue)
        } else {
            amountUsdValue.text = "≈ $0.00 USD"
        }
    }

    private fun setupPriceRefresh() {
        // Toggle currency display when swap arrows are clicked
        findViewById<View>(R.id.toggleCurrency)?.setOnClickListener {
            // This will toggle between USD and token display
            loadWalletBalance()
        }
    }

    private fun loadCurrentWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@SendActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@SendActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    if (wallets.isNotEmpty()) {
                        val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                        if (currentWallet != null) {
                            currentWalletId = currentWallet.walletId
                            currentWalletName = currentWallet.name

                            // Get address based on wallet type
                            currentWalletAddress = if (currentWallet.zcashAddress != null) {
                                selectedCurrency = "ZEC"
                                currentWallet.zcashAddress ?: ""
                            } else {
                                selectedCurrency = "SOL"
                                currentWallet.solanaAddress
                            }

                            loadWalletInfo()
                            selectCurrency(selectedCurrency)
                        }
                    } else {
                        currentWalletName = "----"
                        currentWalletAddress = ""
                        loadWalletInfo()
                    }
                }
            } catch (e: Exception) {
                Log.e("SendActivity", "Failed to load current wallet", e)
            }
        }
    }

    private fun loadWalletInfo() {
        // Wallet info is already loaded from token selector - no UI to update
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@SendActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@SendActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@SendActivity, "No wallets found")
                        return@withContext
                    }

                    // Create bottom sheet dialog
                    val bottomSheet = BottomSheetDialog(this@SendActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)

                    // Set minimum height on the view itself
                    val displayMetrics = resources.displayMetrics
                    val screenHeight = displayMetrics.heightPixels
                    val desiredHeight = (screenHeight * 0.6).toInt()
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

                    // Get container for wallet list
                    val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)

                    // Add each wallet to the list
                    for (wallet in wallets) {
                        val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                        val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                        val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
                        val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

                        walletName.text = wallet.name
                        walletBalance.text = "Loading..."

                        // Load balance for this wallet
                        lifecycleScope.launch(Dispatchers.IO) {
                            try {
                                // Determine wallet type and load appropriate balance
                                val isZcashWallet = !wallet.zcashAddress.isNullOrEmpty() || !wallet.zcashUnifiedAddress.isNullOrEmpty()

                                if (isZcashWallet) {
                                    val zcashService = ZcashService.getInstance(this@SendActivity)
                                    val balanceResult = zcashService.getBalance()

                                    withContext(Dispatchers.Main) {
                                        if (balanceResult.isSuccess) {
                                            val balance = balanceResult.getOrNull() ?: 0.0
                                            walletBalance.text = "${formatBalance(balance)} ZEC"
                                        } else {
                                            walletBalance.text = "0 ZEC"
                                        }
                                    }
                                } else {
                                    val solanaService = SolanaService(this@SendActivity)
                                    val balanceResult = solanaService.getBalance(wallet.solanaAddress)

                                    withContext(Dispatchers.Main) {
                                        if (balanceResult.isSuccess) {
                                            val balance = balanceResult.getOrNull() ?: 0.0
                                            walletBalance.text = "${formatBalance(balance)} SOL"
                                        } else {
                                            walletBalance.text = "0 SOL"
                                        }
                                    }
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    walletBalance.text = "Error"
                                }
                            }
                        }

                        // Click on wallet item to switch
                        walletItemView.setOnClickListener {
                            switchToWallet(wallet)
                            bottomSheet.dismiss()
                        }

                        // Click on settings button
                        settingsBtn.setOnClickListener {
                            val intent = Intent(this@SendActivity, WalletSettingsActivity::class.java)
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
                Log.e("SendActivity", "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@SendActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun switchToWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("SendActivity", "Switching to wallet: ${wallet.name}")

                // Update wallet info
                currentWalletId = wallet.walletId
                currentWalletName = wallet.name

                // Get wallet address based on type
                currentWalletAddress = if (wallet.zcashAddress != null) {
                    selectedCurrency = "ZEC"
                    wallet.zcashAddress ?: ""
                } else {
                    selectedCurrency = "SOL"
                    wallet.solanaAddress
                }

                // Update last used timestamp
                val keyManager = KeyManager.getInstance(this@SendActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@SendActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                withContext(Dispatchers.Main) {
                    // Update wallet info display
                    loadWalletInfo()
                    selectCurrency(selectedCurrency)

                    // Reload balance for the new wallet
                    loadWalletBalance()
                }
            } catch (e: Exception) {
                Log.e("SendActivity", "Failed to switch wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@SendActivity, "Failed to switch wallet")
                }
            }
        }
    }

    private fun showSendConfirmation(recipientAddress: String, amount: Double) {
        // Create bottom sheet dialog
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_send_confirm, null)

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
        val confirmAmount = view.findViewById<TextView>(R.id.confirmSendAmount)
        val confirmAmountUSD = view.findViewById<TextView>(R.id.confirmSendAmountUSD)
        val confirmFromWallet = view.findViewById<TextView>(R.id.confirmSendFromWallet)
        val confirmToAddress = view.findViewById<TextView>(R.id.confirmSendTo)
        val confirmCurrency = view.findViewById<TextView>(R.id.confirmSendCurrency)

        // Calculate USD value (always use cached or current price)
        val usdText = if (currentTokenPrice > 0) {
            val usdValue = amount * currentTokenPrice
            "≈ $${String.format("%.2f", usdValue)} USD"
        } else {
            "≈ $0.00 USD"
        }

        Log.d("SendActivity", "Confirmation - amount: $amount, price: $currentTokenPrice, USD: $usdText")

        // Set values
        confirmAmount?.text = "$amount $selectedCurrency"
        confirmAmountUSD?.text = usdText
        confirmFromWallet?.text = currentWalletName
        confirmToAddress?.text = "${recipientAddress.take(6)}...${recipientAddress.takeLast(6)}"

        // Show network name instead of just currency symbol
        val networkName = when (selectedCurrency) {
            "SOL" -> "Solana"
            "ZEC" -> "Zcash"
            else -> selectedCurrency
        }
        confirmCurrency?.text = networkName

        // Confirm button
        val confirmButton = view.findViewById<View>(R.id.confirmSendButton)
        confirmButton.setOnClickListener {
            bottomSheet.dismiss()

            // Send transaction based on selected currency
            when (selectedCurrency) {
                "SOL" -> sendSolanaTransaction(recipientAddress, amount)
                "ZEC" -> sendZcashTransaction(recipientAddress, amount)
            }
        }

        // Cancel button
        val cancelButton = view.findViewById<View>(R.id.cancelSendButton)
        cancelButton.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun selectCurrency(currency: String) {
        selectedCurrency = currency

        val balanceChainIcon = findViewById<ImageView>(R.id.balanceChainIcon)
        val currencySymbol = findViewById<TextView>(R.id.currencySymbol)

        when (currency) {
            "SOL" -> {
                // Update currency display
                balanceChainIcon?.setImageResource(R.drawable.ic_solana)
                currencySymbol?.text = "SOL"

                Log.d("SendActivity", "Selected currency: Solana")
            }
            "ZEC" -> {
                // Update currency display
                balanceChainIcon?.setImageResource(R.drawable.ic_zcash)
                currencySymbol?.text = "ZEC"

                Log.d("SendActivity", "Selected currency: Zcash")
            }
        }

        // Reload balance for selected currency
        loadWalletBalance()
    }

    private fun sendSolanaTransaction(recipientAddress: String, amount: Double) {
        // Create transaction status bottom sheet
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_transaction_status, null)

        // Set minimum height
        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        val desiredHeight = (screenHeight * 0.7).toInt()
        view.minimumHeight = desiredHeight

        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = false // Prevent dismissing during transaction
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true
        bottomSheet.setCancelable(false) // Prevent back button dismiss during transaction

        // Make backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Get views
        val spinner = view.findViewById<ProgressBar>(R.id.txStatusSpinner)
        val successIcon = view.findViewById<ImageView>(R.id.txStatusSuccessIcon)
        val errorIcon = view.findViewById<ImageView>(R.id.txStatusErrorIcon)
        val titleText = view.findViewById<TextView>(R.id.txStatusTitle)
        val statusMessage = view.findViewById<TextView>(R.id.txStatusMessage)
        val amountText = view.findViewById<TextView>(R.id.txStatusAmount)
        val usdValueText = view.findViewById<TextView>(R.id.txStatusUsdValue)
        val fromWalletText = view.findViewById<TextView>(R.id.txStatusFromWallet)
        val toAddressText = view.findViewById<TextView>(R.id.txStatusToAddress)
        val networkText = view.findViewById<TextView>(R.id.txStatusNetwork)
        val networkFeeText = view.findViewById<TextView>(R.id.txStatusNetworkFee)
        val txHashContainer = view.findViewById<LinearLayout>(R.id.txHashContainer)
        val txHashText = view.findViewById<TextView>(R.id.txHashText)
        val copyTxHashIcon = view.findViewById<ImageView>(R.id.copyTxHashIcon)
        val errorMessage = view.findViewById<TextView>(R.id.txErrorMessage)
        val closeButton = view.findViewById<Button>(R.id.txStatusCloseButton)

        // Set transaction details
        amountText?.text = "$amount SOL"
        val usdValue = amount * currentTokenPrice
        usdValueText?.text = "≈ $${String.format("%.2f", usdValue)} USD"
        fromWalletText?.text = currentWalletName
        toAddressText?.text = "${recipientAddress.take(6)}...${recipientAddress.takeLast(6)}"
        networkText?.text = "Solana"
        networkFeeText?.text = "~0.000005 SOL"

        bottomSheet.show()

        lifecycleScope.launch {
            try {
                Log.i("SendActivity", "Initiating SOL transfer: $amount SOL from $currentWalletName to $recipientAddress")

                // Update status: Preparing
                statusMessage?.text = "Preparing transaction..."

                val keyManager = KeyManager.getInstance(this@SendActivity)
                val solanaService = SolanaService(this@SendActivity)

                // Update status: Sending
                statusMessage?.text = "Sending transaction to network..."

                val result = solanaService.sendTransaction(
                    fromPublicKey = currentWalletAddress,
                    toPublicKey = recipientAddress,
                    amountSOL = amount,
                    keyManager = keyManager,
                    walletId = currentWalletId
                )

                if (result.isSuccess) {
                    val txSignature = result.getOrNull()!!
                    Log.i("SendActivity", "Transaction successful: $txSignature")

                    // Update status: Success
                    spinner?.visibility = View.GONE
                    successIcon?.visibility = View.VISIBLE
                    titleText?.text = "Transaction Sent!"
                    statusMessage?.text = "Your transaction has been broadcast to the network"

                    // Show transaction hash
                    txHashContainer?.visibility = View.VISIBLE
                    txHashText?.text = txSignature

                    // Copy hash button
                    copyTxHashIcon?.setOnClickListener {
                        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        val clip = android.content.ClipData.newPlainText("Transaction Hash", txSignature)
                        clipboard.setPrimaryClip(clip)
                        ThemedToast.show(this@SendActivity, "Transaction hash copied")
                    }

                    // Enable close button
                    closeButton?.isEnabled = true
                    closeButton?.alpha = 1.0f
                    closeButton?.setOnClickListener {
                        bottomSheet.dismiss()
                        // Clear inputs and go back
                        findViewById<EditText>(R.id.recipientAddressInput).setText("")
                        findViewById<EditText>(R.id.balanceAmount).setText("")
                        finish()
                    }

                    // Auto-dismiss after 5 seconds
                    view.postDelayed({
                        if (bottomSheet.isShowing) {
                            bottomSheet.dismiss()
                            findViewById<EditText>(R.id.recipientAddressInput).setText("")
                            findViewById<EditText>(R.id.balanceAmount).setText("")
                            finish()
                        }
                    }, 5000)

                } else {
                    val error = result.exceptionOrNull()
                    Log.e("SendActivity", "Transaction failed", error)

                    // Update status: Error
                    spinner?.visibility = View.GONE
                    errorIcon?.visibility = View.VISIBLE
                    titleText?.text = "Transaction Failed"
                    statusMessage?.visibility = View.GONE
                    errorMessage?.visibility = View.VISIBLE
                    errorMessage?.text = error?.message ?: "Unknown error occurred"

                    // Enable close button
                    closeButton?.isEnabled = true
                    closeButton?.alpha = 1.0f
                    closeButton?.setOnClickListener {
                        bottomSheet.dismiss()
                    }
                }

            } catch (e: Exception) {
                Log.e("SendActivity", "Failed to send transaction", e)

                // Update status: Error
                spinner?.visibility = View.GONE
                errorIcon?.visibility = View.VISIBLE
                titleText?.text = "Transaction Failed"
                statusMessage?.visibility = View.GONE
                errorMessage?.visibility = View.VISIBLE
                errorMessage?.text = e.message ?: "Unknown error occurred"

                // Enable close button
                closeButton?.isEnabled = true
                closeButton?.alpha = 1.0f
                closeButton?.setOnClickListener {
                    bottomSheet.dismiss()
                }
            }
        }
    }

    private fun sendZcashTransaction(recipientAddress: String, amount: Double) {
        // Create transaction status bottom sheet
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_transaction_status, null)

        // Set minimum height
        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        val desiredHeight = (screenHeight * 0.7).toInt()
        view.minimumHeight = desiredHeight

        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = false // Prevent dismissing during transaction
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true
        bottomSheet.setCancelable(false) // Prevent back button dismiss during transaction

        // Make backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Get views
        val spinner = view.findViewById<ProgressBar>(R.id.txStatusSpinner)
        val successIcon = view.findViewById<ImageView>(R.id.txStatusSuccessIcon)
        val errorIcon = view.findViewById<ImageView>(R.id.txStatusErrorIcon)
        val titleText = view.findViewById<TextView>(R.id.txStatusTitle)
        val statusMessage = view.findViewById<TextView>(R.id.txStatusMessage)
        val amountText = view.findViewById<TextView>(R.id.txStatusAmount)
        val usdValueText = view.findViewById<TextView>(R.id.txStatusUsdValue)
        val fromWalletText = view.findViewById<TextView>(R.id.txStatusFromWallet)
        val toAddressText = view.findViewById<TextView>(R.id.txStatusToAddress)
        val networkText = view.findViewById<TextView>(R.id.txStatusNetwork)
        val networkFeeText = view.findViewById<TextView>(R.id.txStatusNetworkFee)
        val txHashContainer = view.findViewById<LinearLayout>(R.id.txHashContainer)
        val txHashText = view.findViewById<TextView>(R.id.txHashText)
        val copyTxHashIcon = view.findViewById<ImageView>(R.id.copyTxHashIcon)
        val errorMessage = view.findViewById<TextView>(R.id.txErrorMessage)
        val closeButton = view.findViewById<Button>(R.id.txStatusCloseButton)

        // Set transaction details
        amountText?.text = "$amount ZEC"
        val usdValue = amount * currentTokenPrice
        usdValueText?.text = "≈ $${String.format("%.2f", usdValue)} USD"
        fromWalletText?.text = currentWalletName
        toAddressText?.text = "${recipientAddress.take(6)}...${recipientAddress.takeLast(6)}"
        networkText?.text = "Zcash"
        networkFeeText?.text = "~0.0001 ZEC"

        bottomSheet.show()

        lifecycleScope.launch {
            try {
                Log.i("SendActivity", "Initiating ZEC transfer: $amount ZEC from $currentWalletName to $recipientAddress")

                // Update status: Preparing
                statusMessage?.text = "Preparing transaction..."

                val zcashService = ZcashService.getInstance(this@SendActivity)

                // Update status: Sending
                statusMessage?.text = "Sending transaction to network..."

                val result = zcashService.sendTransaction(
                    toAddress = recipientAddress,
                    amountZEC = amount,
                    memo = "Sent from SecureLegion"
                )

                if (result.isSuccess) {
                    val txId = result.getOrNull()!!
                    Log.i("SendActivity", "ZEC transaction successful: $txId")

                    // Update status: Success
                    spinner?.visibility = View.GONE
                    successIcon?.visibility = View.VISIBLE
                    titleText?.text = "Transaction Sent!"
                    statusMessage?.text = "Your transaction has been broadcast to the network"

                    // Show transaction hash
                    txHashContainer?.visibility = View.VISIBLE
                    txHashText?.text = txId

                    // Copy hash button
                    copyTxHashIcon?.setOnClickListener {
                        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        val clip = android.content.ClipData.newPlainText("Transaction ID", txId)
                        clipboard.setPrimaryClip(clip)
                        ThemedToast.show(this@SendActivity, "Transaction ID copied")
                    }

                    // Enable close button
                    closeButton?.isEnabled = true
                    closeButton?.alpha = 1.0f
                    closeButton?.setOnClickListener {
                        bottomSheet.dismiss()
                        // Clear inputs and go back
                        findViewById<EditText>(R.id.recipientAddressInput).setText("")
                        findViewById<EditText>(R.id.balanceAmount).setText("")
                        finish()
                    }

                    // Auto-dismiss after 5 seconds
                    view.postDelayed({
                        if (bottomSheet.isShowing) {
                            bottomSheet.dismiss()
                            findViewById<EditText>(R.id.recipientAddressInput).setText("")
                            findViewById<EditText>(R.id.balanceAmount).setText("")
                            finish()
                        }
                    }, 5000)

                } else {
                    val error = result.exceptionOrNull()
                    Log.e("SendActivity", "ZEC transaction failed", error)

                    // Update status: Error
                    spinner?.visibility = View.GONE
                    errorIcon?.visibility = View.VISIBLE
                    titleText?.text = "Transaction Failed"
                    statusMessage?.visibility = View.GONE
                    errorMessage?.visibility = View.VISIBLE
                    errorMessage?.text = error?.message ?: "Unknown error occurred"

                    // Enable close button
                    closeButton?.isEnabled = true
                    closeButton?.alpha = 1.0f
                    closeButton?.setOnClickListener {
                        bottomSheet.dismiss()
                    }
                }

            } catch (e: Exception) {
                Log.e("SendActivity", "Failed to send ZEC transaction", e)

                // Update status: Error
                spinner?.visibility = View.GONE
                errorIcon?.visibility = View.VISIBLE
                titleText?.text = "Transaction Failed"
                statusMessage?.visibility = View.GONE
                errorMessage?.visibility = View.VISIBLE
                errorMessage?.text = e.message ?: "Unknown error occurred"

                // Enable close button
                closeButton?.isEnabled = true
                closeButton?.alpha = 1.0f
                closeButton?.setOnClickListener {
                    bottomSheet.dismiss()
                }
            }
        }
    }

    private fun loadCachedPrice() {
        val prefs = getSharedPreferences("wallet_prices", MODE_PRIVATE)
        val priceKey = "${selectedCurrency}_price"
        val balanceKey = "${currentWalletId}_${selectedCurrency}_balance"

        val cachedPrice = prefs.getFloat(priceKey, 0f).toDouble()
        val cachedBalance = prefs.getFloat(balanceKey, 0f).toDouble()

        if (cachedPrice > 0) {
            currentTokenPrice = cachedPrice
            Log.d("SendActivity", "Loaded cached price for $selectedCurrency: $$cachedPrice")
        } else {
            Log.d("SendActivity", "No cached price found for $selectedCurrency")
        }

        // Show cached balance for display only, but don't use it for validation
        if (cachedBalance > 0) {
            val balanceText = findViewById<TextView>(R.id.availableBalance)
            balanceText?.text = "${formatBalance(cachedBalance)} $selectedCurrency (cached)"
            Log.d("SendActivity", "Loaded cached balance for display: $cachedBalance (not used for validation)")
        } else {
            val balanceText = findViewById<TextView>(R.id.availableBalance)
            balanceText?.text = "Loading..."
            Log.d("SendActivity", "No cached balance found")
        }
    }

    private fun savePriceToCache(price: Double) {
        val prefs = getSharedPreferences("wallet_prices", MODE_PRIVATE)
        val key = "${selectedCurrency}_price"
        prefs.edit().putFloat(key, price.toFloat()).apply()
        Log.d("SendActivity", "Saved price to cache for $selectedCurrency: $$price")
    }

    private fun saveBalanceToCache(balance: Double) {
        val prefs = getSharedPreferences("wallet_prices", MODE_PRIVATE)
        val key = "${currentWalletId}_${selectedCurrency}_balance"
        prefs.edit().putFloat(key, balance.toFloat()).apply()
        Log.d("SendActivity", "Saved balance to cache for $selectedCurrency: $balance")
    }

    private fun loadWalletBalance() {
        when (selectedCurrency) {
            "SOL" -> loadSolanaBalance()
            "ZEC" -> loadZcashBalance()
        }
    }

    private fun loadSolanaBalance() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val solanaService = SolanaService(this@SendActivity)

                // Use the current wallet address
                val walletAddress = currentWalletAddress

                // Fetch balance and price together
                val balanceResult = solanaService.getBalance(walletAddress)
                val priceResult = solanaService.getSolPrice()

                withContext(Dispatchers.Main) {
                    if (balanceResult.isSuccess) {
                        val balanceSOL = balanceResult.getOrNull() ?: 0.0

                        // Update available balance for validation
                        availableBalance = balanceSOL
                        saveBalanceToCache(balanceSOL)

                        // Update SOL balance with smart formatting
                        findViewById<TextView>(R.id.availableBalance).text = "${formatBalance(balanceSOL)} SOL"

                        // Set price for USD conversion
                        if (priceResult.isSuccess) {
                            val priceUSD = priceResult.getOrNull() ?: 0.0
                            currentTokenPrice = priceUSD
                            savePriceToCache(priceUSD)
                            Log.i("SendActivity", "Balance loaded: $balanceSOL SOL (Price: $$priceUSD)")
                        } else {
                            Log.e("SendActivity", "Failed to load SOL price: ${priceResult.exceptionOrNull()?.message}")
                            // Keep cached price if fresh load fails
                        }

                        Log.i("SendActivity", "Balance loaded: $balanceSOL SOL, currentTokenPrice: $currentTokenPrice")
                    } else {
                        Log.e("SendActivity", "Failed to load balance: ${balanceResult.exceptionOrNull()?.message}")
                        findViewById<TextView>(R.id.availableBalance).text = "0 SOL"
                    }
                }
            } catch (e: Exception) {
                Log.e("SendActivity", "Error loading wallet balance", e)
                withContext(Dispatchers.Main) {
                    findViewById<TextView>(R.id.availableBalance).text = "0 SOL"
                }
            }
        }
    }

    private fun loadZcashBalance() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val zcashService = ZcashService.getInstance(this@SendActivity)

                // Fetch ZEC balance and price together
                val balanceResult = zcashService.getBalance()
                val priceResult = zcashService.getZecPrice()

                withContext(Dispatchers.Main) {
                    if (balanceResult.isSuccess) {
                        val balanceZEC = balanceResult.getOrNull() ?: 0.0

                        // Update available balance for validation
                        availableBalance = balanceZEC
                        saveBalanceToCache(balanceZEC)

                        // Update ZEC balance with smart formatting
                        findViewById<TextView>(R.id.availableBalance).text = "${formatBalance(balanceZEC)} ZEC"

                        // Set price for USD conversion
                        if (priceResult.isSuccess) {
                            val priceUSD = priceResult.getOrNull() ?: 0.0
                            currentTokenPrice = priceUSD
                            savePriceToCache(priceUSD)
                            Log.i("SendActivity", "Balance loaded: $balanceZEC ZEC (Price: $$priceUSD)")
                        } else {
                            Log.e("SendActivity", "Failed to load ZEC price: ${priceResult.exceptionOrNull()?.message}")
                            // Keep cached price if fresh load fails
                        }

                        Log.i("SendActivity", "Balance loaded: $balanceZEC ZEC, currentTokenPrice: $currentTokenPrice")
                    } else {
                        val errorMsg = balanceResult.exceptionOrNull()?.message ?: "Unknown error"
                        Log.e("SendActivity", "Failed to load ZEC balance: $errorMsg")
                        findViewById<TextView>(R.id.availableBalance).text = "0 ZEC"
                        ThemedToast.show(this@SendActivity, "ZEC wallet syncing... Balance may be unavailable")
                    }
                }
            } catch (e: Exception) {
                Log.e("SendActivity", "Error loading ZEC balance", e)
                withContext(Dispatchers.Main) {
                    findViewById<TextView>(R.id.availableBalance).text = "0 ZEC"
                    ThemedToast.show(this@SendActivity, "Unable to load ZEC balance: ${e.message}")
                }
            }
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }
    }
}
