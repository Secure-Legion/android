package com.securelegion

import android.app.Activity
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_send)

        // Get wallet info from intent
        currentWalletId = intent.getStringExtra("WALLET_ID") ?: "main"
        currentWalletName = intent.getStringExtra("WALLET_NAME") ?: "Wallet 1"
        currentWalletAddress = intent.getStringExtra("WALLET_ADDRESS") ?: ""

        Log.d("SendActivity", "Sending from wallet: $currentWalletName ($currentWalletAddress)")

        setupCurrencySelector()
        setupQRScanner()
        setupWalletSelector()
        setupAmountInput()
        loadCurrentWallet()
        loadWalletBalance()
        setupPriceRefresh()
        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            val recipientAddress = findViewById<EditText>(R.id.recipientAddressInput).text.toString()
            val amount = findViewById<EditText>(R.id.amountInput).text.toString()

            if (recipientAddress.isEmpty()) {
                ThemedToast.show(this, "Please enter recipient address")
                return@setOnClickListener
            }

            if (amount.isEmpty() || amount.toDoubleOrNull() == null || amount.toDouble() <= 0) {
                ThemedToast.show(this, "Please enter a valid amount")
                return@setOnClickListener
            }

            // Show confirmation dialog before sending
            showSendConfirmation(recipientAddress, amount.toDouble())
        }
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
        val usdValue = findViewById<TextView>(R.id.usdValue)
        usdValue?.setOnClickListener {
            ThemedToast.show(this, "Refreshing price...")
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
        findViewById<TextView>(R.id.walletNameText)?.text = currentWalletName
        if (currentWalletAddress.isNotEmpty()) {
            findViewById<TextView>(R.id.walletAddressShort)?.text =
                "${currentWalletAddress.take(5)}.....${currentWalletAddress.takeLast(6)}"
        } else {
            findViewById<TextView>(R.id.walletAddressShort)?.text = "----"
        }
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
        val confirmRecipientShort = view.findViewById<TextView>(R.id.confirmSendRecipient)
        val confirmFromWallet = view.findViewById<TextView>(R.id.confirmSendFromWallet)
        val confirmToAddress = view.findViewById<TextView>(R.id.confirmSendTo)
        val confirmCurrency = view.findViewById<TextView>(R.id.confirmSendCurrency)

        // Set values
        confirmAmount?.text = "$amount $selectedCurrency"
        confirmRecipientShort?.text = "${recipientAddress.take(5)}...${recipientAddress.takeLast(6)}"
        confirmFromWallet?.text = currentWalletName
        confirmToAddress?.text = "${recipientAddress.take(5)}...${recipientAddress.takeLast(6)}"
        confirmCurrency?.text = selectedCurrency

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

        val selectedIcon = findViewById<ImageView>(R.id.selectedCurrencyIcon)
        val selectedName = findViewById<TextView>(R.id.selectedCurrencyName)
        val currencySymbol = findViewById<TextView>(R.id.currencySymbol)

        when (currency) {
            "SOL" -> {
                // Update currency display
                selectedIcon.setImageResource(R.drawable.ic_solana)
                selectedName.text = "Solana"
                currencySymbol.text = "SOL"

                Log.d("SendActivity", "Selected currency: Solana")
            }
            "ZEC" -> {
                // Update currency display
                selectedIcon.setImageResource(R.drawable.ic_zcash)
                selectedName.text = "Zcash"
                currencySymbol.text = "ZEC"

                Log.d("SendActivity", "Selected currency: Zcash")
            }
        }

        // Reload balance for selected currency
        loadWalletBalance()
    }

    private fun sendSolanaTransaction(recipientAddress: String, amount: Double) {
        val sendButton = findViewById<View>(R.id.sendButton)
        sendButton.isEnabled = false // Disable during processing

        lifecycleScope.launch {
            try {
                Log.i("SendActivity", "Initiating SOL transfer: $amount SOL from $currentWalletName to $recipientAddress")

                val keyManager = KeyManager.getInstance(this@SendActivity)
                val solanaService = SolanaService(this@SendActivity)

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
                    ThemedToast.showLong(
                        this@SendActivity,
                        "SOL transaction sent!\nSignature: ${txSignature.take(8)}..."
                    )

                    // Clear inputs
                    findViewById<EditText>(R.id.recipientAddressInput).setText("")
                    findViewById<EditText>(R.id.amountInput).setText("")
                    finish()
                } else {
                    val error = result.exceptionOrNull()
                    Log.e("SendActivity", "Transaction failed", error)
                    ThemedToast.showLong(
                        this@SendActivity,
                        "Transaction failed: ${error?.message}"
                    )
                    sendButton.isEnabled = true
                }

            } catch (e: Exception) {
                Log.e("SendActivity", "Failed to send transaction", e)
                ThemedToast.showLong(
                    this@SendActivity,
                    "Error: ${e.message}"
                )
                sendButton.isEnabled = true
            }
        }
    }

    private fun sendZcashTransaction(recipientAddress: String, amount: Double) {
        val sendButton = findViewById<View>(R.id.sendButton)
        sendButton.isEnabled = false // Disable during processing

        lifecycleScope.launch {
            try {
                Log.i("SendActivity", "Initiating ZEC transfer: $amount ZEC from $currentWalletName to $recipientAddress")

                val zcashService = ZcashService.getInstance(this@SendActivity)

                val result = zcashService.sendTransaction(
                    toAddress = recipientAddress,
                    amountZEC = amount,
                    memo = "Sent from SecureLegion"
                )

                if (result.isSuccess) {
                    val txId = result.getOrNull()!!
                    Log.i("SendActivity", "ZEC transaction successful: $txId")
                    ThemedToast.showLong(
                        this@SendActivity,
                        "ZEC transaction sent!\nTx ID: ${txId.take(8)}..."
                    )

                    // Clear inputs
                    findViewById<EditText>(R.id.recipientAddressInput).setText("")
                    findViewById<EditText>(R.id.amountInput).setText("")
                    finish()
                } else {
                    val error = result.exceptionOrNull()
                    Log.e("SendActivity", "ZEC transaction failed", error)
                    ThemedToast.showLong(
                        this@SendActivity,
                        "Transaction failed: ${error?.message}"
                    )
                    sendButton.isEnabled = true
                }

            } catch (e: Exception) {
                Log.e("SendActivity", "Failed to send ZEC transaction", e)
                ThemedToast.showLong(
                    this@SendActivity,
                    "Error: ${e.message}"
                )
                sendButton.isEnabled = true
            }
        }
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

                // Fetch balance
                val balanceResult = solanaService.getBalance(walletAddress)

                withContext(Dispatchers.Main) {
                    if (balanceResult.isSuccess) {
                        val balanceSOL = balanceResult.getOrNull() ?: 0.0

                        // Update SOL balance with smart formatting
                        findViewById<TextView>(R.id.availableBalance).text = "${formatBalance(balanceSOL)} SOL"

                        // Fetch live SOL price and calculate USD value
                        lifecycleScope.launch(Dispatchers.IO) {
                            try {
                                val priceResult = solanaService.getSolPrice()
                                withContext(Dispatchers.Main) {
                                    if (priceResult.isSuccess) {
                                        val priceUSD = priceResult.getOrNull() ?: 0.0
                                        currentTokenPrice = priceUSD // Cache for live conversion
                                        val balanceUSD = balanceSOL * priceUSD
                                        findViewById<TextView>(R.id.usdValue).text = String.format("$%,.2f", balanceUSD)
                                        // Update the amount USD value if there's already an amount
                                        updateAmountUsdValue()
                                    } else {
                                        findViewById<TextView>(R.id.usdValue).text = "$0.00"
                                    }
                                }
                            } catch (e: Exception) {
                                Log.e("SendActivity", "Error loading SOL price", e)
                                withContext(Dispatchers.Main) {
                                    findViewById<TextView>(R.id.usdValue).text = "$0.00"
                                }
                            }
                        }

                        Log.i("SendActivity", "Balance loaded: $balanceSOL SOL")
                    } else {
                        Log.e("SendActivity", "Failed to load balance: ${balanceResult.exceptionOrNull()?.message}")
                        findViewById<TextView>(R.id.availableBalance).text = "0 SOL"
                        findViewById<TextView>(R.id.usdValue).text = "$0.00"
                    }
                }
            } catch (e: Exception) {
                Log.e("SendActivity", "Error loading wallet balance", e)
                withContext(Dispatchers.Main) {
                    findViewById<TextView>(R.id.availableBalance).text = "0 SOL"
                    findViewById<TextView>(R.id.usdValue).text = "$0.00"
                }
            }
        }
    }

    private fun loadZcashBalance() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val zcashService = ZcashService.getInstance(this@SendActivity)

                // Fetch ZEC balance
                val balanceResult = zcashService.getBalance()

                withContext(Dispatchers.Main) {
                    if (balanceResult.isSuccess) {
                        val balanceZEC = balanceResult.getOrNull() ?: 0.0

                        // Update ZEC balance with smart formatting
                        findViewById<TextView>(R.id.availableBalance).text = "${formatBalance(balanceZEC)} ZEC"

                        // Fetch live ZEC price and calculate USD value
                        lifecycleScope.launch(Dispatchers.IO) {
                            try {
                                val priceResult = zcashService.getZecPrice()
                                withContext(Dispatchers.Main) {
                                    if (priceResult.isSuccess) {
                                        val priceUSD = priceResult.getOrNull() ?: 0.0
                                        if (priceUSD > 0) {
                                            currentTokenPrice = priceUSD // Cache for live conversion
                                            val balanceUSD = balanceZEC * priceUSD
                                            findViewById<TextView>(R.id.usdValue).text = String.format("$%,.2f", balanceUSD)
                                            // Update the amount USD value if there's already an amount
                                            updateAmountUsdValue()
                                        } else {
                                            findViewById<TextView>(R.id.usdValue).text = "$0.00"
                                        }
                                    } else {
                                        findViewById<TextView>(R.id.usdValue).text = "$0.00"
                                    }
                                }
                            } catch (e: Exception) {
                                Log.e("SendActivity", "Error loading ZEC price", e)
                                withContext(Dispatchers.Main) {
                                    findViewById<TextView>(R.id.usdValue).text = "$0.00"
                                }
                            }
                        }

                        Log.i("SendActivity", "Balance loaded: $balanceZEC ZEC")
                    } else {
                        val errorMsg = balanceResult.exceptionOrNull()?.message ?: "Unknown error"
                        Log.e("SendActivity", "Failed to load ZEC balance: $errorMsg")
                        findViewById<TextView>(R.id.availableBalance).text = "0 ZEC"
                        findViewById<TextView>(R.id.usdValue).text = "$0.00"
                        ThemedToast.show(this@SendActivity, "ZEC wallet syncing... Balance may be unavailable")
                    }
                }
            } catch (e: Exception) {
                Log.e("SendActivity", "Error loading ZEC balance", e)
                withContext(Dispatchers.Main) {
                    findViewById<TextView>(R.id.availableBalance).text = "0 ZEC"
                    findViewById<TextView>(R.id.usdValue).text = "$0.00"
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
