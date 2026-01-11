package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.services.SolanaService
import com.securelegion.services.ZcashService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WalletActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.fragment_wallet)

        setupUI()
        ensureZcashInitialized()
        loadWalletBalance()
    }

    private fun ensureZcashInitialized() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val zcashAddress = keyManager.getZcashAddress()

                // If user has a Zcash address but ZcashService isn't initialized, initialize it now
                if (zcashAddress != null && zcashAddress.isNotEmpty()) {
                    // Get seed phrase from main wallet (Zcash uses main account seed)
                    val seedPhrase = keyManager.getMainWalletSeedForZcash()
                        ?: keyManager.getSeedPhrase() // Fallback to temporary backup

                    if (seedPhrase != null) {
                        val useTestnet = BridgeActivity.isTestnetEnabled(this@WalletActivity)
                        Log.d("WalletActivity", "Auto-initializing ZcashService on wallet load (testnet: $useTestnet)")
                        val zcashService = ZcashService.getInstance(this@WalletActivity)
                        val result = zcashService.initialize(seedPhrase, useTestnet = useTestnet)
                        if (result.isSuccess) {
                            Log.i("WalletActivity", "ZcashService initialized successfully")
                        } else {
                            Log.e("WalletActivity", "Failed to initialize ZcashService: ${result.exceptionOrNull()?.message}")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Error during Zcash initialization check", e)
            }
        }
    }

    private fun setupUI() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            val intent = Intent(this, SendActivity::class.java)
            startActivity(intent)
        }

        // Receive button
        findViewById<View>(R.id.receiveButton).setOnClickListener {
            val intent = Intent(this, ReceiveActivity::class.java)
            startActivity(intent)
        }

        // Shield button
        findViewById<View>(R.id.shieldButton)?.setOnClickListener {
            shieldTransparentFunds()
        }

        // Wallet settings button
        findViewById<View>(R.id.walletSettingsButton).setOnClickListener {
            openWalletSettings()
        }

        // Bottom navigation (optional - may not exist in all layouts)
        findViewById<View>(R.id.navMessages)?.setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet)?.setOnClickListener {
            // Already on wallet page, do nothing
        }

        findViewById<View>(R.id.navAddFriend)?.setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.navLock)?.setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }

        // Load current wallet name
        loadCurrentWalletName()

        // Wallet selector dropdown
        findViewById<View>(R.id.walletSelectorDropdown)?.setOnClickListener {
            showWalletSelector()
        }

        // Eye button - toggle balance visibility
        findViewById<View>(R.id.toggleBalanceVisibility)?.setOnClickListener {
            toggleBalanceVisibility()
        }

        // Currency dropdown - toggle between USD and token display
        findViewById<View>(R.id.currencyDropdown)?.setOnClickListener {
            toggleCurrencyDisplay()
        }

        // Balance text - tap to refresh (for ZEC sync status)
        findViewById<TextView>(R.id.balanceAmount)?.setOnClickListener {
            showZcashSyncStatus()
        }

        // Balance text - long press to shield transparent funds
        findViewById<TextView>(R.id.balanceAmount)?.setOnLongClickListener {
            shieldTransparentFunds()
            true
        }

        // Tokens tab
        findViewById<TextView>(R.id.tokensTab)?.setOnClickListener {
            // Already on tokens view, just update tab colors
            findViewById<TextView>(R.id.tokensTab)?.setTextColor(resources.getColor(R.color.text_white, null))
            findViewById<TextView>(R.id.recentTab)?.setTextColor(resources.getColor(android.R.color.darker_gray, null))
        }

        // Recent tab
        findViewById<TextView>(R.id.recentTab)?.setOnClickListener {
            val intent = Intent(this, RecentTransactionsActivity::class.java)
            startActivity(intent)
        }

        // Set initial currency label
        updateCurrencyLabel()
    }

    private var isBalanceVisible = true
    private var isShowingUSD = true

    private fun shieldTransparentFunds() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val zcashService = ZcashService.getInstance(this@WalletActivity)

                // Get balance breakdown
                val balanceResult = zcashService.getBalance()
                if (balanceResult.isFailure) {
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@WalletActivity, "Failed to get balance")
                    }
                    return@launch
                }

                // Get balance details (we'll need to add a method to get breakdown)
                // For now, show a dialog with shield all option
                withContext(Dispatchers.Main) {
                    showShieldingDialog()
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to show shielding dialog", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Error: ${e.message}")
                }
            }
        }
    }

    private fun showShieldingDialog() {
        val bottomSheet = com.google.android.material.bottomsheet.BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_shield_funds, null)

        // Get views
        val transparentAmount = view.findViewById<android.widget.TextView>(R.id.transparentAmount)
        val shieldedAmount = view.findViewById<android.widget.TextView>(R.id.shieldedAmount)
        val amountInput = view.findViewById<android.widget.EditText>(R.id.shieldAmountInput)
        val shieldButton = view.findViewById<android.widget.Button>(R.id.shieldButton)

        // Get ZEC balance breakdown
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val zcashService = ZcashService.getInstance(this@WalletActivity)
                val balanceResult = zcashService.getBalanceBreakdown()

                if (balanceResult.isSuccess) {
                    val breakdown = balanceResult.getOrNull()
                    if (breakdown != null) {
                        val transparentZEC = breakdown.transparentZEC
                        val shieldedZEC = breakdown.shieldedZEC

                        withContext(Dispatchers.Main) {
                            transparentAmount?.text = String.format("%.4f ZEC", transparentZEC)
                            shieldedAmount?.text = String.format("%.4f ZEC", shieldedZEC)

                            if (transparentZEC <= 0) {
                                shieldButton?.isEnabled = false
                                amountInput?.isEnabled = false
                                ThemedToast.show(this@WalletActivity, "No transparent funds to shield")
                            } else {
                                // Shield button
                                shieldButton?.setOnClickListener {
                                    val customAmount = amountInput?.text.toString().toDoubleOrNull()

                                    // If no amount entered, shield all
                                    val amountToShield = customAmount ?: transparentZEC

                                    if (customAmount != null && customAmount <= 0) {
                                        ThemedToast.show(this@WalletActivity, "Please enter a valid amount")
                                    } else if (customAmount != null && customAmount > transparentZEC) {
                                        ThemedToast.show(this@WalletActivity, "Amount exceeds transparent balance")
                                    } else {
                                        bottomSheet.dismiss()
                                        executeShielding(amountToShield)
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to get balance breakdown", e)
            }
        }

        bottomSheet.setContentView(view)
        bottomSheet.show()
    }

    private fun executeShielding(amountZEC: Double) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Shielding $amountZEC ZEC...\n\nThis may take a moment")
                }

                val zcashService = ZcashService.getInstance(this@WalletActivity)
                val result = zcashService.shieldTransparentFunds(amountZEC)

                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        val txId = result.getOrNull()
                        ThemedToast.show(
                            this@WalletActivity,
                            "Shielding Transaction Submitted!\n\nNote: All transparent ZEC will be shielded\nTx: ${txId?.take(16)}...\n\nWill complete in ~75 seconds"
                        )
                        // Reload balance after a delay
                        kotlinx.coroutines.delay(5000)
                        loadWalletBalance()
                    } else {
                        val error = result.exceptionOrNull()?.message ?: "Unknown error"
                        ThemedToast.show(
                            this@WalletActivity,
                            "Shielding Failed\n\n$error"
                        )
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to shield funds", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Error shielding funds\n\n${e.message}")
                }
            }
        }
    }

    private fun showZcashSyncStatus() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val zcashService = ZcashService.getInstance(this@WalletActivity)

                // Check if Zcash needs initialization first
                val zcashAddress = keyManager.getZcashAddress()
                if (zcashAddress != null && zcashAddress.isNotEmpty()) {
                    // Get seed phrase from main wallet (Zcash uses main account seed)
                    val seedPhrase = keyManager.getMainWalletSeedForZcash()
                        ?: keyManager.getSeedPhrase() // Fallback to temporary backup

                    if (seedPhrase != null) {
                        val useTestnet = BridgeActivity.isTestnetEnabled(this@WalletActivity)
                        android.util.Log.d("WalletActivity", "Initializing ZcashService with seed phrase (testnet: $useTestnet)...")

                        val result = zcashService.initialize(seedPhrase, useTestnet = useTestnet)
                        if (result.isSuccess) {
                            android.util.Log.i("WalletActivity", "ZcashService initialized successfully: ${result.getOrNull()}")
                        } else {
                            val error = result.exceptionOrNull()
                            android.util.Log.e("WalletActivity", "Failed to initialize ZcashService", error)

                            withContext(Dispatchers.Main) {
                                ThemedToast.show(
                                    this@WalletActivity,
                                    "Failed to connect to Zcash network\n\nTap again to retry"
                                )
                            }
                            return@launch
                        }
                    } else {
                        android.util.Log.e("WalletActivity", "No seed phrase found in KeyManager")
                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@WalletActivity, "No seed phrase found\n\nCannot initialize Zcash")
                        }
                        return@launch
                    }
                } else {
                    android.util.Log.d("WalletActivity", "No Zcash address found, skipping initialization")
                    return@launch
                }

                // Check sync status and balance breakdown
                val syncStatusResult = zcashService.getSyncStatus()
                val syncProgressResult = zcashService.getSyncProgress()
                val balanceResult = zcashService.getBalance()

                val syncStatus = syncStatusResult.getOrNull() ?: "UNKNOWN"
                val syncProgress = syncProgressResult.getOrNull() ?: 0
                val balanceZEC = balanceResult.getOrNull() ?: 0.0

                withContext(Dispatchers.Main) {
                    // Only show error messages, not sync status
                    if (syncStatus == "DISCONNECTED") {
                        ThemedToast.show(
                            this@WalletActivity,
                            "No network connection"
                        )
                    }

                    // Reload balance in background
                    loadWalletBalance()
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to get sync status", e)
                withContext(Dispatchers.Main) {
                    loadWalletBalance()
                }
            }
        }
    }

    private fun toggleBalanceVisibility() {
        isBalanceVisible = !isBalanceVisible
        val balanceText = findViewById<TextView>(R.id.balanceAmount)

        if (isBalanceVisible) {
            // Show balance - reload it
            loadWalletBalance()
        } else {
            // Hide balance
            balanceText?.text = "••••••"
        }
    }

    private fun toggleCurrencyDisplay() {
        isShowingUSD = !isShowingUSD
        updateCurrencyLabel()

        // Reload balance with new currency
        loadWalletBalance()
    }

    private fun updateCurrencyLabel() {
        val currencyLabel = findViewById<TextView>(R.id.currencyLabel)

        if (isShowingUSD) {
            currencyLabel?.text = "USD"
        } else {
            // Determine currency based on current wallet type
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val keyManager = KeyManager.getInstance(this@WalletActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                    val allWallets = database.walletDao().getAllWallets()

                    // Filter out "main" wallet
                    val wallets = allWallets.filter { it.walletId != "main" }

                    if (wallets.isNotEmpty()) {
                        // Get the most recently used wallet
                        val currentWallet = wallets.maxByOrNull { it.lastUsedAt }

                        withContext(Dispatchers.Main) {
                            // If wallet has a Zcash address (unified or legacy), it's a ZEC wallet
                            if (!currentWallet?.zcashUnifiedAddress.isNullOrEmpty() || !currentWallet?.zcashAddress.isNullOrEmpty()) {
                                currencyLabel?.text = "ZEC"
                            } else {
                                currencyLabel?.text = "SOL"
                            }
                        }
                    } else {
                        withContext(Dispatchers.Main) {
                            currencyLabel?.text = "SOL"
                        }
                    }
                } catch (e: Exception) {
                    Log.e("WalletActivity", "Failed to determine wallet currency", e)
                    withContext(Dispatchers.Main) {
                        currencyLabel?.text = "SOL"
                    }
                }
            }
        }
    }

    private fun loadWalletBalance() {
        // Don't load if balance is hidden
        if (!isBalanceVisible) {
            return
        }

        lifecycleScope.launch {
            try {
                Log.d("WalletActivity", "Loading wallet balance")

                val balanceText = findViewById<TextView>(R.id.balanceAmount)
                val solBalanceText = findViewById<TextView>(R.id.solBalance)
                val zecBalanceText = findViewById<TextView>(R.id.zecBalance)

                // Show loading state
                withContext(Dispatchers.Main) {
                    balanceText?.text = "Loading..."
                    solBalanceText?.text = "$0.00"
                    zecBalanceText?.text = "$0.00"
                }

                // Determine wallet type from database
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()
                val wallets = allWallets.filter { it.walletId != "main" }
                val currentWallet = wallets.maxByOrNull { it.lastUsedAt }

                // Check if this is a Zcash wallet or Solana wallet
                val isZcashWallet = (!currentWallet?.zcashUnifiedAddress.isNullOrEmpty() || !currentWallet?.zcashAddress.isNullOrEmpty())

                if (isZcashWallet) {
                    Log.d("WalletActivity", "Loading ZEC wallet balance")
                    // Load Zcash balance as main balance
                    loadZcashBalanceAsMain()
                    // Also load SOL balance for the side display
                    loadSolanaBalance()
                } else {
                    Log.d("WalletActivity", "Loading SOL wallet balance")
                    // Get Solana wallet address from current wallet
                    val solanaAddress = currentWallet?.solanaAddress ?: keyManager.getSolanaAddress()

                Log.d("WalletActivity", "Fetching balance for address: $solanaAddress (wallet: ${currentWallet?.name})")

                // Fetch SOL balance
                val solanaService = SolanaService(this@WalletActivity)
                val result = solanaService.getBalance(solanaAddress)

                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        val balanceSOL = result.getOrNull() ?: 0.0
                        Log.d("WalletActivity", "SOL balance: $balanceSOL, solBalanceText view exists: ${solBalanceText != null}")

                        // Display based on currency preference
                        if (isShowingUSD) {
                            // Fetch SOL price and calculate USD value
                            lifecycleScope.launch {
                                val priceResult = solanaService.getSolPrice()
                                if (priceResult.isSuccess) {
                                    val priceUSD = priceResult.getOrNull() ?: 0.0
                                    val balanceUSDValue = balanceSOL * priceUSD
                                    Log.d("WalletActivity", "Setting SOL USD: $balanceUSDValue (${balanceSOL} * ${priceUSD})")
                                    withContext(Dispatchers.Main) {
                                        balanceText?.text = String.format("$%,.2f", balanceUSDValue)
                                        solBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                        Log.d("WalletActivity", "Set solBalanceText to: ${solBalanceText?.text}")
                                    }
                                } else {
                                    Log.e("WalletActivity", "Failed to get SOL price")
                                    withContext(Dispatchers.Main) {
                                        balanceText?.text = "$0.00"
                                        solBalanceText?.text = "$0.00"
                                    }
                                }
                            }
                        } else {
                            // Show SOL amount
                            Log.d("WalletActivity", "Setting SOL amount: $balanceSOL SOL")
                            balanceText?.text = String.format("%.4f", balanceSOL)
                            solBalanceText?.text = String.format("%.4f SOL", balanceSOL)
                            Log.d("WalletActivity", "Set solBalanceText to: ${solBalanceText?.text}")
                        }

                        Log.i("WalletActivity", "Balance loaded successfully")
                    } else {
                        if (isShowingUSD) {
                            balanceText?.text = "$0.00"
                            solBalanceText?.text = "$0.00"
                        } else {
                            balanceText?.text = "0.0000"
                            solBalanceText?.text = "0.0000 SOL"
                        }
                        Log.e("WalletActivity", "Failed to load balance: ${result.exceptionOrNull()?.message}")
                    }
                }

                    // Load Zcash balance
                    loadZcashBalance()
                }

            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load wallet balance", e)
                withContext(Dispatchers.Main) {
                    val balanceText = findViewById<TextView>(R.id.balanceAmount)
                    balanceText?.text = "$0"
                }
            }
        }
    }

    private suspend fun loadZcashBalanceAsMain() {
        try {
            Log.d("WalletActivity", "Loading Zcash balance as main display")

            val keyManager = KeyManager.getInstance(this@WalletActivity)
            val zcashAddress = keyManager.getZcashAddress()
            val transparentAddress = keyManager.getZcashTransparentAddress()

            Log.d("WalletActivity", "Unified address: $zcashAddress")
            Log.d("WalletActivity", "Transparent address: $transparentAddress")

            withContext(Dispatchers.Main) {
                ThemedToast.show(this@WalletActivity, "DEBUG: Loading ZEC balance\nUnified: ${zcashAddress?.take(10)}...\nTransparent: ${transparentAddress?.take(10)}...")
            }

            if (zcashAddress == null) {
                Log.w("WalletActivity", "Zcash address not available")
                withContext(Dispatchers.Main) {
                    val balanceText = findViewById<TextView>(R.id.balanceAmount)
                    val zecBalanceText = findViewById<TextView>(R.id.zecBalance)
                    balanceText?.text = "$0.00"
                    zecBalanceText?.text = "$0.00"
                    ThemedToast.show(this@WalletActivity, "DEBUG: No ZEC address found!")
                }
                return
            }

            val zcashService = ZcashService.getInstance(this@WalletActivity)

            // Check sync status first
            val syncStatusResult = zcashService.getSyncStatus()
            val syncProgressResult = zcashService.getSyncProgress()

            val syncStatus = syncStatusResult.getOrNull() ?: "UNKNOWN"
            val syncProgress = syncProgressResult.getOrNull() ?: 0

            Log.d("WalletActivity", "Sync status: $syncStatus, progress: $syncProgress%")

            val balanceResult = zcashService.getBalance()

            Log.d("WalletActivity", "Balance result: ${balanceResult.isSuccess}, value: ${balanceResult.getOrNull()}")

            withContext(Dispatchers.Main) {
                val balanceText = findViewById<TextView>(R.id.balanceAmount)
                val zecBalanceText = findViewById<TextView>(R.id.zecBalance)

                if (balanceResult.isSuccess) {
                    val balanceZEC = balanceResult.getOrNull() ?: 0.0

                    // Don't show any debug messages
                    Log.i("WalletActivity", "Successfully loaded ZEC balance: $balanceZEC ZEC")

                    // Fetch ZEC price and calculate USD value
                    lifecycleScope.launch {
                        val priceResult = zcashService.getZecPrice()
                        if (priceResult.isSuccess) {
                            val priceUSD = priceResult.getOrNull() ?: 0.0
                            if (priceUSD > 0) {
                                val balanceUSDValue = balanceZEC * priceUSD

                                withContext(Dispatchers.Main) {
                                    if (isShowingUSD) {
                                        // Show USD value in main display
                                        balanceText?.text = String.format("$%,.2f", balanceUSDValue)
                                        zecBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                    } else {
                                        // Show ZEC amount in main display
                                        balanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                        zecBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                    }
                                }
                            } else {
                                withContext(Dispatchers.Main) {
                                    if (isShowingUSD) {
                                        balanceText?.text = "$0.00"
                                    } else {
                                        balanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                    }
                                    zecBalanceText?.text = "$0.00"
                                }
                            }
                        } else {
                            withContext(Dispatchers.Main) {
                                if (isShowingUSD) {
                                    balanceText?.text = "$0.00"
                                } else {
                                    balanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                }
                                zecBalanceText?.text = "$0.00"
                            }
                        }
                    }
                } else {
                    balanceText?.text = "$0.00"
                    zecBalanceText?.text = "$0.00"
                    val errorMsg = balanceResult.exceptionOrNull()?.message ?: "Unknown error"
                    Log.e("WalletActivity", "Failed to load ZEC balance: $errorMsg")
                    ThemedToast.show(this@WalletActivity, "DEBUG: Failed to get balance\nError: $errorMsg")
                }
            }

        } catch (e: Exception) {
            Log.e("WalletActivity", "Failed to load Zcash balance as main", e)
            withContext(Dispatchers.Main) {
                ThemedToast.show(this@WalletActivity, "DEBUG: Exception loading ZEC balance\n${e.message}")
            }
        }
    }

    private suspend fun loadZcashBalance() {
        try {
            Log.d("WalletActivity", "Loading Zcash balance")

            val keyManager = KeyManager.getInstance(this@WalletActivity)
            val zcashAddress = keyManager.getZcashAddress()

            if (zcashAddress == null) {
                Log.w("WalletActivity", "Zcash address not available")
                withContext(Dispatchers.Main) {
                    val zecBalanceText = findViewById<TextView>(R.id.zecBalance)
                    zecBalanceText?.text = "$0.00"
                }
                return
            }

            val zcashService = ZcashService.getInstance(this@WalletActivity)
            val balanceResult = zcashService.getBalance()

            withContext(Dispatchers.Main) {
                val zecBalanceText = findViewById<TextView>(R.id.zecBalance)

                if (balanceResult.isSuccess) {
                    val balanceZEC = balanceResult.getOrNull() ?: 0.0

                    // Fetch ZEC price and calculate USD value
                    lifecycleScope.launch {
                        val priceResult = zcashService.getZecPrice()
                        if (priceResult.isSuccess) {
                            val priceUSD = priceResult.getOrNull() ?: 0.0
                            if (priceUSD > 0) {
                                val balanceUSDValue = balanceZEC * priceUSD
                                withContext(Dispatchers.Main) {
                                    zecBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                }
                            } else {
                                withContext(Dispatchers.Main) {
                                    zecBalanceText?.text = "$0.00"
                                }
                            }
                        } else {
                            withContext(Dispatchers.Main) {
                                zecBalanceText?.text = "$0.00"
                            }
                        }
                    }
                } else {
                    zecBalanceText?.text = "$0.00"
                    Log.e("WalletActivity", "Failed to load ZEC balance: ${balanceResult.exceptionOrNull()?.message}")
                }
            }

        } catch (e: Exception) {
            Log.e("WalletActivity", "Failed to load Zcash balance", e)
        }
    }

    private suspend fun loadSolanaBalance() {
        try {
            Log.d("WalletActivity", "Loading Solana balance (side display)")

            val keyManager = KeyManager.getInstance(this@WalletActivity)

            // Get a SOL wallet from database
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
            val allWallets = database.walletDao().getAllWallets()
            val wallets = allWallets.filter { it.walletId != "main" }

            // Find a SOL wallet (one without ZEC address)
            val solWallet = wallets.firstOrNull { wallet ->
                wallet.zcashAddress.isNullOrEmpty() && wallet.solanaAddress.isNotEmpty()
            }

            val solanaAddress = solWallet?.solanaAddress ?: keyManager.getSolanaAddress()
            Log.d("WalletActivity", "SOL address: $solanaAddress (wallet: ${solWallet?.name})")

            if (solanaAddress.isEmpty()) {
                Log.w("WalletActivity", "Solana address not available")
                withContext(Dispatchers.Main) {
                    val solBalanceText = findViewById<TextView>(R.id.solBalance)
                    solBalanceText?.text = "$0.00"
                }
                return
            }

            val solanaService = SolanaService(this@WalletActivity)
            val balanceResult = solanaService.getBalance(solanaAddress)

            withContext(Dispatchers.Main) {
                val solBalanceText = findViewById<TextView>(R.id.solBalance)
                Log.d("WalletActivity", "solBalanceText view exists: ${solBalanceText != null}")

                if (balanceResult.isSuccess) {
                    val balanceSOL = balanceResult.getOrNull() ?: 0.0
                    Log.d("WalletActivity", "SOL balance (side): $balanceSOL")

                    // Fetch SOL price and calculate USD value
                    lifecycleScope.launch {
                        val priceResult = solanaService.getSolPrice()
                        if (priceResult.isSuccess) {
                            val priceUSD = priceResult.getOrNull() ?: 0.0
                            if (priceUSD > 0) {
                                val balanceUSDValue = balanceSOL * priceUSD
                                Log.d("WalletActivity", "Setting SOL side display: $$balanceUSDValue")
                                withContext(Dispatchers.Main) {
                                    solBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                    Log.d("WalletActivity", "Set solBalanceText (side) to: ${solBalanceText?.text}")
                                }
                            } else {
                                withContext(Dispatchers.Main) {
                                    solBalanceText?.text = "$0.00"
                                }
                            }
                        } else {
                            Log.e("WalletActivity", "Failed to get SOL price (side)")
                            withContext(Dispatchers.Main) {
                                solBalanceText?.text = "$0.00"
                            }
                        }
                    }
                } else {
                    solBalanceText?.text = "$0.00"
                    Log.e("WalletActivity", "Failed to load SOL balance (side): ${balanceResult.exceptionOrNull()?.message}")
                }
            }

        } catch (e: Exception) {
            Log.e("WalletActivity", "Failed to load Solana balance (side)", e)
        }
    }

    private fun loadCurrentWalletName() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    val walletNameText = findViewById<TextView>(R.id.walletNameText)
                    val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)

                    if (wallets.isNotEmpty()) {
                        // Get the most recently used wallet
                        val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                        walletNameText?.text = currentWallet?.name ?: "----"

                        // Update chain icon based on wallet type
                        updateChainIcon(walletChainIcon, currentWallet)

                        // Update visible tokens based on wallet type
                        updateVisibleTokens(currentWallet)
                    } else {
                        walletNameText?.text = "----"
                        walletChainIcon?.setImageResource(R.drawable.ic_solana)

                        // Show Solana tokens by default
                        updateVisibleTokens(null)
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load current wallet name", e)
                withContext(Dispatchers.Main) {
                    val walletNameText = findViewById<TextView>(R.id.walletNameText)
                    walletNameText?.text = "----"
                }
            }
        }
    }

    private fun updateChainIcon(iconView: ImageView?, wallet: Wallet?) {
        if (iconView == null || wallet == null) return

        // Determine wallet type: if it has a Zcash address (unified or legacy) and no Solana, it's ZEC
        // If it has Solana address, it's SOL (default)
        val isZcashWallet = (!wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()) && wallet.solanaAddress.isEmpty()

        if (isZcashWallet) {
            iconView.setImageResource(R.drawable.ic_zcash)
        } else {
            iconView.setImageResource(R.drawable.ic_solana)
        }
    }

    private fun updateVisibleTokens(wallet: Wallet?) {
        // Determine wallet chain type
        val isZcashWallet = wallet?.let {
            (!it.zcashUnifiedAddress.isNullOrEmpty() || !it.zcashAddress.isNullOrEmpty()) && it.solanaAddress.isEmpty()
        } ?: false

        // Find token items in the layout
        val solTokenItem = findViewById<View>(R.id.solBalance)?.parent?.parent as? LinearLayout
        val zecTokenItem = findViewById<View>(R.id.zecBalance)?.parent?.parent as? LinearLayout

        // Show/hide tokens based on wallet type
        if (isZcashWallet) {
            // Zcash wallet - show only ZEC token
            solTokenItem?.visibility = View.GONE
            zecTokenItem?.visibility = View.VISIBLE
        } else {
            // Solana wallet - show only SOL token
            solTokenItem?.visibility = View.VISIBLE
            zecTokenItem?.visibility = View.GONE
        }
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                // Get current wallet to determine initial chain selection
                val currentWallet = wallets.maxByOrNull { it.lastUsedAt }

                withContext(Dispatchers.Main) {
                    // Create bottom sheet dialog
                    val bottomSheet = BottomSheetDialog(this@WalletActivity)
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

                    // Get UI elements
                    val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)
                    val solanaChainButton = view.findViewById<View>(R.id.solanaChainButton)
                    val zcashChainButton = view.findViewById<View>(R.id.zcashChainButton)

                    // Determine initial chain selection based on current wallet
                    val isCurrentZcash = currentWallet?.let {
                        !it.zcashUnifiedAddress.isNullOrEmpty() || !it.zcashAddress.isNullOrEmpty()
                    } ?: false
                    var selectedChain = if (isCurrentZcash) "ZCASH" else "SOLANA"

                    // Function to update chain button states
                    fun updateChainButtons() {
                        if (selectedChain == "SOLANA") {
                            solanaChainButton.alpha = 1.0f
                            zcashChainButton.alpha = 0.5f
                        } else {
                            solanaChainButton.alpha = 0.5f
                            zcashChainButton.alpha = 1.0f
                        }
                    }

                    // Function to populate wallet list based on selected chain
                    fun populateWalletList() {
                        walletListContainer.removeAllViews()

                        // Filter wallets by selected chain
                        val filteredWallets = wallets.filter { wallet ->
                            when (selectedChain) {
                                "SOLANA" -> wallet.solanaAddress.isNotEmpty()
                                "ZCASH" -> !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                                else -> false
                            }
                        }

                        for (wallet in filteredWallets) {
                            val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                            val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                            val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
                            val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

                            walletName.text = wallet.name
                            walletBalance.text = "$0.00" // Will be updated with actual balance

                            // Click on wallet item to switch (and set active if Zcash)
                            walletItemView.setOnClickListener {
                                val isZcashWallet = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                                if (isZcashWallet) {
                                    // For Zcash wallets, set as active and switch
                                    setActiveZcashWallet(wallet.walletId)
                                } else {
                                    // For non-Zcash wallets, just switch
                                    switchToWallet(wallet)
                                }
                                bottomSheet.dismiss()
                            }

                            // Click on settings button
                            settingsBtn.setOnClickListener {
                                val intent = Intent(this@WalletActivity, WalletSettingsActivity::class.java)
                                intent.putExtra("WALLET_ID", wallet.walletId)
                                intent.putExtra("WALLET_NAME", wallet.name)
                                intent.putExtra("IS_MAIN_WALLET", wallet.walletId == "main")
                                startActivity(intent)
                                bottomSheet.dismiss()
                            }

                            walletListContainer.addView(walletItemView)
                        }
                    }

                    // Chain button click handlers
                    solanaChainButton.setOnClickListener {
                        selectedChain = "SOLANA"
                        updateChainButtons()
                        populateWalletList()
                    }

                    zcashChainButton.setOnClickListener {
                        selectedChain = "ZCASH"
                        updateChainButtons()
                        populateWalletList()
                    }

                    // Initialize chain buttons and wallet list
                    updateChainButtons()
                    populateWalletList()

                    bottomSheet.show()
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun switchToWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("WalletActivity", "Switching to wallet: ${wallet.name}")

                // Update last used timestamp
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                withContext(Dispatchers.Main) {
                    // Update wallet name
                    val walletNameText = findViewById<TextView>(R.id.walletNameText)
                    walletNameText?.text = wallet.name

                    // Update chain icon based on wallet type
                    val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)
                    updateChainIcon(walletChainIcon, wallet)

                    // Update visible tokens based on wallet type
                    updateVisibleTokens(wallet)

                    // Reload balance for the new wallet
                    loadWalletBalance()
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to switch wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Failed to switch wallet")
                }
            }
        }
    }

    private fun setActiveZcashWallet(walletId: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("WalletActivity", "Setting active Zcash wallet: $walletId")

                // Get wallet from database
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val wallet = database.walletDao().getWalletById(walletId)

                if (wallet == null) {
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@WalletActivity, "Wallet not found")
                    }
                    return@launch
                }

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Activating Zcash wallet...")
                }

                // Call ZcashService to set active wallet
                val zcashService = ZcashService.getInstance(this@WalletActivity)
                val result = zcashService.setActiveZcashWallet(walletId)

                if (result.isSuccess) {
                    Log.i("WalletActivity", "Successfully set active Zcash wallet: $walletId")

                    // Update last used timestamp
                    database.walletDao().updateLastUsed(walletId, System.currentTimeMillis())

                    withContext(Dispatchers.Main) {
                        // Update wallet name
                        val walletNameText = findViewById<TextView>(R.id.walletNameText)
                        walletNameText?.text = wallet.name

                        // Update chain icon based on wallet type
                        val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)
                        updateChainIcon(walletChainIcon, wallet)

                        ThemedToast.show(this@WalletActivity, "Zcash wallet activated successfully!")
                        // Reload wallet balance for the active wallet
                        loadWalletBalance()
                    }
                } else {
                    Log.e("WalletActivity", "Failed to set active Zcash wallet", result.exceptionOrNull())
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@WalletActivity, "Failed to activate Zcash wallet: ${result.exceptionOrNull()?.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Error setting active Zcash wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Error: ${e.message}")
                }
            }
        }
    }

    private fun openWalletSettings() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    val intent = Intent(this@WalletActivity, WalletSettingsActivity::class.java)

                    if (wallets.isNotEmpty()) {
                        // Get the most recently used wallet
                        val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                        if (currentWallet != null) {
                            intent.putExtra("WALLET_ID", currentWallet.walletId)
                            intent.putExtra("WALLET_NAME", currentWallet.name)
                            intent.putExtra("IS_MAIN_WALLET", currentWallet.walletId == "main")
                        }
                    }
                    // If no wallets, still open settings page with defaults
                    // so user can create or import a wallet

                    startActivity(intent)
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to open wallet settings", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Failed to open settings")
                }
            }
        }
    }
}
