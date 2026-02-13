package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.services.ShadowWireService
import com.securelegion.services.SolanaService
import com.securelegion.services.ZcashService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WalletActivity : AppCompatActivity() {
    private lateinit var swipeRefreshLayout: SwipeRefreshLayout

    // Aggressive balance auto-refresh polling
    private val balanceRefreshHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private var balanceRefreshRunnable: Runnable? = null
    private companion object {
        const val BALANCE_REFRESH_INTERVAL_MS = 10_000L // 10 seconds
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wallet)

        // Enable edge-to-edge and handle system bar insets (matches MainActivity)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val rootView = findViewById<View>(android.R.id.content)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        ViewCompat.setOnApplyWindowInsetsListener(rootView) { _, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout()
            )
            bottomNav.setPadding(
                bottomNav.paddingLeft,
                bottomNav.paddingTop,
                bottomNav.paddingRight,
                insets.bottom
            )
            windowInsets
        }

        setupUI()
        if (BuildConfig.ENABLE_ZCASH_WALLET) {
            ensureZcashInitialized()
        }

        // Load cached balances immediately for instant display
        loadCachedBalances()

        // Then load fresh balances in background
        loadWalletBalance()
    }

    override fun onResume() {
        super.onResume()
        // Auto-refresh balance when returning to wallet screen
        loadWalletBalance()
        // Start aggressive periodic balance polling
        startBalancePolling()
    }

    override fun onPause() {
        super.onPause()
        // Stop polling when screen is not visible
        stopBalancePolling()
    }

    private fun startBalancePolling() {
        stopBalancePolling() // Clear any existing callbacks
        balanceRefreshRunnable = object : Runnable {
            override fun run() {
                if (!isFinishing && !isDestroyed) {
                    loadWalletBalance()
                    balanceRefreshHandler.postDelayed(this, BALANCE_REFRESH_INTERVAL_MS)
                }
            }
        }
        balanceRefreshHandler.postDelayed(balanceRefreshRunnable!!, BALANCE_REFRESH_INTERVAL_MS)
    }

    private fun stopBalancePolling() {
        balanceRefreshRunnable?.let { balanceRefreshHandler.removeCallbacks(it) }
        balanceRefreshRunnable = null
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
        // Setup pull-to-refresh
        swipeRefreshLayout = findViewById(R.id.swipeRefreshLayout)
        swipeRefreshLayout.setOnRefreshListener {
            loadWalletBalance()
        }
        // Set refresh indicator colors to match app theme
        swipeRefreshLayout.setColorSchemeColors(0xFF6BA4FF.toInt(), 0xFF4CAF50.toInt())
        swipeRefreshLayout.setProgressBackgroundColorSchemeColor(0xFF1A1A1A.toInt())

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Send button - shows token selector first
        findViewById<View>(R.id.sendButton).setOnClickListener {
            showTokenSelector()
        }

        // Receive button
        findViewById<View>(R.id.receiveButton).setOnClickListener {
            val intent = Intent(this, ReceiveActivity::class.java)
            startActivity(intent)
        }

        // Shield/Private button
        findViewById<View>(R.id.shieldButton)?.setOnClickListener {
            handleShieldOrPrivateAction()
        }

        // Solana shielded card — opens ShadowWire privacy pool
        findViewById<View>(R.id.solShieldedItem)?.setOnClickListener {
            handleShieldOrPrivateAction()
        }

        // Wallet settings button
        findViewById<View>(R.id.walletSettingsButton).setOnClickListener {
            openWalletSettings()
        }

        // Bottom navigation
        findViewById<View>(R.id.navMessages)?.setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAccounts)?.setOnClickListener {
            showWalletSelector()
        }

        findViewById<View>(R.id.navNewWallet)?.setOnClickListener {
            lifecycleScope.launch(Dispatchers.IO) {
                val chain = try {
                    val keyManager = KeyManager.getInstance(this@WalletActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                    val wallets = database.walletDao().getAllWallets().filter { it.walletId != "main" }
                    val current = wallets.maxByOrNull { it.lastUsedAt }
                    if (!current?.zcashUnifiedAddress.isNullOrEmpty() || !current?.zcashAddress.isNullOrEmpty()) "ZCASH" else "SOLANA"
                } catch (e: Exception) {
                    "SOLANA"
                }
                withContext(Dispatchers.Main) {
                    val intent = Intent(this@WalletActivity, CreateWalletActivity::class.java)
                    intent.putExtra("SELECTED_CHAIN", chain)
                    startActivity(intent)
                }
            }
        }

        findViewById<View>(R.id.navRecent)?.setOnClickListener {
            // Pass current wallet info to Recent Activity
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val keyManager = KeyManager.getInstance(this@WalletActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                    val allWallets = database.walletDao().getAllWallets()
                    val wallets = allWallets.filter { it.walletId != "main" }
                    val currentWallet = wallets.maxByOrNull { it.lastUsedAt }

                    withContext(Dispatchers.Main) {
                        val intent = Intent(this@WalletActivity, RecentTransactionsActivity::class.java)
                        if (currentWallet != null) {
                            intent.putExtra("WALLET_ID", currentWallet.walletId)
                            intent.putExtra("WALLET_NAME", currentWallet.name)
                            intent.putExtra("WALLET_ADDRESS", currentWallet.solanaAddress)
                            intent.putExtra("WALLET_ZCASH_ADDRESS", currentWallet.zcashAddress ?: currentWallet.zcashUnifiedAddress)
                        }
                        startActivity(intent)
                    }
                } catch (e: Exception) {
                    Log.e("WalletActivity", "Failed to get current wallet for Recent Activity", e)
                    withContext(Dispatchers.Main) {
                        // Fallback: launch without wallet info
                        val intent = Intent(this@WalletActivity, RecentTransactionsActivity::class.java)
                        startActivity(intent)
                    }
                }
            }
        }

        // Load current wallet name into header
        loadCurrentWalletName()

        // Toggle currency button - switch between USD and native token display
        findViewById<View>(R.id.toggleCurrency)?.setOnClickListener {
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

        // Set initial currency label
        updateCurrencyLabel()
    }

    private var isBalanceVisible = true
    private var isShowingUSD = true
    private var walletBalanceSOL = 0.0
    private var poolBalanceSOL = 0.0

    private fun handleShieldOrPrivateAction() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()
                val wallets = allWallets.filter { it.walletId != "main" }
                val currentWallet = wallets.maxByOrNull { it.lastUsedAt }

                // Check if this is a Zcash wallet
                val isZcashWallet = !currentWallet?.zcashUnifiedAddress.isNullOrEmpty() || !currentWallet?.zcashAddress.isNullOrEmpty()

                withContext(Dispatchers.Main) {
                    if (isZcashWallet) {
                        // Zcash wallet - proceed with shielding
                        shieldTransparentFunds()
                    } else {
                        // Solana wallet - open ShadowWire privacy pool if enabled
                        if (BuildConfig.ENABLE_SHADOW_WIRE) {
                            startActivity(android.content.Intent(this@WalletActivity, ShadowWireActivity::class.java).apply {
                                putExtra("WALLET_ID", currentWallet?.walletId ?: "main")
                            })
                        } else {
                            ThemedToast.show(this@WalletActivity, "Coming soon")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to determine wallet type", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Coming soon")
                }
            }
        }
    }

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

    private fun updateMainBalanceDisplay() {
        val balanceText = findViewById<TextView>(R.id.balanceAmount)
        val totalSOL = walletBalanceSOL + poolBalanceSOL
        val solPrice = getCachedPrice("SOL")
        Log.d("WalletActivity", "updateMainBalanceDisplay: wallet=$walletBalanceSOL + pool=$poolBalanceSOL = $totalSOL SOL, price=$solPrice")

        if (isShowingUSD && solPrice > 0) {
            balanceText?.text = String.format("$%,.2f", totalSOL * solPrice)
        } else {
            balanceText?.text = String.format("%.4f", totalSOL)
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

    private fun loadCachedBalances() {
        val prefs = getSharedPreferences("wallet_prices", MODE_PRIVATE)

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()
                val wallets = allWallets.filter { it.walletId != "main" }

                // Prefer Solana wallet on initial load
                val solanaWallets = wallets.filter { it.solanaAddress.isNotEmpty() }
                val currentWallet = if (solanaWallets.isNotEmpty()) {
                    solanaWallets.maxByOrNull { it.lastUsedAt }
                } else {
                    wallets.maxByOrNull { it.lastUsedAt }
                }
                val walletId = currentWallet?.walletId ?: "main"

                val solBalance = prefs.getFloat("${walletId}_SOL_balance", 0f).toDouble()
                val zecBalance = prefs.getFloat("${walletId}_ZEC_balance", 0f).toDouble()
                val solPrice = prefs.getFloat("SOL_price", 0f).toDouble()
                val zecPrice = prefs.getFloat("ZEC_price", 0f).toDouble()

                withContext(Dispatchers.Main) {
                    val balanceText = findViewById<TextView>(R.id.balanceAmount)
                    val solBalanceText = findViewById<TextView>(R.id.solBalance)
                    val solAmountText = findViewById<TextView>(R.id.solAmount)
                    val zecBalanceText = findViewById<TextView>(R.id.zecBalance)
                    val zecAmountText = findViewById<TextView>(R.id.zecAmount)

                    if (solBalance > 0) {
                        val solUSD = solBalance * solPrice
                        solBalanceText?.text = String.format("$%.2f", solUSD)
                        solAmountText?.text = String.format("%.4f SOL", solBalance)
                        Log.d("WalletActivity", "Loaded cached SOL balance: $solBalance ($$solUSD)")
                    }

                    if (zecBalance > 0) {
                        val zecUSD = zecBalance * zecPrice
                        zecBalanceText?.text = String.format("$%.2f", zecUSD)
                        zecAmountText?.text = String.format("%.4f ZEC", zecBalance)
                        Log.d("WalletActivity", "Loaded cached ZEC balance: $zecBalance ($$zecUSD)")
                    }

                    // Always show SOL balance as main display on initial load
                    if (solBalance > 0) {
                        if (isShowingUSD && solPrice > 0) {
                            balanceText?.text = String.format("$%,.2f", solBalance * solPrice)
                        } else {
                            balanceText?.text = String.format("%.4f SOL", solBalance)
                        }
                    } else if (zecBalance > 0) {
                        if (isShowingUSD && zecPrice > 0) {
                            balanceText?.text = String.format("$%,.2f", zecBalance * zecPrice)
                        } else {
                            balanceText?.text = String.format("%.4f ZEC", zecBalance)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load cached balances", e)
            }
        }
    }

    private fun saveBalanceToCache(walletId: String, currency: String, balance: Double) {
        val prefs = getSharedPreferences("wallet_prices", MODE_PRIVATE)
        val key = "${walletId}_${currency}_balance"
        prefs.edit().putFloat(key, balance.toFloat()).apply()
        Log.d("WalletActivity", "Saved balance to cache: $key = $balance")
    }

    private fun savePriceToCache(currency: String, price: Double) {
        val prefs = getSharedPreferences("wallet_prices", MODE_PRIVATE)
        val key = "${currency}_price"
        prefs.edit().putFloat(key, price.toFloat()).apply()
        Log.d("WalletActivity", "Saved price to cache: $key = $price")
    }

    private fun getCachedPrice(currency: String): Double {
        val prefs = getSharedPreferences("wallet_prices", MODE_PRIVATE)
        return prefs.getFloat("${currency}_price", 0f).toDouble()
    }

    private fun loadWalletBalance() {
        // Don't load if balance is hidden
        if (!isBalanceVisible) {
            swipeRefreshLayout.isRefreshing = false
            return
        }

        lifecycleScope.launch {
            try {
                Log.d("WalletActivity", "Loading wallet balance")

                val balanceText = findViewById<TextView>(R.id.balanceAmount)
                val solBalanceText = findViewById<TextView>(R.id.solBalance)
                val solAmountText = findViewById<TextView>(R.id.solAmount)
                val zecBalanceText = findViewById<TextView>(R.id.zecBalance)
                val zecAmountText = findViewById<TextView>(R.id.zecAmount)

                // Determine wallet type from database
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()
                val wallets = allWallets.filter { it.walletId != "main" }

                // Prefer Solana wallet on initial load
                val solanaWallets = wallets.filter { it.solanaAddress.isNotEmpty() }
                val currentWallet = if (solanaWallets.isNotEmpty()) {
                    solanaWallets.maxByOrNull { it.lastUsedAt }
                } else {
                    wallets.maxByOrNull { it.lastUsedAt }
                }

                // Check if this is a Zcash-only wallet (no Solana address)
                val isZcashWallet = currentWallet?.solanaAddress.isNullOrEmpty() &&
                    (!currentWallet?.zcashUnifiedAddress.isNullOrEmpty() || !currentWallet?.zcashAddress.isNullOrEmpty())

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
                        walletBalanceSOL = balanceSOL
                        Log.d("WalletActivity", "SOL balance: $balanceSOL, solBalanceText view exists: ${solBalanceText != null}")

                        // Save balance to cache
                        val walletId = currentWallet?.walletId ?: "main"
                        saveBalanceToCache(walletId, "SOL", balanceSOL)

                        // Display based on currency preference
                        if (isShowingUSD) {
                            // Fetch SOL price and calculate USD value
                            lifecycleScope.launch {
                                val priceResult = solanaService.getSolPrice()
                                if (priceResult.isSuccess) {
                                    val priceUSD = priceResult.getOrNull() ?: 0.0
                                    savePriceToCache("SOL", priceUSD)
                                    val balanceUSDValue = balanceSOL * priceUSD
                                    Log.d("WalletActivity", "Setting SOL USD: $balanceUSDValue (${balanceSOL} * ${priceUSD})")
                                    withContext(Dispatchers.Main) {
                                        solBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                        solAmountText?.text = String.format("%.4f SOL", balanceSOL)
                                        updateMainBalanceDisplay()
                                        Log.d("WalletActivity", "Set solBalanceText to: ${solBalanceText?.text}")
                                    }
                                } else {
                                    Log.e("WalletActivity", "Failed to get SOL price - keeping cached values")
                                    // Don't overwrite with zero - keep showing cached/stale data
                                    // Only update if we have a cached price
                                    val cachedPrice = getCachedPrice("SOL")
                                    if (cachedPrice > 0) {
                                        val balanceUSDValue = balanceSOL * cachedPrice
                                        withContext(Dispatchers.Main) {
                                            solBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                            solAmountText?.text = String.format("%.4f SOL", balanceSOL)
                                            updateMainBalanceDisplay()
                                        }
                                    }
                                }
                            }
                        } else {
                            // Show SOL amount
                            Log.d("WalletActivity", "Setting SOL amount: $balanceSOL SOL")
                            solBalanceText?.text = String.format("%.4f SOL", balanceSOL)
                            solAmountText?.text = String.format("%.4f SOL", balanceSOL)
                            updateMainBalanceDisplay()
                            Log.d("WalletActivity", "Set solBalanceText to: ${solBalanceText?.text}")
                        }

                        Log.i("WalletActivity", "Balance loaded successfully")
                    } else {
                        // Balance fetch failed - keep showing cached values, don't flash to zero
                        Log.e("WalletActivity", "Failed to load balance: ${result.exceptionOrNull()?.message} - keeping cached values")
                        // walletBalanceSOL remains unchanged (keeps previous value)
                    }
                }

                    // Load Zcash balance
                    loadZcashBalance()
                }

                // Load shielded balances
                loadShieldedBalance(currentWallet)

                // Stop refresh indicator
                withContext(Dispatchers.Main) {
                    swipeRefreshLayout.isRefreshing = false
                }

            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load wallet balance: ${e.message} - keeping cached values")
                // Don't overwrite with zero on error - keep showing cached/stale data
                withContext(Dispatchers.Main) {
                    swipeRefreshLayout.isRefreshing = false
                }
            }
        }
    }

    private suspend fun loadShieldedBalance(wallet: Wallet?) {
        val isZcashWallet = wallet?.let {
            !it.zcashUnifiedAddress.isNullOrEmpty() || !it.zcashAddress.isNullOrEmpty()
        } ?: false

        Log.d("WalletActivity", "loadShieldedBalance: isZcash=$isZcashWallet, shadowWire=${BuildConfig.ENABLE_SHADOW_WIRE}, wallet=${wallet?.walletId}")

        if (!isZcashWallet && BuildConfig.ENABLE_SHADOW_WIRE) {
            // Solana wallet — load ShadowWire pool balance
            try {
                val walletId = wallet?.walletId ?: "main"
                Log.d("WalletActivity", "Loading pool balance for walletId: $walletId")
                val shadowWireService = ShadowWireService(this@WalletActivity, walletId)
                val result = withContext(Dispatchers.IO) {
                    shadowWireService.getPoolBalance()
                }
                val solPrice = getCachedPrice("SOL")
                Log.d("WalletActivity", "Pool result: success=${result.isSuccess}, solPrice=$solPrice")

                withContext(Dispatchers.Main) {
                    val shieldedBalanceText = findViewById<TextView>(R.id.solShieldedBalance)
                    val shieldedAmountText = findViewById<TextView>(R.id.solShieldedAmount)

                    if (result.isSuccess) {
                        val poolBalance = result.getOrNull()
                        val available = poolBalance?.available ?: 0.0
                        poolBalanceSOL = available
                        Log.d("WalletActivity", "Pool available: $available SOL")

                        if (isShowingUSD) {
                            val usdValue = available * solPrice
                            shieldedBalanceText?.text = String.format("$%,.2f", usdValue)
                            shieldedAmountText?.text = String.format("%.4f SOL", available)
                        } else {
                            shieldedBalanceText?.text = String.format("%.4f", available)
                            shieldedAmountText?.text = String.format("%.4f SOL", available)
                        }
                    } else {
                        // Pool balance failed - keep existing display, don't flash to zero
                        Log.e("WalletActivity", "Pool balance failed: ${result.exceptionOrNull()?.message} - keeping cached values")
                    }

                    // Update main balance to include pool balance
                    updateMainBalanceDisplay()
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load shielded SOL balance", e)
            }
        } else if (isZcashWallet) {
            // Zcash wallet — load shielded balance from breakdown
            try {
                val zcashService = ZcashService.getInstance(this@WalletActivity)
                val breakdownResult = withContext(Dispatchers.IO) {
                    zcashService.getBalanceBreakdown()
                }
                val zecPrice = getCachedPrice("ZEC")

                withContext(Dispatchers.Main) {
                    val shieldedBalanceText = findViewById<TextView>(R.id.zecShieldedBalance)
                    val shieldedAmountText = findViewById<TextView>(R.id.zecShieldedAmount)

                    if (breakdownResult.isSuccess) {
                        val breakdown = breakdownResult.getOrNull()
                        val shieldedZEC = breakdown?.shieldedZEC ?: 0.0

                        if (isShowingUSD) {
                            val usdValue = shieldedZEC * zecPrice
                            shieldedBalanceText?.text = String.format("$%,.2f", usdValue)
                            shieldedAmountText?.text = String.format("%.4f ZEC", shieldedZEC)
                        } else {
                            shieldedBalanceText?.text = String.format("%.4f", shieldedZEC)
                            shieldedAmountText?.text = String.format("%.4f ZEC", shieldedZEC)
                        }
                    } else {
                        // Shielded ZEC breakdown failed - keep existing display
                        Log.w("WalletActivity", "Shielded ZEC breakdown failed - keeping cached values")
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load shielded ZEC balance - keeping cached values", e)
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

            if (zcashAddress == null) {
                Log.w("WalletActivity", "Zcash address not available - keeping cached values")
                // Don't overwrite with zero - keep cached values
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
                val zecAmountText = findViewById<TextView>(R.id.zecAmount)

                if (balanceResult.isSuccess) {
                    val balanceZEC = balanceResult.getOrNull() ?: 0.0

                    // Don't show any debug messages
                    Log.i("WalletActivity", "Successfully loaded ZEC balance: $balanceZEC ZEC")

                    // Save balance to cache
                    lifecycleScope.launch(Dispatchers.IO) {
                        val dbPassphrase = keyManager.getDatabasePassphrase()
                        val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                        val allWallets = database.walletDao().getAllWallets()
                        val wallets = allWallets.filter { it.walletId != "main" }
                        val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                        val walletId = currentWallet?.walletId ?: "main"
                        saveBalanceToCache(walletId, "ZEC", balanceZEC)
                    }

                    // Fetch ZEC price and calculate USD value
                    lifecycleScope.launch {
                        val priceResult = zcashService.getZecPrice()
                        if (priceResult.isSuccess) {
                            val priceUSD = priceResult.getOrNull() ?: 0.0
                            savePriceToCache("ZEC", priceUSD)
                            if (priceUSD > 0) {
                                val balanceUSDValue = balanceZEC * priceUSD

                                withContext(Dispatchers.Main) {
                                    if (isShowingUSD) {
                                        // Show USD value in main display
                                        balanceText?.text = String.format("$%,.2f", balanceUSDValue)
                                        zecBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                        zecAmountText?.text = String.format("%.4f ZEC", balanceZEC)
                                    } else {
                                        // Show ZEC amount in main display
                                        balanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                        zecBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                        zecAmountText?.text = String.format("%.4f ZEC", balanceZEC)
                                    }
                                }
                            } else {
                                // Price fetch failed - use cached price or show ZEC amount
                                Log.w("WalletActivity", "ZEC price fetch failed - using cached price")
                                val cachedPrice = getCachedPrice("ZEC")
                                withContext(Dispatchers.Main) {
                                    if (isShowingUSD && cachedPrice > 0) {
                                        val cachedUsdValue = balanceZEC * cachedPrice
                                        balanceText?.text = String.format("$%.2f", cachedUsdValue)
                                        zecBalanceText?.text = String.format("$%.2f", cachedUsdValue)
                                    } else {
                                        balanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                        zecBalanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                    }
                                    zecAmountText?.text = String.format("%.4f ZEC", balanceZEC)
                                }
                            }
                        } else {
                            // Price fetch failed - use cached price or show ZEC amount
                            Log.w("WalletActivity", "ZEC price fetch failed - using cached price")
                            val cachedPrice = getCachedPrice("ZEC")
                            withContext(Dispatchers.Main) {
                                if (isShowingUSD && cachedPrice > 0) {
                                    val cachedUsdValue = balanceZEC * cachedPrice
                                    balanceText?.text = String.format("$%.2f", cachedUsdValue)
                                    zecBalanceText?.text = String.format("$%.2f", cachedUsdValue)
                                } else {
                                    balanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                    zecBalanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                }
                                zecAmountText?.text = String.format("%.4f ZEC", balanceZEC)
                            }
                        }
                    }
                } else {
                    // Balance fetch failed - keep cached values
                    val errorMsg = balanceResult.exceptionOrNull()?.message ?: "Unknown error"
                    Log.e("WalletActivity", "Failed to load ZEC balance: $errorMsg - keeping cached values")
                }
            }

        } catch (e: Exception) {
            Log.e("WalletActivity", "Failed to load Zcash balance as main", e)
        }
    }

    private suspend fun loadZcashBalance() {
        try {
            Log.d("WalletActivity", "Loading Zcash balance")

            val keyManager = KeyManager.getInstance(this@WalletActivity)
            val zcashAddress = keyManager.getZcashAddress()

            if (zcashAddress == null) {
                Log.w("WalletActivity", "Zcash address not available - keeping cached values")
                // Don't overwrite with zero - keep cached values
                return
            }

            val zcashService = ZcashService.getInstance(this@WalletActivity)
            val balanceResult = zcashService.getBalance()

            withContext(Dispatchers.Main) {
                val zecBalanceText = findViewById<TextView>(R.id.zecBalance)
                val zecAmountText = findViewById<TextView>(R.id.zecAmount)

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
                                    zecAmountText?.text = String.format("%.4f ZEC", balanceZEC)
                                }
                            } else {
                                // Price fetch failed - use cached price
                                Log.w("WalletActivity", "ZEC price fetch failed - using cached")
                                val cachedPrice = getCachedPrice("ZEC")
                                withContext(Dispatchers.Main) {
                                    if (cachedPrice > 0) {
                                        zecBalanceText?.text = String.format("$%.2f", balanceZEC * cachedPrice)
                                    } else {
                                        zecBalanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                    }
                                    zecAmountText?.text = String.format("%.4f ZEC", balanceZEC)
                                }
                            }
                        } else {
                            // Price fetch failed - use cached price
                            Log.w("WalletActivity", "ZEC price fetch failed - using cached")
                            val cachedPrice = getCachedPrice("ZEC")
                            withContext(Dispatchers.Main) {
                                if (cachedPrice > 0) {
                                    zecBalanceText?.text = String.format("$%.2f", balanceZEC * cachedPrice)
                                } else {
                                    zecBalanceText?.text = String.format("%.4f ZEC", balanceZEC)
                                }
                                zecAmountText?.text = String.format("%.4f ZEC", balanceZEC)
                            }
                        }
                    }
                } else {
                    // Balance fetch failed - keep cached values
                    Log.e("WalletActivity", "Failed to load ZEC balance: ${balanceResult.exceptionOrNull()?.message} - keeping cached")
                }
            }

        } catch (e: Exception) {
            Log.e("WalletActivity", "Failed to load Zcash balance - keeping cached", e)
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
                Log.w("WalletActivity", "Solana address not available - keeping cached values")
                // Don't overwrite with zero - keep cached values
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
                                // Price is zero - use cached price
                                val cachedPrice = getCachedPrice("SOL")
                                if (cachedPrice > 0) {
                                    withContext(Dispatchers.Main) {
                                        solBalanceText?.text = String.format("$%.2f", balanceSOL * cachedPrice)
                                    }
                                }
                                // else keep existing display
                            }
                        } else {
                            Log.e("WalletActivity", "Failed to get SOL price (side) - using cached")
                            val cachedPrice = getCachedPrice("SOL")
                            if (cachedPrice > 0) {
                                withContext(Dispatchers.Main) {
                                    solBalanceText?.text = String.format("$%.2f", balanceSOL * cachedPrice)
                                }
                            }
                            // else keep existing display
                        }
                    }
                } else {
                    // Balance fetch failed - keep cached values
                    Log.e("WalletActivity", "Failed to load SOL balance (side): ${balanceResult.exceptionOrNull()?.message} - keeping cached")
                }
            }

        } catch (e: Exception) {
            Log.e("WalletActivity", "Failed to load Solana balance (side) - keeping cached", e)
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
                    val walletTitle = findViewById<TextView>(R.id.walletTitle)
                    val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)
                    val shieldButtonLabel = findViewById<TextView>(R.id.shieldButtonLabel)

                    if (wallets.isNotEmpty()) {
                        // Prefer a Solana wallet on initial load, then fall back to most recently used
                        val solanaWallets = wallets.filter { it.solanaAddress.isNotEmpty() }
                        val currentWallet = if (solanaWallets.isNotEmpty()) {
                            solanaWallets.maxByOrNull { it.lastUsedAt }
                        } else {
                            wallets.maxByOrNull { it.lastUsedAt }
                        }
                        walletTitle?.text = currentWallet?.name ?: "Wallet"

                        // Update chain icon based on wallet type
                        updateChainIcon(walletChainIcon, currentWallet)

                        // Update shield button label - Solana wallet gets "Private"
                        shieldButtonLabel?.text = "Private"

                        // Update visible tokens - show Solana tokens first
                        updateVisibleTokens(currentWallet)
                    } else {
                        walletTitle?.text = "Wallet"
                        walletChainIcon?.setImageResource(R.drawable.ic_solana)
                        shieldButtonLabel?.text = "Private"

                        // Show Solana tokens by default
                        updateVisibleTokens(null)
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load current wallet name", e)
                withContext(Dispatchers.Main) {
                    val walletTitle = findViewById<TextView>(R.id.walletTitle)
                    walletTitle?.text = "Wallet"
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
        // Determine wallet chain type - if it has a Zcash address, it's a Zcash wallet
        val isZcashWallet = wallet?.let {
            !it.zcashUnifiedAddress.isNullOrEmpty() || !it.zcashAddress.isNullOrEmpty()
        } ?: false

        // Find token items in the layout
        val solTokenItem = findViewById<View>(R.id.solBalance)?.parent?.parent as? LinearLayout
        val zecTokenItem = findViewById<View>(R.id.zecBalance)?.parent?.parent as? LinearLayout
        val solShieldedItem = findViewById<View>(R.id.solShieldedItem)
        val zecShieldedItem = findViewById<View>(R.id.zecShieldedItem)

        Log.d("WalletActivity", "Updating visible tokens - isZcashWallet: $isZcashWallet, wallet: ${wallet?.name}")

        // Show/hide tokens based on wallet type
        if (isZcashWallet) {
            // Zcash wallet - show only ZEC token + ZEC shielded
            solTokenItem?.visibility = View.GONE
            zecTokenItem?.visibility = View.VISIBLE
            solShieldedItem?.visibility = View.GONE
            zecShieldedItem?.visibility = View.VISIBLE
            Log.d("WalletActivity", "Showing ZEC token, hiding SOL token")
        } else {
            // Solana wallet - show only SOL token + SOL shielded (if enabled)
            solTokenItem?.visibility = View.VISIBLE
            zecTokenItem?.visibility = View.GONE
            solShieldedItem?.visibility = if (BuildConfig.ENABLE_SHADOW_WIRE) View.VISIBLE else View.GONE
            zecShieldedItem?.visibility = View.GONE
            Log.d("WalletActivity", "Showing SOL token, hiding ZEC token")
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
                var wallets = allWallets.filter { it.walletId != "main" }.toMutableList()

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

                    // Track if we're currently showing initialization message
                    var isShowingInitializing = false
                    var initializingStartTime = 0L

                    // Handler for auto-refresh polling
                    val handler = android.os.Handler(android.os.Looper.getMainLooper())
                    var pollRunnable: Runnable? = null

                    // Function to update chain button states
                    fun updateChainButtons() {
                        if (selectedChain == "SOLANA") {
                            solanaChainButton.setBackgroundResource(R.drawable.swap_button_bg)
                            zcashChainButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)
                        } else {
                            solanaChainButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)
                            zcashChainButton.setBackgroundResource(R.drawable.swap_button_bg)
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

                        // If no wallets exist for this chain, check if Zcash is still initializing
                        if (filteredWallets.isEmpty()) {
                            // Check if Zcash is still initializing (only for ZCASH chain)
                            val isZcashInitializing = if (selectedChain == "ZCASH") {
                                val zcashPrefs = getSharedPreferences("zcash_init", MODE_PRIVATE)
                                zcashPrefs.getBoolean("initializing", false)
                            } else {
                                false
                            }

                            val createWalletView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                            val walletName = createWalletView.findViewById<TextView>(R.id.walletName)
                            val walletBalance = createWalletView.findViewById<TextView>(R.id.walletBalance)
                            val settingsBtn = createWalletView.findViewById<View>(R.id.walletSettingsBtn)

                            if (isZcashInitializing) {
                                walletName.text = "Initializing Zcash Wallet..."
                                walletBalance.text = "Please wait, this may take a moment"
                                settingsBtn.visibility = View.GONE
                                createWalletView.isClickable = false
                                createWalletView.alpha = 0.7f
                                isShowingInitializing = true
                                initializingStartTime = System.currentTimeMillis()
                            } else {
                                isShowingInitializing = false
                                initializingStartTime = 0L
                                walletName.text = "Create $selectedChain Wallet"
                                walletBalance.text = "Tap to create new wallet"
                                settingsBtn.visibility = View.GONE

                                createWalletView.setOnClickListener {
                                    val intent = Intent(this@WalletActivity, CreateWalletActivity::class.java)
                                    intent.putExtra("SELECTED_CHAIN", selectedChain)
                                    startActivity(intent)
                                    bottomSheet.dismiss()
                                }
                            }

                            walletListContainer.addView(createWalletView)
                            return
                        }

                        val showingUsdMap = mutableMapOf<String, Boolean>()

                        for (wallet in filteredWallets) {
                            val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                            val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                            val walletBalanceView = walletItemView.findViewById<TextView>(R.id.walletBalance)
                            val toggleBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)
                            val walletIcon = walletItemView.findViewById<ImageView>(R.id.walletIcon)

                            walletName.text = wallet.name
                            showingUsdMap[wallet.walletId] = true

                            // Set chain-specific icon
                            val isZcashWallet = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                            if (isZcashWallet) {
                                walletIcon.setImageResource(R.drawable.ic_zcash)
                            } else {
                                walletIcon.setImageResource(R.drawable.ic_solana)
                            }

                            // Load balance async
                            walletBalanceView.text = "Loading..."
                            lifecycleScope.launch {
                                try {
                                    val balance: Double
                                    val price: Double
                                    val symbol: String
                                    if (isZcashWallet) {
                                        val zcashService = com.securelegion.services.ZcashService.getInstance(this@WalletActivity)
                                        val balResult = zcashService.getBalance()
                                        balance = balResult.getOrDefault(0.0)
                                        price = getCachedPrice("ZEC")
                                        symbol = "ZEC"
                                    } else {
                                        val solanaService = com.securelegion.services.SolanaService(this@WalletActivity)
                                        val balResult = solanaService.getBalance(wallet.solanaAddress)
                                        balance = balResult.getOrDefault(0.0)
                                        price = getCachedPrice("SOL")
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

                            // Click on wallet item to switch (and set active if Zcash)
                            walletItemView.setOnClickListener {
                                val isZcash = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                                if (isZcash) {
                                    setActiveZcashWallet(wallet.walletId)
                                } else {
                                    switchToWallet(wallet)
                                }
                                bottomSheet.dismiss()
                            }

                            walletListContainer.addView(walletItemView)
                        }
                    }

                    // Chain button click handlers
                    solanaChainButton.setOnClickListener {
                        selectedChain = "SOLANA"
                        updateChainButtons()
                        pollRunnable?.let { handler.removeCallbacks(it) } // Stop polling
                        populateWalletList()
                    }

                    zcashChainButton.setOnClickListener {
                        selectedChain = "ZCASH"
                        updateChainButtons()
                        pollRunnable?.let { handler.removeCallbacks(it) } // Stop any existing polling
                        populateWalletList()
                        // Start polling if showing initialization message
                        if (isShowingInitializing) {
                            handler.postDelayed(pollRunnable!!, 2000)
                        }
                    }

                    // Initialize chain buttons and wallet list
                    updateChainButtons()
                    populateWalletList()

                    // Setup polling to auto-refresh when Zcash is initializing
                    pollRunnable = object : Runnable {
                        override fun run() {
                            if (isShowingInitializing && selectedChain == "ZCASH") {
                                // Check if initialization is complete
                                val zcashPrefs = getSharedPreferences("zcash_init", MODE_PRIVATE)
                                val stillInitializing = zcashPrefs.getBoolean("initializing", false)

                                if (!stillInitializing) {
                                    // Initialization complete! Reload wallets from database
                                    lifecycleScope.launch(Dispatchers.IO) {
                                        try {
                                            val keyManager = KeyManager.getInstance(this@WalletActivity)
                                            val dbPassphrase = keyManager.getDatabasePassphrase()
                                            val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                                            val allWallets = database.walletDao().getAllWallets()
                                            val updatedWallets = allWallets.filter { it.walletId != "main" }

                                            withContext(Dispatchers.Main) {
                                                // Update wallets list and refresh UI
                                                wallets.clear()
                                                wallets.addAll(updatedWallets)
                                                populateWalletList()
                                                Log.i("WalletActivity", "Auto-refreshed wallet list - Zcash initialization complete")
                                            }
                                        } catch (e: Exception) {
                                            Log.e("WalletActivity", "Failed to reload wallets during polling", e)
                                        }
                                    }
                                } else {
                                    // Still initializing, check again in 2 seconds
                                    handler.postDelayed(this, 2000)
                                }
                            }
                        }
                    }

                    // Start polling if showing initialization message
                    if (isShowingInitializing) {
                        handler.postDelayed(pollRunnable!!, 2000)
                    }

                    // Stop polling when bottom sheet is dismissed
                    bottomSheet.setOnDismissListener {
                        pollRunnable?.let { handler.removeCallbacks(it) }
                    }

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

                // Small delay to ensure database write completes before querying
                kotlinx.coroutines.delay(50)

                withContext(Dispatchers.Main) {
                    // Update wallet name in header
                    val walletTitle = findViewById<TextView>(R.id.walletTitle)
                    walletTitle?.text = wallet.name

                    // Update chain icon based on wallet type
                    val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)
                    updateChainIcon(walletChainIcon, wallet)

                    // Update shield button label based on wallet type
                    val shieldButtonLabel = findViewById<TextView>(R.id.shieldButtonLabel)
                    val isZcashWallet = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                    shieldButtonLabel?.text = if (isZcashWallet) "Shield" else "Private"

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
                    // Show loading overlay with Zcash initialization message
                    val walletTitle = findViewById<TextView>(R.id.walletTitle)
                    walletTitle?.text = "Initializing..."

                    // Update to show Zcash icon immediately
                    val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)
                    walletChainIcon?.setImageResource(R.drawable.ic_zcash)
                }

                // Call ZcashService to set active wallet
                val zcashService = ZcashService.getInstance(this@WalletActivity)
                val result = zcashService.setActiveZcashWallet(walletId)

                if (result.isSuccess) {
                    Log.i("WalletActivity", "Successfully set active Zcash wallet: $walletId")

                    // Update last used timestamp
                    database.walletDao().updateLastUsed(walletId, System.currentTimeMillis())

                    // Small delay to ensure database write completes
                    kotlinx.coroutines.delay(50)

                    withContext(Dispatchers.Main) {
                        // Update wallet name in header
                        val walletTitle = findViewById<TextView>(R.id.walletTitle)
                        walletTitle?.text = wallet.name

                        // Update chain icon based on wallet type
                        val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)
                        updateChainIcon(walletChainIcon, wallet)

                        // Update shield button label
                        val shieldButtonLabel = findViewById<TextView>(R.id.shieldButtonLabel)
                        shieldButtonLabel?.text = "Shield"

                        // Update visible tokens based on wallet type
                        updateVisibleTokens(wallet)

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

    private fun showTokenSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletActivity, "No wallets found")
                        return@withContext
                    }

                    // Get the current wallet
                    val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                    if (currentWallet == null) {
                        ThemedToast.show(this@WalletActivity, "No wallet selected")
                        return@withContext
                    }

                    // Determine if this is a Zcash or Solana wallet
                    val isZcashWallet = !currentWallet.zcashUnifiedAddress.isNullOrEmpty() || !currentWallet.zcashAddress.isNullOrEmpty()

                    // Create bottom sheet dialog
                    val bottomSheet = BottomSheetDialog(this@WalletActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_token_selector, null)

                    // Set minimum height
                    val displayMetrics = resources.displayMetrics
                    val screenHeight = displayMetrics.heightPixels
                    val desiredHeight = (screenHeight * 0.5).toInt()
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

                    // Get token list container
                    val tokenListContainer = view.findViewById<LinearLayout>(R.id.tokenListContainer)

                    // Add token item based on wallet type
                    if (isZcashWallet) {
                        // Add Zcash token
                        addTokenItem(tokenListContainer, currentWallet, "ZEC", "Zcash", R.drawable.ic_zcash, bottomSheet)
                    } else {
                        // Add Solana token
                        addTokenItem(tokenListContainer, currentWallet, "SOL", "Solana", R.drawable.ic_solana, bottomSheet)
                    }

                    bottomSheet.show()
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to show token selector", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Failed to load tokens")
                }
            }
        }
    }

    private fun addTokenItem(
        container: LinearLayout,
        wallet: Wallet,
        tokenSymbol: String,
        tokenName: String,
        tokenIconRes: Int,
        bottomSheet: BottomSheetDialog
    ) {
        val tokenItemView = layoutInflater.inflate(R.layout.item_token_selector, container, false)

        val tokenIcon = tokenItemView.findViewById<ImageView>(R.id.tokenIcon)
        val tokenNameView = tokenItemView.findViewById<TextView>(R.id.tokenName)
        val tokenSymbolView = tokenItemView.findViewById<TextView>(R.id.tokenSymbol)
        val tokenBalance = tokenItemView.findViewById<TextView>(R.id.tokenBalance)

        // Set token info
        tokenIcon.setImageResource(tokenIconRes)
        tokenNameView.text = tokenName
        tokenSymbolView.text = tokenSymbol
        tokenBalance.text = "Loading..."

        // Load balance for the token
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val balance = when (tokenSymbol) {
                    "SOL" -> {
                        val solanaService = SolanaService(this@WalletActivity)
                        val result = solanaService.getBalance(wallet.solanaAddress)
                        result.getOrNull() ?: 0.0
                    }
                    "ZEC" -> {
                        val zcashService = ZcashService.getInstance(this@WalletActivity)
                        val result = zcashService.getBalance()
                        result.getOrNull() ?: 0.0
                    }
                    else -> 0.0
                }

                withContext(Dispatchers.Main) {
                    tokenBalance.text = String.format("%.4f", balance)
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load $tokenSymbol balance", e)
                withContext(Dispatchers.Main) {
                    tokenBalance.text = "0.0"
                }
            }
        }

        // Click on token item to open Send page with this token
        tokenItemView.setOnClickListener {
            val intent = Intent(this@WalletActivity, SendActivity::class.java)
            intent.putExtra("WALLET_ID", wallet.walletId)
            intent.putExtra("WALLET_NAME", wallet.name)
            intent.putExtra("TOKEN_SYMBOL", tokenSymbol)
            intent.putExtra("TOKEN_NAME", tokenName)

            // Pass the appropriate address based on token type
            if (tokenSymbol == "ZEC") {
                val address = wallet.zcashUnifiedAddress ?: wallet.zcashAddress ?: ""
                intent.putExtra("WALLET_ADDRESS", address)
            } else {
                intent.putExtra("WALLET_ADDRESS", wallet.solanaAddress)
            }

            startActivity(intent)
            bottomSheet.dismiss()
        }

        container.addView(tokenItemView)
    }
}
