package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
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
        setContentView(R.layout.activity_wallet)

        setupUI()
        loadWalletBalance()
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

        // Swap button
        findViewById<View>(R.id.swapButton).setOnClickListener {
            ThemedToast.show(this, "Swap feature coming soon")
        }

        // Wallet settings button
        findViewById<View>(R.id.walletSettingsButton).setOnClickListener {
            val intent = Intent(this, WalletSettingsActivity::class.java)
            startActivity(intent)
        }

        // Bottom navigation
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            // Already on wallet page, do nothing
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
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
    }

    private var isBalanceVisible = true
    private var isShowingUSD = true

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
        val currencyLabel = findViewById<TextView>(R.id.currencyLabel)

        if (isShowingUSD) {
            currencyLabel?.text = "USD"
        } else {
            currencyLabel?.text = "SOL"
        }

        // Reload balance with new currency
        loadWalletBalance()
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

                // Get wallet address
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val solanaAddress = keyManager.getSolanaAddress()

                Log.d("WalletActivity", "Fetching balance for address: $solanaAddress")

                // Fetch SOL balance
                val solanaService = SolanaService(this@WalletActivity)
                val result = solanaService.getBalance(solanaAddress)

                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        val balanceSOL = result.getOrNull() ?: 0.0

                        // Display based on currency preference
                        if (isShowingUSD) {
                            // Fetch SOL price and calculate USD value
                            lifecycleScope.launch {
                                val priceResult = solanaService.getSolPrice()
                                if (priceResult.isSuccess) {
                                    val priceUSD = priceResult.getOrNull() ?: 0.0
                                    val balanceUSDValue = balanceSOL * priceUSD
                                    withContext(Dispatchers.Main) {
                                        balanceText?.text = String.format("$%,.2f", balanceUSDValue)
                                        solBalanceText?.text = String.format("$%.2f", balanceUSDValue)
                                    }
                                } else {
                                    withContext(Dispatchers.Main) {
                                        balanceText?.text = "$0.00"
                                        solBalanceText?.text = "$0.00"
                                    }
                                }
                            }
                        } else {
                            // Show SOL amount
                            balanceText?.text = String.format("%.4f", balanceSOL)
                            solBalanceText?.text = String.format("%.4f SOL", balanceSOL)
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

            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load wallet balance", e)
                withContext(Dispatchers.Main) {
                    val balanceText = findViewById<TextView>(R.id.balanceAmount)
                    balanceText?.text = "$0"
                }
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

    private fun loadCurrentWalletName() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val wallets = database.walletDao().getAllWallets()

                withContext(Dispatchers.Main) {
                    val walletNameText = findViewById<TextView>(R.id.walletNameText)
                    if (wallets.isNotEmpty()) {
                        // Get the most recently used wallet
                        val currentWallet = wallets.firstOrNull()
                        walletNameText?.text = currentWallet?.name ?: "Wallet 1"
                    } else {
                        walletNameText?.text = "Wallet 1"
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletActivity", "Failed to load current wallet name", e)
                withContext(Dispatchers.Main) {
                    val walletNameText = findViewById<TextView>(R.id.walletNameText)
                    walletNameText?.text = "Wallet 1"
                }
            }
        }
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletActivity, dbPassphrase)
                val wallets = database.walletDao().getAllWallets()

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletActivity, "No wallets found")
                        return@withContext
                    }

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

                    // Get container for wallet list
                    val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)

                    // Add each wallet to the list
                    for (wallet in wallets) {
                        val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                        val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                        val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
                        val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

                        walletName.text = wallet.name
                        walletBalance.text = "Loading..." // TODO: Load actual balance

                        // Click on wallet item to switch
                        walletItemView.setOnClickListener {
                            switchToWallet(wallet)
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
}
