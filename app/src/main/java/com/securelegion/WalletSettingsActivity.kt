package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WalletSettingsActivity : AppCompatActivity() {

    private var selectedChain: String = "SOLANA" // Default to Solana
    private var currentWallet: Wallet? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wallet_settings)

        Log.d("WalletSettings", "Wallet Settings opened")

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        setupChainButtons()
        setupClickListeners()
        loadCurrentWallet()
    }

    private fun setupChainButtons() {
        val solanaButton = findViewById<View>(R.id.solanaChainButton)
        val zcashButton = findViewById<View>(R.id.zcashChainButton)

        // Initially select Solana
        updateChainSelection()

        solanaButton.setOnClickListener {
            selectedChain = "SOLANA"
            updateChainSelection()
            Log.d("WalletSettings", "Selected chain: Solana")
        }

        zcashButton.setOnClickListener {
            selectedChain = "ZCASH"
            updateChainSelection()
            Log.d("WalletSettings", "Selected chain: Zcash")
        }
    }

    private fun updateChainSelection() {
        val solanaButton = findViewById<View>(R.id.solanaChainButton)
        val zcashButton = findViewById<View>(R.id.zcashChainButton)

        if (selectedChain == "SOLANA") {
            solanaButton.alpha = 1.0f
            zcashButton.alpha = 0.5f
        } else {
            solanaButton.alpha = 0.5f
            zcashButton.alpha = 1.0f
        }
    }

    private fun setupClickListeners() {
        // Wallet selector box click
        findViewById<View>(R.id.currentWalletSelector).setOnClickListener {
            showWalletSelector()
        }

        // Create New Wallet button
        findViewById<View>(R.id.createWalletButton).setOnClickListener {
            val intent = Intent(this, CreateWalletActivity::class.java)
            intent.putExtra("SELECTED_CHAIN", selectedChain)
            startActivity(intent)
        }

        // Import Wallet button
        findViewById<View>(R.id.importWalletButton).setOnClickListener {
            val intent = Intent(this, ImportWalletActivity::class.java)
            intent.putExtra("SELECTED_CHAIN", selectedChain)
            startActivity(intent)
        }

        // Export Key button - export current wallet directly
        findViewById<View>(R.id.exportKeyButton).setOnClickListener {
            exportCurrentWallet()
        }

        // Delete Wallet button - shows wallet selector filtered by chain
        findViewById<View>(R.id.deleteWalletButton).setOnClickListener {
            showWalletSelectorForDelete()
        }
    }

    private fun loadCurrentWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()
                val wallets = allWallets.filter { it.walletId != "main" }

                // Get most recently used wallet
                val wallet = wallets.maxByOrNull { it.lastUsedAt }

                withContext(Dispatchers.Main) {
                    if (wallet != null) {
                        currentWallet = wallet
                        updateCurrentWalletDisplay()

                        // Auto-select chain based on wallet type
                        val isZcashWallet = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                        selectedChain = if (isZcashWallet) "ZCASH" else "SOLANA"
                        updateChainSelection()
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to load current wallet", e)
            }
        }
    }

    private fun updateCurrentWalletDisplay() {
        val wallet = currentWallet ?: return

        val walletName = findViewById<TextView>(R.id.currentWalletName)
        val walletBalance = findViewById<TextView>(R.id.currentWalletBalance)
        val walletIcon = findViewById<ImageView>(R.id.currentWalletIcon)

        walletName.text = wallet.name

        // Show address preview
        val address = if (!wallet.zcashUnifiedAddress.isNullOrEmpty()) {
            wallet.zcashUnifiedAddress
        } else if (!wallet.zcashAddress.isNullOrEmpty()) {
            wallet.zcashAddress
        } else {
            wallet.solanaAddress
        }

        val addressPreview = if (address.length > 15) {
            "${address.take(6)}...${address.takeLast(6)}"
        } else {
            address
        }
        walletBalance.text = addressPreview

        // Update icon based on wallet type
        val isZcashWallet = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
        if (isZcashWallet) {
            walletIcon.setImageResource(R.drawable.ic_zcash)
        } else {
            walletIcon.setImageResource(R.drawable.ic_solana)
        }
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter by selected chain
                val wallets = allWallets.filter { wallet ->
                    wallet.walletId != "main" && when (selectedChain) {
                        "SOLANA" -> wallet.solanaAddress.isNotEmpty()
                        "ZCASH" -> !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                        else -> false
                    }
                }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletSettingsActivity, "No $selectedChain wallets found")
                        return@withContext
                    }

                    showWalletSelectorBottomSheet(wallets) { wallet ->
                        // Update current wallet and set as active
                        currentWallet = wallet
                        updateCurrentWalletDisplay()

                        // Update database to set as active
                        lifecycleScope.launch(Dispatchers.IO) {
                            try {
                                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())
                            } catch (e: Exception) {
                                Log.e("WalletSettings", "Failed to update wallet", e)
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun exportCurrentWallet() {
        val wallet = currentWallet
        if (wallet == null) {
            ThemedToast.show(this, "No wallet selected")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val seedPhrase = keyManager.getWalletSeedPhrase(wallet.walletId)

                if (seedPhrase != null) {
                    withContext(Dispatchers.Main) {
                        showExportKeyBottomSheet(seedPhrase)
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@WalletSettingsActivity, "Wallet seed not found")
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to export wallet key", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to export key")
                }
            }
        }
    }

    private fun showWalletSelectorForDelete() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter by selected chain
                val wallets = allWallets.filter { wallet ->
                    wallet.walletId != "main" && when (selectedChain) {
                        "SOLANA" -> wallet.solanaAddress.isNotEmpty()
                        "ZCASH" -> !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                        else -> false
                    }
                }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletSettingsActivity, "No $selectedChain wallets found")
                        return@withContext
                    }

                    showWalletSelectorBottomSheet(wallets) { wallet ->
                        showDeleteConfirmation(wallet)
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun showWalletSelectorBottomSheet(wallets: List<Wallet>, onSelect: (Wallet) -> Unit) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)

        bottomSheet.setContentView(view)

        // Get container for wallet list
        val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)

        // Add each wallet to the list
        for (wallet in wallets) {
            val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

            val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
            val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
            val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

            walletName.text = wallet.name

            // Show address preview instead of balance
            val address = if (!wallet.zcashUnifiedAddress.isNullOrEmpty()) {
                wallet.zcashUnifiedAddress
            } else if (!wallet.zcashAddress.isNullOrEmpty()) {
                wallet.zcashAddress
            } else {
                wallet.solanaAddress
            }

            val addressPreview = if (address.length > 15) {
                "${address.take(6)}...${address.takeLast(6)}"
            } else {
                address
            }
            walletBalance.text = addressPreview

            // Hide settings button since we're selecting
            settingsBtn.visibility = View.GONE

            // Click on wallet item to select it
            walletItemView.setOnClickListener {
                onSelect(wallet)
                bottomSheet.dismiss()
            }

            walletListContainer.addView(walletItemView)
        }

        bottomSheet.show()
    }

    private fun showExportKeyBottomSheet(seedPhrase: String) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_private_key, null)

        val keyText = view.findViewById<TextView>(R.id.seedPhraseText)
        keyText.text = seedPhrase

        view.findViewById<View>(R.id.copyButton).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Seed Phrase", seedPhrase)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Seed phrase copied to clipboard")
            bottomSheet.dismiss()
        }

        view.findViewById<View>(R.id.closeButton).setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.setContentView(view)
        bottomSheet.setCancelable(true)
        bottomSheet.show()
    }

    private fun showDeleteConfirmation(wallet: Wallet) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_delete_wallet, null)

        view.findViewById<TextView>(R.id.walletNameText).text = wallet.name

        // Show address preview
        val address = if (!wallet.zcashUnifiedAddress.isNullOrEmpty()) {
            wallet.zcashUnifiedAddress
        } else if (!wallet.zcashAddress.isNullOrEmpty()) {
            wallet.zcashAddress
        } else {
            wallet.solanaAddress
        }
        val addressPreview = if (address.length > 15) {
            "${address.take(6)}...${address.takeLast(6)}"
        } else {
            address
        }
        view.findViewById<TextView>(R.id.walletAddressText).text = addressPreview

        val confirmCheckbox = view.findViewById<CheckBox>(R.id.confirmCheckbox)
        val deleteButton = view.findViewById<View>(R.id.deleteButton)

        // Enable delete button only when checkbox is checked
        confirmCheckbox.setOnCheckedChangeListener { _, isChecked ->
            deleteButton.isEnabled = isChecked
            deleteButton.alpha = if (isChecked) 1.0f else 0.5f
        }

        deleteButton.setOnClickListener {
            if (confirmCheckbox.isChecked) {
                deleteWallet(wallet)
                bottomSheet.dismiss()
            } else {
                ThemedToast.show(this, "Please confirm deletion")
            }
        }

        view.findViewById<View>(R.id.cancelButton).setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.setContentView(view)
        bottomSheet.setCancelable(true)
        bottomSheet.show()
    }

    private fun deleteWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)

                database.walletDao().deleteWallet(wallet)
                Log.i("WalletSettings", "Deleted wallet: ${wallet.name}")

                // Reload current wallet after deletion
                val allWallets = database.walletDao().getAllWallets()
                val wallets = allWallets.filter { it.walletId != "main" }
                val newCurrentWallet = wallets.maxByOrNull { it.lastUsedAt }

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Wallet deleted")

                    // Update display with new current wallet
                    if (newCurrentWallet != null) {
                        currentWallet = newCurrentWallet
                        updateCurrentWalletDisplay()

                        // Update selected chain to match new wallet
                        val isZcashWallet = !newCurrentWallet.zcashUnifiedAddress.isNullOrEmpty() ||
                                           !newCurrentWallet.zcashAddress.isNullOrEmpty()
                        selectedChain = if (isZcashWallet) "ZCASH" else "SOLANA"
                        updateChainSelection()
                    } else {
                        // No wallets left
                        currentWallet = null
                        findViewById<TextView>(R.id.currentWalletName).text = "No wallet"
                        findViewById<TextView>(R.id.currentWalletBalance).text = ""
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to delete wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to delete wallet")
                }
            }
        }
    }
}
