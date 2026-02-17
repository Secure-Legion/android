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
import com.securelegion.utils.GlassBottomSheetDialog
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
                Log.d("WalletSettings", "Loading wallets...")
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()
                Log.d("WalletSettings", "Found ${allWallets.size} total wallets")

                // Filter out "main" wallet
                val wallets = allWallets.filter { it.walletId != "main" }
                Log.d("WalletSettings", "Found ${wallets.size} user wallets")

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletSettingsActivity, "No wallets found")
                        return@withContext
                    }

                    try {
                        Log.d("WalletSettings", "Showing wallet selector bottom sheet...")
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
                    } catch (e: Exception) {
                        Log.e("WalletSettings", "Failed to show bottom sheet", e)
                        ThemedToast.show(this@WalletSettingsActivity, "Failed to show wallet selector: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to load wallets: ${e.message}")
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

        val isZcashWallet = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)

                if (isZcashWallet) {
                    // For Zcash, only seed phrase available
                    val seedPhrase = keyManager.getWalletSeedPhrase(wallet.walletId)
                    if (seedPhrase != null) {
                        val birthdayHeight = wallet.zcashBirthdayHeight ?: 0
                        withContext(Dispatchers.Main) {
                            showExportZcashWalletBottomSheet(seedPhrase, birthdayHeight)
                        }
                    } else {
                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@WalletSettingsActivity, "Wallet seed not found")
                        }
                    }
                } else {
                    // For Solana, get both seed phrase and private key
                    val seedPhrase = keyManager.getWalletSeedPhrase(wallet.walletId)
                    val privateKeyBytes = keyManager.getWalletPrivateKey(wallet.walletId)
                    val privateKey = privateKeyBytes?.let {
                        // Export as Base58 (standard Solana format)
                        org.bitcoinj.core.Base58.encode(it)
                    }

                    withContext(Dispatchers.Main) {
                        if (seedPhrase != null && privateKey != null) {
                            showExportSolanaWalletBottomSheet(seedPhrase, privateKey)
                        } else {
                            ThemedToast.show(this@WalletSettingsActivity, "Failed to retrieve wallet credentials")
                        }
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
                Log.d("WalletSettings", "Loading wallets for delete...")
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletSettingsActivity, "No wallets found")
                        return@withContext
                    }

                    try {
                        showWalletSelectorBottomSheet(wallets) { wallet ->
                            showDeleteConfirmation(wallet)
                        }
                    } catch (e: Exception) {
                        Log.e("WalletSettings", "Failed to show bottom sheet for delete", e)
                        ThemedToast.show(this@WalletSettingsActivity, "Failed to show wallet selector: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to load wallets for delete", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to load wallets: ${e.message}")
                }
            }
        }
    }

    private fun showWalletSelectorBottomSheet(wallets: List<Wallet>, onSelect: (Wallet) -> Unit) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)

        bottomSheet.setContentView(view)

        // Get UI elements
        val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)
        val solanaChainButton = view.findViewById<View>(R.id.solanaChainButton)
        val zcashChainButton = view.findViewById<View>(R.id.zcashChainButton)

        // Track current selected chain
        var currentSelectedChain = selectedChain

        // Function to update chain button states
        fun updateChainButtons() {
            if (currentSelectedChain == "SOLANA") {
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

            // Filter wallets by current selected chain
            val filteredWallets = wallets.filter { wallet ->
                when (currentSelectedChain) {
                    "SOLANA" -> wallet.solanaAddress.isNotEmpty()
                    "ZCASH" -> !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                    else -> false
                }
            }

            // Add each wallet to the list
            for (wallet in filteredWallets) {
                val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
                val walletAddress = walletItemView.findViewById<TextView>(R.id.walletAddress)
                val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)
                val walletIcon = walletItemView.findViewById<ImageView>(R.id.walletIcon)

                walletName.text = wallet.name
                walletBalance.text = "Loading..."

                // Set chain-specific icon and address
                val isZcashWallet = !wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()
                if (isZcashWallet) {
                    walletIcon.setImageResource(R.drawable.ic_zcash)
                    val address = wallet.zcashUnifiedAddress ?: wallet.zcashAddress ?: ""
                    walletAddress?.text = if (address.length > 15) {
                        "${address.take(5)}.....${address.takeLast(6)}"
                    } else {
                        address
                    }
                } else {
                    walletIcon.setImageResource(R.drawable.ic_solana)
                    val address = wallet.solanaAddress
                    walletAddress?.text = if (address.length > 15) {
                        "${address.take(5)}.....${address.takeLast(6)}"
                    } else {
                        address
                    }
                }

                // Load balance for this wallet
                lifecycleScope.launch(Dispatchers.IO) {
                    try {
                        if (isZcashWallet) {
                            val zcashService = com.securelegion.services.ZcashService.getInstance(this@WalletSettingsActivity)
                            val balanceResult = zcashService.getBalance()

                            withContext(Dispatchers.Main) {
                                if (balanceResult.isSuccess) {
                                    val balance = balanceResult.getOrNull() ?: 0.0
                                    walletBalance.text = String.format("%.6f ZEC", balance).trimEnd('0').trimEnd('.')
                                } else {
                                    walletBalance.text = "0 ZEC"
                                }
                            }
                        } else {
                            val solanaService = com.securelegion.services.SolanaService(this@WalletSettingsActivity)
                            val balanceResult = solanaService.getBalance(wallet.solanaAddress)

                            withContext(Dispatchers.Main) {
                                if (balanceResult.isSuccess) {
                                    val balance = balanceResult.getOrNull() ?: 0.0
                                    walletBalance.text = String.format("%.6f SOL", balance).trimEnd('0').trimEnd('.')
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

                // Hide settings button since we're selecting
                settingsBtn.visibility = View.GONE

                // Click on wallet item to select it
                walletItemView.setOnClickListener {
                    onSelect(wallet)
                    bottomSheet.dismiss()
                }

                walletListContainer.addView(walletItemView)
            }
        }

        // Chain button click listeners
        solanaChainButton.setOnClickListener {
            currentSelectedChain = "SOLANA"
            updateChainButtons()
            populateWalletList()
        }

        zcashChainButton.setOnClickListener {
            currentSelectedChain = "ZCASH"
            updateChainButtons()
            populateWalletList()
        }

        // Initial population
        updateChainButtons()
        populateWalletList()

        bottomSheet.show()
    }

    private fun showExportSolanaWalletBottomSheet(seedPhrase: String, privateKey: String) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_private_key, null)

        // Get UI elements
        val keyText = view.findViewById<TextView>(R.id.seedPhraseText)
        val infoText = view.findViewById<TextView>(R.id.infoText)
        val walletAddressText = view.findViewById<TextView>(R.id.walletAddressText)
        val walletChainIcon = view.findViewById<ImageView>(R.id.walletChainIcon)
        val copyAddressIcon = view.findViewById<ImageView>(R.id.copyAddressIcon)
        val copySeedPhraseIcon = view.findViewById<ImageView>(R.id.copySeedPhraseIcon)
        val seedPhraseContainer = view.findViewById<View>(R.id.seedPhraseContainer)

        // Set chain icon
        walletChainIcon?.setImageResource(R.drawable.ic_solana)

        // Set wallet address preview
        val wallet = currentWallet
        val address = wallet?.solanaAddress ?: ""
        val addressPreview = if (address.length > 15) {
            "${address.take(6)}...${address.takeLast(6)}"
        } else {
            address
        }
        walletAddressText?.text = addressPreview

        // Copy address icon click
        copyAddressIcon?.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", address)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Wallet address copied to clipboard")
        }

        // Track current content (seed phrase or private key)
        var showingSeedPhrase = true
        var currentContent = seedPhrase

        // Set initial content
        keyText?.text = seedPhrase
        infoText?.text = "Your 12-word seed phrase:"

        // Get type selector buttons
        val seedPhraseButton = view.findViewById<View>(R.id.seedPhraseTypeButton)
        val privateKeyButton = view.findViewById<View>(R.id.privateKeyTypeButton)
        val exportTypeContainer = view.findViewById<View>(R.id.exportTypeContainer)

        // Show export type selector for Solana
        exportTypeContainer?.visibility = View.VISIBLE

        // Function to update button states
        fun updateTypeButtons() {
            if (showingSeedPhrase) {
                seedPhraseButton?.setBackgroundResource(R.drawable.swap_button_bg)
                privateKeyButton?.setBackgroundResource(R.drawable.wallet_dropdown_bg)
            } else {
                seedPhraseButton?.setBackgroundResource(R.drawable.wallet_dropdown_bg)
                privateKeyButton?.setBackgroundResource(R.drawable.swap_button_bg)
            }
        }

        // Initialize button states
        updateTypeButtons()

        // Seed Phrase button click
        seedPhraseButton?.setOnClickListener {
            if (!showingSeedPhrase) {
                showingSeedPhrase = true
                currentContent = seedPhrase
                keyText?.text = seedPhrase
                infoText?.text = "Your 12-word seed phrase:"
                updateTypeButtons()
            }
        }

        // Private Key button click
        privateKeyButton?.setOnClickListener {
            if (showingSeedPhrase) {
                showingSeedPhrase = false
                currentContent = privateKey
                keyText?.text = privateKey
                infoText?.text = "Your private key (Base58):"
                updateTypeButtons()
            }
        }

        // Copy icon click handler
        copySeedPhraseIcon?.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val label = if (showingSeedPhrase) "Seed Phrase" else "Private Key"
            val clip = ClipData.newPlainText(label, currentContent)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "$label copied to clipboard")
        }

        view.findViewById<View>(R.id.closeButton)?.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.setContentView(view)
        bottomSheet.setCancelable(true)
        bottomSheet.show()
    }

    private fun showExportZcashWalletBottomSheet(seedPhrase: String, birthdayHeight: Long) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_private_key, null)

        // Get UI elements
        val keyText = view.findViewById<TextView>(R.id.seedPhraseText)
        val infoText = view.findViewById<TextView>(R.id.infoText)
        val walletAddressText = view.findViewById<TextView>(R.id.walletAddressText)
        val walletChainIcon = view.findViewById<ImageView>(R.id.walletChainIcon)
        val copyAddressIcon = view.findViewById<ImageView>(R.id.copyAddressIcon)
        val copySeedPhraseIcon = view.findViewById<ImageView>(R.id.copySeedPhraseIcon)
        val birthdayHeightLabel = view.findViewById<TextView>(R.id.birthdayHeightLabel)
        val birthdayHeightContainer = view.findViewById<View>(R.id.birthdayHeightContainer)
        val birthdayHeightText = view.findViewById<TextView>(R.id.birthdayHeightText)
        val copyBirthdayHeightIcon = view.findViewById<ImageView>(R.id.copyBirthdayHeightIcon)

        // Set chain icon
        walletChainIcon?.setImageResource(R.drawable.ic_zcash)

        // Set wallet address preview
        val wallet = currentWallet
        val address = wallet?.zcashUnifiedAddress ?: wallet?.zcashAddress ?: ""
        val addressPreview = if (address.length > 15) {
            "${address.take(6)}...${address.takeLast(6)}"
        } else {
            address
        }
        walletAddressText?.text = addressPreview

        // Copy address icon click
        copyAddressIcon?.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", address)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Wallet address copied to clipboard")
        }

        // Set seed phrase
        keyText?.text = seedPhrase
        infoText?.text = "Your 24-word seed phrase:"

        // Copy seed phrase icon click
        copySeedPhraseIcon?.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Seed Phrase", seedPhrase)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Seed phrase copied to clipboard")
        }

        // Show birthday height section
        birthdayHeightLabel?.visibility = View.VISIBLE
        birthdayHeightContainer?.visibility = View.VISIBLE
        birthdayHeightText?.text = birthdayHeight.toString()

        // Copy birthday height icon click
        copyBirthdayHeightIcon?.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Birthday Height", birthdayHeight.toString())
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Birthday height copied to clipboard")
        }

        view.findViewById<View>(R.id.closeButton)?.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.setContentView(view)
        bottomSheet.setCancelable(true)
        bottomSheet.show()
    }

    private fun showDeleteConfirmation(wallet: Wallet) {
        val bottomSheet = GlassBottomSheetDialog(this)
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
