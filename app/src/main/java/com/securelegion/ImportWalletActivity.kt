package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ImportWalletActivity : AppCompatActivity() {

    private var selectedChain = "SOLANA" // Default to Solana
    private var solanaImportType = "SEED_PHRASE" // Default to seed phrase for Solana

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_import_wallet)

        setupUI()
        setupClickListeners()
    }

    private fun setupUI() {
        // Set initial chain to Solana
        updateChainSelection()
        updateSolanaImportTypeSelection()
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Chain selector buttons
        findViewById<View>(R.id.solanaChainButton).setOnClickListener {
            selectedChain = "SOLANA"
            updateChainSelection()
        }

        findViewById<View>(R.id.zcashChainButton).setOnClickListener {
            selectedChain = "ZCASH"
            updateChainSelection()
        }

        // Solana import type buttons
        findViewById<View>(R.id.seedPhraseTypeButton).setOnClickListener {
            solanaImportType = "SEED_PHRASE"
            updateSolanaImportTypeSelection()
        }

        findViewById<View>(R.id.privateKeyTypeButton).setOnClickListener {
            solanaImportType = "PRIVATE_KEY"
            updateSolanaImportTypeSelection()
        }

        // Import button
        findViewById<View>(R.id.importButton).setOnClickListener {
            importWallet()
        }
    }

    private fun updateChainSelection() {
        val solanaButton = findViewById<View>(R.id.solanaChainButton)
        val zcashButton = findViewById<View>(R.id.zcashChainButton)

        val solanaImportTypeContainer = findViewById<View>(R.id.solanaImportTypeContainer)
        val seedPhraseInputContainer = findViewById<View>(R.id.seedPhraseInputContainer)
        val privateKeyInputContainer = findViewById<View>(R.id.privateKeyInputContainer)
        val zcashSeedPhraseInputContainer = findViewById<View>(R.id.zcashSeedPhraseInputContainer)
        val zcashBirthdayContainer = findViewById<View>(R.id.zcashBirthdayContainer)

        // Get input fields for updating hints
        val seedPhraseInput = findViewById<EditText>(R.id.seedPhraseInput)
        val privateKeyInput = findViewById<EditText>(R.id.privateKeyInput)
        val zcashSeedPhraseInput = findViewById<EditText>(R.id.zcashSeedPhraseInput)

        when (selectedChain) {
            "SOLANA" -> {
                // Update button backgrounds
                solanaButton.setBackgroundResource(R.drawable.swap_button_bg)
                zcashButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)

                // Update hints for Solana
                seedPhraseInput.hint = "Enter 12 or 24-word seed phrase of Solana wallet"
                privateKeyInput.hint = "Base58 string or JSON array of Solana wallet"

                // Show Solana UI
                solanaImportTypeContainer.visibility = View.VISIBLE
                updateSolanaImportTypeSelection()

                // Hide Zcash UI
                zcashSeedPhraseInputContainer.visibility = View.GONE
                zcashBirthdayContainer.visibility = View.GONE
            }
            "ZCASH" -> {
                // Update button backgrounds
                solanaButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)
                zcashButton.setBackgroundResource(R.drawable.swap_button_bg)

                // Update hint for Zcash
                zcashSeedPhraseInput.hint = "Enter 24-word seed phrase of Zcash wallet"

                // Hide Solana UI
                solanaImportTypeContainer.visibility = View.GONE
                seedPhraseInputContainer.visibility = View.GONE
                privateKeyInputContainer.visibility = View.GONE

                // Show Zcash UI
                zcashSeedPhraseInputContainer.visibility = View.VISIBLE
                zcashBirthdayContainer.visibility = View.VISIBLE
            }
        }
    }

    private fun updateSolanaImportTypeSelection() {
        val seedPhraseButton = findViewById<View>(R.id.seedPhraseTypeButton)
        val privateKeyButton = findViewById<View>(R.id.privateKeyTypeButton)
        val seedPhraseInputContainer = findViewById<View>(R.id.seedPhraseInputContainer)
        val privateKeyInputContainer = findViewById<View>(R.id.privateKeyInputContainer)

        when (solanaImportType) {
            "SEED_PHRASE" -> {
                // Update button backgrounds
                seedPhraseButton.setBackgroundResource(R.drawable.swap_button_bg)
                privateKeyButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)

                // Show seed phrase input, hide private key input
                seedPhraseInputContainer.visibility = View.VISIBLE
                privateKeyInputContainer.visibility = View.GONE
            }
            "PRIVATE_KEY" -> {
                // Update button backgrounds
                seedPhraseButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)
                privateKeyButton.setBackgroundResource(R.drawable.swap_button_bg)

                // Hide seed phrase input, show private key input
                seedPhraseInputContainer.visibility = View.GONE
                privateKeyInputContainer.visibility = View.VISIBLE
            }
        }
    }

    private fun importWallet() {
        val walletName = findViewById<EditText>(R.id.walletNameInput).text.toString().trim()

        // Validate wallet name
        if (walletName.isEmpty()) {
            ThemedToast.show(this, "Please enter a wallet name")
            return
        }

        // Get the appropriate input based on selected chain and type
        val privateKeyOrSeed: String
        var birthdayHeight: Long? = null

        when (selectedChain) {
            "SOLANA" -> {
                privateKeyOrSeed = if (solanaImportType == "SEED_PHRASE") {
                    findViewById<EditText>(R.id.seedPhraseInput).text.toString().trim()
                } else {
                    findViewById<EditText>(R.id.privateKeyInput).text.toString().trim()
                }
            }
            "ZCASH" -> {
                privateKeyOrSeed = findViewById<EditText>(R.id.zcashSeedPhraseInput).text.toString().trim()

                // Get birthday height if provided
                val birthdayHeightStr = findViewById<EditText>(R.id.birthdayHeightInput).text.toString().trim()
                birthdayHeight = if (birthdayHeightStr.isNotEmpty()) {
                    try {
                        birthdayHeightStr.toLong()
                    } catch (e: NumberFormatException) {
                        ThemedToast.show(this, "Invalid birthday height")
                        return
                    }
                } else {
                    null // Will use current height
                }
            }
            else -> {
                privateKeyOrSeed = ""
            }
        }

        // Validate input
        if (privateKeyOrSeed.isEmpty()) {
            ThemedToast.show(this, "Please enter a private key or seed phrase")
            return
        }

        // Disable button during import
        val importButton = findViewById<View>(R.id.importButton)
        importButton.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("ImportWallet", "Importing $selectedChain wallet: $walletName")

                when (selectedChain) {
                    "SOLANA" -> importSolanaWallet(walletName, privateKeyOrSeed)
                    "ZCASH" -> importZcashWallet(walletName, privateKeyOrSeed, birthdayHeight)
                }

            } catch (e: Exception) {
                Log.e("ImportWallet", "Failed to import wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.showLong(this@ImportWalletActivity, "Import failed: ${e.message}")
                    importButton.isEnabled = true
                }
            }
        }
    }

    private suspend fun importSolanaWallet(walletName: String, privateKeyOrSeed: String) {
        try {
            val keyManager = KeyManager.getInstance(this@ImportWalletActivity)

            // Generate a unique wallet ID
            val walletId = "sol_${System.currentTimeMillis()}"

            // Try to import as seed phrase (12 or 24 words) or private key (base58 string)
            val words = privateKeyOrSeed.split("\\s+".toRegex())

            val imported = if (words.size == 12 || words.size == 24) {
                // Import from seed phrase
                Log.d("ImportWallet", "Importing Solana wallet from ${words.size}-word seed phrase")
                keyManager.importWalletFromSeed(walletId, privateKeyOrSeed)
            } else {
                // Import from private key
                Log.d("ImportWallet", "Importing Solana wallet from private key")
                keyManager.importSolanaWalletFromPrivateKey(walletId, privateKeyOrSeed)
            }

            if (!imported) {
                withContext(Dispatchers.Main) {
                    val errorMsg = if (words.size == 12 || words.size == 24) {
                        "Invalid seed phrase. Please check that all ${words.size} words are correct."
                    } else {
                        "Invalid private key. Accepted formats:\n• Base58 string\n• JSON array [1,2,3,...]"
                    }
                    ThemedToast.showLong(this@ImportWalletActivity, errorMsg)
                    findViewById<View>(R.id.importButton).isEnabled = true
                }
                return
            }

            // Save wallet to database
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@ImportWalletActivity, dbPassphrase)

            // Get Solana address for the imported wallet
            val solanaAddress = keyManager.getWalletSolanaAddress(walletId)

            val wallet = Wallet(
                walletId = walletId,
                name = walletName,
                solanaAddress = solanaAddress,
                isMainWallet = false,
                createdAt = System.currentTimeMillis(),
                lastUsedAt = System.currentTimeMillis()
            )

            database.walletDao().insertWallet(wallet)

            Log.i("ImportWallet", "Solana wallet imported successfully: $walletId")

            withContext(Dispatchers.Main) {
                ThemedToast.show(this@ImportWalletActivity, "Wallet imported successfully!")
                finish()
            }

        } catch (e: Exception) {
            Log.e("ImportWallet", "Error importing Solana wallet", e)
            withContext(Dispatchers.Main) {
                ThemedToast.showLong(this@ImportWalletActivity, "Error: ${e.message}")
                findViewById<View>(R.id.importButton).isEnabled = true
            }
        }
    }

    private suspend fun importZcashWallet(walletName: String, privateKeyOrSeed: String, birthdayHeight: Long?) {
        try {
            val keyManager = KeyManager.getInstance(this@ImportWalletActivity)

            // Generate a unique wallet ID
            val walletId = "zec_${System.currentTimeMillis()}"

            // Try to import as seed phrase (12 or 24 words)
            val words = privateKeyOrSeed.split("\\s+".toRegex())

            val imported = if (words.size == 12 || words.size == 24) {
                // Import from seed phrase
                Log.d("ImportWallet", "Importing Zcash wallet from ${words.size}-word seed phrase")
                keyManager.importWalletFromSeed(walletId, privateKeyOrSeed)
            } else {
                // Zcash private key import (WIF format)
                Log.d("ImportWallet", "Importing Zcash wallet from private key")
                keyManager.importZcashWalletFromPrivateKey(walletId, privateKeyOrSeed)
            }

            if (!imported) {
                withContext(Dispatchers.Main) {
                    ThemedToast.showLong(this@ImportWalletActivity, "Failed to import Zcash wallet. Invalid key or seed phrase.")
                    findViewById<View>(R.id.importButton).isEnabled = true
                }
                return
            }

            // Save wallet to database
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@ImportWalletActivity, dbPassphrase)

            // Derive Zcash unified address for THIS wallet's seed
            val zcashUnifiedAddress = if (words.size == 12 || words.size == 24) {
                try {
                    com.securelegion.utils.ZcashAddressDeriver.deriveUnifiedAddressFromSeed(
                        seedPhrase = privateKeyOrSeed,
                        network = cash.z.ecc.android.sdk.model.ZcashNetwork.Mainnet,
                        accountIndex = 0
                    )
                } catch (e: Exception) {
                    Log.e("ImportWallet", "Failed to derive Zcash UA", e)
                    null
                }
            } else {
                // For private key import (WIF), address derivation not supported yet
                Log.w("ImportWallet", "Cannot derive UA from WIF private key - will need to sync with ZcashService")
                null
            }

            val wallet = Wallet(
                walletId = walletId,
                name = walletName,
                solanaAddress = "",
                zcashUnifiedAddress = zcashUnifiedAddress,
                zcashAccountIndex = 0,
                zcashBirthdayHeight = birthdayHeight, // Use provided birthday height or null for current height
                isActiveZcash = false, // Don't auto-activate imported wallet
                isMainWallet = false,
                createdAt = System.currentTimeMillis(),
                lastUsedAt = System.currentTimeMillis()
            )

            database.walletDao().insertWallet(wallet)

            // Update Zcash derived info in DB
            if (zcashUnifiedAddress != null) {
                database.walletDao().updateZcashDerivedInfo(
                    walletId = walletId,
                    ua = zcashUnifiedAddress,
                    accountIndex = 0,
                    birthdayHeight = birthdayHeight
                )
            }

            Log.i("ImportWallet", "Zcash wallet imported successfully: $walletId")
            if (zcashUnifiedAddress != null) {
                Log.i("ImportWallet", "Derived UA: ${zcashUnifiedAddress.take(20)}...")
            }
            if (birthdayHeight != null) {
                Log.i("ImportWallet", "Birthday height: $birthdayHeight")
            }

            withContext(Dispatchers.Main) {
                ThemedToast.show(this@ImportWalletActivity, "Wallet imported successfully!")
                finish()
            }

        } catch (e: Exception) {
            Log.e("ImportWallet", "Error importing Zcash wallet", e)
            withContext(Dispatchers.Main) {
                ThemedToast.showLong(this@ImportWalletActivity, "Error: ${e.message}")
                findViewById<View>(R.id.importButton).isEnabled = true
            }
        }
    }
}
