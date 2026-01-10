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

    private var selectedCurrency = "SOL" // Default to Solana

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_import_wallet)

        setupUI()
        setupClickListeners()
    }

    private fun setupUI() {
        // Set initial currency to Solana
        updateCurrencyDisplay()
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Currency dropdown - toggle between SOL and ZEC
        findViewById<View>(R.id.currencyDropdown).setOnClickListener {
            if (selectedCurrency == "SOL") {
                selectedCurrency = "ZEC"
            } else {
                selectedCurrency = "SOL"
            }
            updateCurrencyDisplay()
        }

        // Import button
        findViewById<View>(R.id.importButton).setOnClickListener {
            importWallet()
        }
    }

    private fun updateCurrencyDisplay() {
        val currencyIcon = findViewById<ImageView>(R.id.selectedCurrencyIcon)
        val currencyName = findViewById<TextView>(R.id.selectedCurrencyName)
        val currencySymbol = findViewById<TextView>(R.id.selectedCurrencySymbol)

        when (selectedCurrency) {
            "SOL" -> {
                currencyIcon.setImageResource(R.drawable.ic_solana)
                currencyName.text = "Solana"
                currencySymbol.text = "SOL"
            }
            "ZEC" -> {
                currencyIcon.setImageResource(R.drawable.ic_zcash)
                currencyName.text = "Zcash"
                currencySymbol.text = "ZEC"
            }
        }
    }

    private fun importWallet() {
        val walletName = findViewById<EditText>(R.id.walletNameInput).text.toString().trim()
        val privateKeyOrSeed = findViewById<EditText>(R.id.privateKeyInput).text.toString().trim()

        // Validate inputs
        if (walletName.isEmpty()) {
            ThemedToast.show(this, "Please enter a wallet name")
            return
        }

        if (privateKeyOrSeed.isEmpty()) {
            ThemedToast.show(this, "Please enter a private key or seed phrase")
            return
        }

        // Disable button during import
        val importButton = findViewById<View>(R.id.importButton)
        importButton.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("ImportWallet", "Importing $selectedCurrency wallet: $walletName")

                when (selectedCurrency) {
                    "SOL" -> importSolanaWallet(walletName, privateKeyOrSeed)
                    "ZEC" -> importZcashWallet(walletName, privateKeyOrSeed)
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

            // Try to import as seed phrase (12 words) or private key (base58 string)
            val words = privateKeyOrSeed.split("\\s+".toRegex())

            val imported = if (words.size == 12) {
                // Import from seed phrase
                Log.d("ImportWallet", "Importing Solana wallet from 12-word seed phrase")
                keyManager.importWalletFromSeed(walletId, privateKeyOrSeed)
            } else {
                // Import from private key
                Log.d("ImportWallet", "Importing Solana wallet from private key")
                keyManager.importSolanaWalletFromPrivateKey(walletId, privateKeyOrSeed)
            }

            if (!imported) {
                withContext(Dispatchers.Main) {
                    ThemedToast.showLong(this@ImportWalletActivity, "Failed to import Solana wallet. Invalid key or seed phrase.")
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

    private suspend fun importZcashWallet(walletName: String, privateKeyOrSeed: String) {
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
                zcashBirthdayHeight = null, // TODO: Could ask user or use current height
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
                    birthdayHeight = null
                )
            }

            Log.i("ImportWallet", "Zcash wallet imported successfully: $walletId")
            if (zcashUnifiedAddress != null) {
                Log.i("ImportWallet", "Derived UA: ${zcashUnifiedAddress.take(20)}...")
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
