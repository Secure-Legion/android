package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
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

class CreateWalletActivity : AppCompatActivity() {

    private lateinit var walletNameInput: EditText
    private lateinit var solanaOption: View
    private lateinit var zcashOption: View
    private lateinit var solanaCheckbox: View
    private lateinit var zcashCheckbox: View

    private var selectedWalletType = "SOLANA" // Default to Solana

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_wallet)

        walletNameInput = findViewById(R.id.walletNameInput)
        solanaOption = findViewById(R.id.solanaOption)
        zcashOption = findViewById(R.id.zcashOption)
        solanaCheckbox = findViewById(R.id.solanaCheckbox)
        zcashCheckbox = findViewById(R.id.zcashCheckbox)

        setupClickListeners()
        setDefaultWalletName()
        updateWalletTypeSelection()
    }

    private fun setDefaultWalletName() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@CreateWalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@CreateWalletActivity, dbPassphrase)
                val walletCount = database.walletDao().getWalletCount()
                val defaultName = "Wallet ${walletCount + 1}"

                withContext(Dispatchers.Main) {
                    walletNameInput.setText(defaultName)
                }
            } catch (e: Exception) {
                Log.e("CreateWallet", "Failed to get wallet count", e)
            }
        }
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Solana option
        solanaOption.setOnClickListener {
            selectedWalletType = "SOLANA"
            updateWalletTypeSelection()
        }

        // Zcash option
        zcashOption.setOnClickListener {
            selectedWalletType = "ZCASH"
            updateWalletTypeSelection()
        }

        // Create button
        findViewById<View>(R.id.createWalletButton).setOnClickListener {
            val walletName = walletNameInput.text.toString().trim()
            if (walletName.isEmpty()) {
                ThemedToast.show(this, "Please enter a wallet name")
                return@setOnClickListener
            }
            createNewWallet(walletName)
        }
    }

    private fun updateWalletTypeSelection() {
        if (selectedWalletType == "SOLANA") {
            solanaCheckbox.isSelected = true
            zcashCheckbox.isSelected = false
        } else {
            solanaCheckbox.isSelected = false
            zcashCheckbox.isSelected = true
        }
    }

    private fun createNewWallet(walletName: String) {
        // Disable button to prevent double clicks
        val createButton = findViewById<View>(R.id.createWalletButton)
        createButton.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("CreateWallet", "Creating new $selectedWalletType wallet: $walletName")

                val keyManager = KeyManager.getInstance(this@CreateWalletActivity)

                val (walletId, solanaAddress, zcashAddress) = if (selectedWalletType == "ZCASH") {
                    // Generate unique wallet ID for Zcash (uses main wallet's seed for keys)
                    val walletId = "wallet_${System.currentTimeMillis()}"

                    // Initialize ZcashService to generate both unified and transparent addresses
                    val seedPhrase = keyManager.getSeedPhrase()
                    if (seedPhrase != null) {
                        val zcashService = com.securelegion.services.ZcashService.getInstance(this@CreateWalletActivity)
                        val result = zcashService.initialize(seedPhrase, useTestnet = false)
                        if (result.isSuccess) {
                            val zcashAddr = result.getOrNull()
                            Log.i("CreateWallet", "Zcash wallet initialized: $zcashAddr")
                            Log.i("CreateWallet", "Transparent address: ${keyManager.getZcashTransparentAddress()}")
                            Triple(walletId, "", zcashAddr)
                        } else {
                            Log.e("CreateWallet", "Failed to initialize Zcash wallet: ${result.exceptionOrNull()}")
                            Triple(walletId, "", keyManager.getZcashAddress())
                        }
                    } else {
                        Log.e("CreateWallet", "No seed phrase found")
                        Triple(walletId, "", keyManager.getZcashAddress())
                    }
                } else {
                    // Generate new Solana wallet with unique seed
                    val (id, addr) = keyManager.generateNewWallet()
                    Triple(id, addr, null)
                }

                // Create wallet entity
                val timestamp = System.currentTimeMillis()
                val wallet = Wallet(
                    walletId = walletId,
                    name = walletName,
                    solanaAddress = solanaAddress,
                    zcashAddress = zcashAddress,
                    isMainWallet = false,
                    createdAt = timestamp,
                    lastUsedAt = timestamp
                )

                // Save to database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@CreateWalletActivity, dbPassphrase)
                database.walletDao().insertWallet(wallet)

                // Get seed phrase to show user
                val seedPhrase = if (selectedWalletType == "SOLANA") {
                    keyManager.getWalletSeedPhrase(walletId)
                } else {
                    // For Zcash, get the main wallet seed since that's what generates the ZEC address
                    keyManager.getSeedPhrase()
                }

                // Get private key bytes for Solana (deprecated, but keeping for compatibility)
                val privateKeyBytes = if (selectedWalletType == "SOLANA") {
                    keyManager.getWalletPrivateKey(walletId)
                } else {
                    null
                }
                val privateKey = privateKeyBytes?.let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }

                // Display address
                val displayAddress = if (selectedWalletType == "ZCASH") zcashAddress ?: "" else solanaAddress

                withContext(Dispatchers.Main) {
                    Log.i("CreateWallet", "Wallet created successfully: $walletId")
                    createButton.isEnabled = true
                    showWalletCreatedBottomSheet(walletName, displayAddress, seedPhrase)
                }

            } catch (e: Exception) {
                Log.e("CreateWallet", "Failed to create wallet", e)
                withContext(Dispatchers.Main) {
                    createButton.isEnabled = true
                    ThemedToast.show(this@CreateWalletActivity, "Failed to create wallet: ${e.message}")
                }
            }
        }
    }

    private fun showWalletCreatedBottomSheet(walletName: String, address: String, privateKey: String?) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_created, null)

        // Set wallet details
        view.findViewById<TextView>(R.id.walletNameText).text = walletName

        val addressShort = if (address.length > 15) {
            "${address.take(5)}.....${address.takeLast(6)}"
        } else {
            address
        }
        view.findViewById<TextView>(R.id.walletAddressText).text = addressShort

        // Copy address button
        view.findViewById<View>(R.id.copyAddressButton).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", address)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Address copied to clipboard")
        }

        // Done button
        view.findViewById<View>(R.id.doneButton).setOnClickListener {
            bottomSheet.dismiss()
            finish()
        }

        bottomSheet.setContentView(view)
        bottomSheet.setCancelable(false)
        bottomSheet.show()
    }
}
