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

    // Helper data class for 4 return values
    private data class WalletCreationResult(
        val walletId: String,
        val solanaAddress: String,
        val zcashAddress: String?,
        val seedPhrase: String?
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_wallet)

        walletNameInput = findViewById(R.id.walletNameInput)
        solanaOption = findViewById(R.id.solanaOption)
        zcashOption = findViewById(R.id.zcashOption)
        solanaCheckbox = findViewById(R.id.solanaCheckbox)
        zcashCheckbox = findViewById(R.id.zcashCheckbox)

        // Hide Zcash option if disabled for this flavor
        if (!BuildConfig.ENABLE_ZCASH_WALLET) {
            zcashOption.visibility = View.GONE
            selectedWalletType = "SOLANA"
        }

        // Check if chain was pre-selected via intent
        val preSelectedChain = intent.getStringExtra("SELECTED_CHAIN")
        if (preSelectedChain != null && (preSelectedChain != "ZCASH" || BuildConfig.ENABLE_ZCASH_WALLET)) {
            selectedWalletType = preSelectedChain
        }

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

                val result = if (selectedWalletType == "ZCASH") {
                    // Generate unique wallet ID for Zcash
                    val walletId = "wallet_${System.currentTimeMillis()}"

                    // Use main wallet seed for Zcash (all Zcash wallets share main seed)
                    val mainSeed = keyManager.getMainWalletSeedForZcash()
                    val backupSeed = keyManager.getSeedPhrase()
                    val seedPhrase = mainSeed ?: backupSeed

                    if (seedPhrase != null) {
                        Log.d("CreateWallet", "Deriving Zcash address offline from main seed")

                        // Use FAST offline derivation (no blockchain sync needed)
                        val zcashUnifiedAddress = try {
                            val derivedAddress = com.securelegion.utils.ZcashAddressDeriver.deriveUnifiedAddressFromSeed(
                                seedPhrase = seedPhrase,
                                network = cash.z.ecc.android.sdk.model.ZcashNetwork.Mainnet,
                                accountIndex = 0
                            )
                            Log.i("CreateWallet", "Successfully derived Zcash UA (offline): ${derivedAddress.take(20)}...")
                            derivedAddress
                        } catch (e: Exception) {
                            Log.e("CreateWallet", "Failed to derive Zcash address", e)
                            withContext(Dispatchers.Main) {
                                ThemedToast.showLong(this@CreateWalletActivity, "Failed to derive address: ${e.message}")
                            }
                            null
                        }

                        WalletCreationResult(walletId, "", zcashUnifiedAddress, seedPhrase)
                    } else {
                        Log.e("CreateWallet", "No seed phrase found for Zcash wallet")
                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@CreateWalletActivity, "No seed phrase found - cannot create Zcash wallet")
                        }
                        WalletCreationResult("wallet_${System.currentTimeMillis()}", "", null, null)
                    }
                } else {
                    // Generate new Solana wallet with unique seed
                    val (id, addr) = keyManager.generateNewWallet()
                    val solSeed = keyManager.getWalletSeedPhrase(id)
                    WalletCreationResult(id, addr, null, solSeed)
                }

                val walletId = result.walletId
                val solanaAddress = result.solanaAddress
                val zcashAddress = result.zcashAddress
                val seedPhrase = result.seedPhrase

                // Create wallet entity
                val timestamp = System.currentTimeMillis()
                val wallet = Wallet(
                    walletId = walletId,
                    name = walletName,
                    solanaAddress = solanaAddress,
                    zcashUnifiedAddress = zcashAddress,
                    zcashAccountIndex = 0,
                    zcashBirthdayHeight = null,
                    isActiveZcash = false,
                    isMainWallet = false,
                    createdAt = timestamp,
                    lastUsedAt = timestamp
                )

                // Save to database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@CreateWalletActivity, dbPassphrase)
                database.walletDao().insertWallet(wallet)

                // Update Zcash derived info if Zcash wallet
                if (selectedWalletType == "ZCASH" && zcashAddress != null) {
                    database.walletDao().updateZcashDerivedInfo(
                        walletId = walletId,
                        ua = zcashAddress,
                        accountIndex = 0,
                        birthdayHeight = null
                    )

                    // Store seed phrase for Zcash wallet so it can be retrieved later
                    if (seedPhrase != null) {
                        keyManager.storeWalletSeed(walletId, seedPhrase)
                        Log.i("CreateWallet", "Stored seed phrase for Zcash wallet: $walletId")
                    }
                }

                // Display address
                val displayAddress = if (selectedWalletType == "ZCASH") zcashAddress ?: "" else solanaAddress

                withContext(Dispatchers.Main) {
                    Log.i("CreateWallet", "Wallet created successfully: $walletId")
                    createButton.isEnabled = true
                    showWalletCreatedBottomSheet(walletName, displayAddress, seedPhrase, walletId)
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

    private fun showWalletCreatedBottomSheet(walletName: String, address: String, privateKey: String?, walletId: String) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_created, null)

        // Set wallet details
        view.findViewById<TextView>(R.id.walletNameText).text = walletName

        // Show full address instead of shortened
        view.findViewById<TextView>(R.id.walletAddressText).text = address

        // Copy address button
        view.findViewById<View>(R.id.copyAddressButton).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", address)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Address copied to clipboard")
        }

        // Done button - set wallet as active before finishing
        view.findViewById<View>(R.id.doneButton).setOnClickListener {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    // Set this wallet as active by updating its lastUsedAt timestamp
                    val keyManager = KeyManager.getInstance(this@CreateWalletActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@CreateWalletActivity, dbPassphrase)
                    database.walletDao().updateLastUsed(walletId, System.currentTimeMillis())

                    withContext(Dispatchers.Main) {
                        bottomSheet.dismiss()
                        finish()
                    }
                } catch (e: Exception) {
                    Log.e("CreateWallet", "Failed to set wallet as active", e)
                    withContext(Dispatchers.Main) {
                        bottomSheet.dismiss()
                        finish()
                    }
                }
            }
        }

        bottomSheet.setContentView(view)
        bottomSheet.setCancelable(false)
        bottomSheet.show()
    }
}
