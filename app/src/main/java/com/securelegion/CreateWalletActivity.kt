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
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Creates an additional Solana wallet.
 *
 * Account identity and messaging recovery remain separate from this wallet-specific seed.
 */
class CreateWalletActivity : AppCompatActivity() {

    private lateinit var walletNameInput: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ENABLE_SOLANA_WALLET) {
            finish()
            return
        }
        setContentView(R.layout.activity_create_wallet)

        walletNameInput = findViewById(R.id.walletNameInput)
        findViewById<View>(R.id.solanaCheckbox).isSelected = true

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<View>(R.id.solanaOption).setOnClickListener {
            findViewById<View>(R.id.solanaCheckbox).isSelected = true
        }
        findViewById<View>(R.id.createWalletButton).setOnClickListener {
            val walletName = walletNameInput.text.toString().trim()
            if (walletName.isEmpty()) {
                ThemedToast.show(this, "Please enter a wallet name")
            } else {
                createNewWallet(walletName)
            }
        }

        setDefaultWalletName()
    }

    private fun setDefaultWalletName() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@CreateWalletActivity)
                val database = SecureLegionDatabase.getInstance(
                    this@CreateWalletActivity,
                    keyManager.getDatabasePassphrase()
                )
                val defaultName = "Wallet " + (database.walletDao().getWalletCount() + 1)
                withContext(Dispatchers.Main) {
                    walletNameInput.setText(defaultName)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to get wallet count", e)
            }
        }
    }

    private fun createNewWallet(walletName: String) {
        val createButton = findViewById<View>(R.id.createWalletButton)
        createButton.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@CreateWalletActivity)
                val (walletId, solanaAddress) = keyManager.generateNewWallet()
                val timestamp = System.currentTimeMillis()
                val wallet = Wallet(
                    walletId = walletId,
                    name = walletName,
                    solanaAddress = solanaAddress,
                    isMainWallet = false,
                    createdAt = timestamp,
                    lastUsedAt = timestamp
                )
                val database = SecureLegionDatabase.getInstance(
                    this@CreateWalletActivity,
                    keyManager.getDatabasePassphrase()
                )
                database.walletDao().insertWallet(wallet)

                withContext(Dispatchers.Main) {
                    createButton.isEnabled = true
                    showWalletCreatedBottomSheet(walletName, solanaAddress, walletId)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create Solana wallet", e)
                withContext(Dispatchers.Main) {
                    createButton.isEnabled = true
                    ThemedToast.show(
                        this@CreateWalletActivity,
                        "Failed to create wallet: " + (e.message ?: "unknown error")
                    )
                }
            }
        }
    }

    private fun showWalletCreatedBottomSheet(
        walletName: String,
        address: String,
        walletId: String
    ) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_created, null)
        view.findViewById<TextView>(R.id.walletNameText).text = walletName
        view.findViewById<TextView>(R.id.walletAddressText).text = address
        view.findViewById<View>(R.id.copyAddressButton).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("Wallet Address", address))
            ThemedToast.show(this, "Address copied to clipboard")
        }
        view.findViewById<View>(R.id.doneButton).setOnClickListener {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val keyManager = KeyManager.getInstance(this@CreateWalletActivity)
                    val database = SecureLegionDatabase.getInstance(
                        this@CreateWalletActivity,
                        keyManager.getDatabasePassphrase()
                    )
                    database.walletDao().updateLastUsed(walletId, System.currentTimeMillis())
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to mark wallet active", e)
                }
                withContext(Dispatchers.Main) {
                    bottomSheet.dismiss()
                    finish()
                }
            }
        }
        bottomSheet.setContentView(view)
        bottomSheet.setCancelable(false)
        bottomSheet.show()
    }

    private companion object {
        const val TAG = "CreateWallet"
    }
}
