package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Imports an additional Solana wallet from a seed phrase or private key. */
class ImportWalletActivity : AppCompatActivity() {

    private var importType = ImportType.SEED_PHRASE

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ENABLE_SOLANA_WALLET) {
            finish()
            return
        }
        setContentView(R.layout.activity_import_wallet)
        updateImportTypeSelection()

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<View>(R.id.seedPhraseTypeButton).setOnClickListener {
            importType = ImportType.SEED_PHRASE
            updateImportTypeSelection()
        }
        findViewById<View>(R.id.privateKeyTypeButton).setOnClickListener {
            importType = ImportType.PRIVATE_KEY
            updateImportTypeSelection()
        }
        findViewById<View>(R.id.importButton).setOnClickListener { importWallet() }
    }

    private fun updateImportTypeSelection() {
        val seedSelected = importType == ImportType.SEED_PHRASE
        findViewById<View>(R.id.seedPhraseTypeButton).setBackgroundResource(
            if (seedSelected) R.drawable.swap_button_bg else R.drawable.wallet_dropdown_bg
        )
        findViewById<View>(R.id.privateKeyTypeButton).setBackgroundResource(
            if (seedSelected) R.drawable.wallet_dropdown_bg else R.drawable.swap_button_bg
        )
        findViewById<View>(R.id.seedPhraseInputContainer).visibility =
            if (seedSelected) View.VISIBLE else View.GONE
        findViewById<View>(R.id.privateKeyInputContainer).visibility =
            if (seedSelected) View.GONE else View.VISIBLE
    }

    private fun importWallet() {
        val walletName = findViewById<EditText>(R.id.walletNameInput).text.toString().trim()
        if (walletName.isEmpty()) {
            ThemedToast.show(this, "Please enter a wallet name")
            return
        }

        val keyMaterial = when (importType) {
            ImportType.SEED_PHRASE ->
                findViewById<EditText>(R.id.seedPhraseInput).text.toString().trim()
            ImportType.PRIVATE_KEY ->
                findViewById<EditText>(R.id.privateKeyInput).text.toString().trim()
        }
        if (keyMaterial.isEmpty()) {
            ThemedToast.show(this, "Please enter a private key or seed phrase")
            return
        }

        val importButton = findViewById<View>(R.id.importButton)
        importButton.isEnabled = false
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                importSolanaWallet(walletName, keyMaterial)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to import Solana wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.showLong(
                        this@ImportWalletActivity,
                        "Import failed: " + (e.message ?: "unknown error")
                    )
                    importButton.isEnabled = true
                }
            }
        }
    }

    private suspend fun importSolanaWallet(walletName: String, keyMaterial: String) {
        val keyManager = KeyManager.getInstance(this@ImportWalletActivity)
        val walletId = "sol_" + System.currentTimeMillis()
        val words = keyMaterial.split("\\s+".toRegex())
        val isMnemonic = words.size == 12 || words.size == 24
        val imported = if (isMnemonic) {
            keyManager.importWalletFromSeed(walletId, keyMaterial)
        } else {
            keyManager.importSolanaWalletFromPrivateKey(walletId, keyMaterial)
        }

        if (!imported) {
            withContext(Dispatchers.Main) {
                val message = if (isMnemonic) {
                    "Invalid seed phrase. Please check all words and try again."
                } else {
                    "Invalid private key. Use a Base58 string or JSON byte array."
                }
                ThemedToast.showLong(this@ImportWalletActivity, message)
                findViewById<View>(R.id.importButton).isEnabled = true
            }
            return
        }

        val solanaAddress = keyManager.getWalletSolanaAddress(walletId)
        if (solanaAddress.isBlank()) {
            throw IllegalStateException("Imported wallet did not produce a Solana address")
        }
        val now = System.currentTimeMillis()
        val wallet = Wallet(
            walletId = walletId,
            name = walletName,
            solanaAddress = solanaAddress,
            isMainWallet = false,
            createdAt = now,
            lastUsedAt = now
        )
        val database = SecureLegionDatabase.getInstance(
            this@ImportWalletActivity,
            keyManager.getDatabasePassphrase()
        )
        database.walletDao().insertWallet(wallet)

        withContext(Dispatchers.Main) {
            ThemedToast.show(this@ImportWalletActivity, "Wallet imported successfully!")
            finish()
        }
    }

    private enum class ImportType {
        SEED_PHRASE,
        PRIVATE_KEY
    }

    private companion object {
        const val TAG = "ImportWallet"
    }
}
