package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WalletSettingsActivity : AppCompatActivity() {

    private var currentWalletId: String = "main"  // Default to main wallet
    private var isMainWallet: Boolean = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wallet_settings)

        // Get current wallet info from intent
        currentWalletId = intent.getStringExtra("WALLET_ID") ?: "main"
        isMainWallet = intent.getBooleanExtra("IS_MAIN_WALLET", true)

        setupUI()
        setupClickListeners()
    }

    private fun setupUI() {
        val currentWalletNameView = findViewById<TextView>(R.id.currentWalletName)
        val currentWalletTypeView = findViewById<TextView>(R.id.currentWalletType)
        val exportKeySubtext = findViewById<TextView>(R.id.exportKeySubtext)
        val deleteWalletSubtext = findViewById<TextView>(R.id.deleteWalletSubtext)
        val exportKeyButton = findViewById<View>(R.id.exportKeyButton)
        val deleteWalletButton = findViewById<View>(R.id.deleteWalletButton)

        // Set wallet name (for now just use "Wallet 1" as default)
        currentWalletNameView.text = if (isMainWallet) "Wallet 1" else "Wallet 2"

        // Set wallet type
        currentWalletTypeView.text = if (isMainWallet) "Main Account Wallet" else "Additional Wallet"

        // Disable export and delete for main wallet
        if (isMainWallet) {
            exportKeySubtext.text = "Cannot export main wallet key"
            exportKeyButton.alpha = 0.5f
            exportKeyButton.isEnabled = false
            exportKeyButton.isClickable = false

            deleteWalletSubtext.text = "Cannot delete main wallet"
            deleteWalletButton.alpha = 0.5f
            deleteWalletButton.isEnabled = false
            deleteWalletButton.isClickable = false
        } else {
            exportKeySubtext.text = "View or export wallet private key"
            deleteWalletSubtext.text = "Permanently remove this wallet"
        }
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Create New Wallet
        findViewById<View>(R.id.createWalletButton).setOnClickListener {
            val intent = android.content.Intent(this, CreateWalletActivity::class.java)
            startActivity(intent)
        }

        // Export Private Key (only enabled for non-main wallets)
        if (!isMainWallet) {
            findViewById<View>(R.id.exportKeyButton).setOnClickListener {
                showExportKeyDialog()
            }

            // Delete Wallet (only enabled for non-main wallets)
            findViewById<View>(R.id.deleteWalletButton).setOnClickListener {
                showDeleteWalletDialog()
            }
        }
    }

    private fun showExportKeyDialog() {
        AlertDialog.Builder(this, R.style.CustomAlertDialog)
            .setTitle("Export Private Key")
            .setMessage("WARNING: Never share your private key with anyone. Anyone with your private key can access your funds.\n\nDo you want to view your private key?")
            .setPositiveButton("View Key") { dialog, _ ->
                exportPrivateKey()
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    private fun showDeleteWalletDialog() {
        AlertDialog.Builder(this, R.style.CustomAlertDialog)
            .setTitle("Delete Wallet")
            .setMessage("WARNING: This will permanently delete this wallet. Make sure you have backed up your private key before proceeding.\n\nThis action cannot be undone.")
            .setPositiveButton("Delete") { dialog, _ ->
                deleteWallet()
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    private fun exportPrivateKey() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("WalletSettings", "Exporting private key for wallet: $currentWalletId")

                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val seedPhrase = keyManager.getWalletSeedPhrase(currentWalletId)

                if (seedPhrase == null) {
                    return@launch
                }

                withContext(Dispatchers.Main) {
                    showPrivateKeyDialog(seedPhrase)
                }

            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to export key", e)
            }
        }
    }

    private fun showPrivateKeyDialog(seedPhrase: String) {
        AlertDialog.Builder(this, R.style.CustomAlertDialog)
            .setTitle("Seed Phrase")
            .setMessage("Your 12-word seed phrase:\n\n$seedPhrase\n\nWARNING: Never share this with anyone!")
            .setPositiveButton("Copy to Clipboard") { dialog, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Seed Phrase", seedPhrase)
                clipboard.setPrimaryClip(clip)
                dialog.dismiss()
            }
            .setNegativeButton("Close") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    private fun deleteWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("WalletSettings", "Deleting wallet: $currentWalletId")

                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val deleted = keyManager.deleteWallet(currentWalletId)

                if (!deleted) {
                    return@launch
                }

                // Remove from database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)
                database.walletDao().deleteWalletById(currentWalletId)

                withContext(Dispatchers.Main) {
                    Log.i("WalletSettings", "Wallet deleted: $currentWalletId")
                    finish()
                }

            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to delete wallet", e)
            }
        }
    }
}
