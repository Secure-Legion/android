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
    private var currentWalletName: String = "Wallet 1"
    private var isMainWallet: Boolean = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wallet_settings)

        // Get current wallet info from intent
        currentWalletId = intent.getStringExtra("WALLET_ID") ?: "main"
        currentWalletName = intent.getStringExtra("WALLET_NAME") ?: "Wallet 1"
        isMainWallet = intent.getBooleanExtra("IS_MAIN_WALLET", true)

        Log.d("WalletSettings", "Opened for wallet: $currentWalletName (ID: $currentWalletId, isMain: $isMainWallet)")

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

        // Set wallet name from the actual wallet data
        currentWalletNameView.text = currentWalletName

        // Set wallet type
        currentWalletTypeView.text = if (isMainWallet) "Main Account Wallet" else "Additional Wallet"

        // Disable export and delete for main wallet ONLY
        if (isMainWallet) {
            exportKeySubtext.text = "Cannot export main wallet key"
            exportKeyButton.alpha = 0.5f
            exportKeyButton.isEnabled = false
            exportKeyButton.isClickable = false

            deleteWalletSubtext.text = "Cannot delete main wallet"
            deleteWalletButton.alpha = 0.5f
            deleteWalletButton.isEnabled = false
            deleteWalletButton.isClickable = false

            Log.d("WalletSettings", "Main wallet - export and delete disabled")
        } else {
            exportKeySubtext.text = "View or export wallet private key"
            deleteWalletSubtext.text = "Permanently remove this wallet"

            // Ensure buttons are enabled for additional wallets
            exportKeyButton.alpha = 1.0f
            exportKeyButton.isEnabled = true
            exportKeyButton.isClickable = true

            deleteWalletButton.alpha = 1.0f
            deleteWalletButton.isEnabled = true
            deleteWalletButton.isClickable = true

            Log.d("WalletSettings", "Additional wallet - export and delete enabled")
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

        // Export Private Key - always set up listener, but will only work when enabled
        findViewById<View>(R.id.exportKeyButton).setOnClickListener {
            if (!isMainWallet) {
                showExportKeyDialog()
            } else {
                Toast.makeText(this, "Cannot export main wallet key", Toast.LENGTH_SHORT).show()
            }
        }

        // Delete Wallet - always set up listener, but will only work when enabled
        findViewById<View>(R.id.deleteWalletButton).setOnClickListener {
            if (!isMainWallet) {
                showDeleteWalletDialog()
            } else {
                Toast.makeText(this, "Cannot delete main wallet", Toast.LENGTH_SHORT).show()
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
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            this@WalletSettingsActivity,
                            "Failed to retrieve wallet seed phrase",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    return@launch
                }

                withContext(Dispatchers.Main) {
                    showPrivateKeyDialog(seedPhrase)
                }

            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to export key", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@WalletSettingsActivity,
                        "Error: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
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
                Toast.makeText(this, "Seed phrase copied to clipboard", Toast.LENGTH_SHORT).show()
                Log.i("WalletSettings", "Seed phrase copied to clipboard for wallet: $currentWalletId")
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
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            this@WalletSettingsActivity,
                            "Failed to delete wallet from secure storage",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    return@launch
                }

                // Remove from database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@WalletSettingsActivity, dbPassphrase)
                val rowsDeleted = database.walletDao().deleteWalletById(currentWalletId)

                withContext(Dispatchers.Main) {
                    if (rowsDeleted > 0) {
                        Log.i("WalletSettings", "Wallet deleted successfully: $currentWalletId")
                        Toast.makeText(
                            this@WalletSettingsActivity,
                            "Wallet deleted successfully",
                            Toast.LENGTH_SHORT
                        ).show()
                        finish()
                    } else {
                        Log.w("WalletSettings", "Wallet not found in database: $currentWalletId")
                        Toast.makeText(
                            this@WalletSettingsActivity,
                            "Wallet not found in database",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }

            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to delete wallet", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@WalletSettingsActivity,
                        "Error deleting wallet: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }
}
