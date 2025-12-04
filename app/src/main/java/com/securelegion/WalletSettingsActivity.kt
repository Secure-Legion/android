package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.CheckBox
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

    private var currentWalletId: String = ""
    private var currentWalletName: String = "----"
    private var isMainWallet: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wallet_settings)

        // Get current wallet info from intent
        currentWalletId = intent.getStringExtra("WALLET_ID") ?: ""
        currentWalletName = intent.getStringExtra("WALLET_NAME") ?: "----"
        isMainWallet = intent.getBooleanExtra("IS_MAIN_WALLET", false)

        Log.d("WalletSettings", "Opened for wallet: $currentWalletName (ID: $currentWalletId, isMain: $isMainWallet)")

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

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
        currentWalletTypeView.text = "Wallet"

        // Hide export and delete buttons for protected wallet
        if (isMainWallet) {
            exportKeyButton.visibility = View.GONE
            deleteWalletButton.visibility = View.GONE
            Log.d("WalletSettings", "Protected wallet - hiding export and delete buttons")
        } else {
            exportKeySubtext.text = "View or export wallet private key"
            deleteWalletSubtext.text = "Permanently remove this wallet"

            // Ensure buttons are visible and enabled for additional wallets
            exportKeyButton.visibility = View.VISIBLE
            exportKeyButton.alpha = 1.0f
            exportKeyButton.isEnabled = true
            exportKeyButton.isClickable = true

            deleteWalletButton.visibility = View.VISIBLE
            deleteWalletButton.alpha = 1.0f
            deleteWalletButton.isEnabled = true
            deleteWalletButton.isClickable = true

            Log.d("WalletSettings", "Additional wallet - export and delete enabled")
        }
    }

    private fun setupClickListeners() {
        // Create New Wallet
        findViewById<View>(R.id.createWalletButton).setOnClickListener {
            val intent = android.content.Intent(this, CreateWalletActivity::class.java)
            startActivity(intent)
        }

        // Import Wallet
        findViewById<View>(R.id.importWalletButton).setOnClickListener {
            val intent = android.content.Intent(this, ImportWalletActivity::class.java)
            startActivity(intent)
        }

        // Export Private Key
        findViewById<View>(R.id.exportKeyButton).setOnClickListener {
            if (!isMainWallet) {
                showExportKeyDialog()
            }
        }

        // Delete Wallet
        findViewById<View>(R.id.deleteWalletButton).setOnClickListener {
            if (!isMainWallet) {
                showDeleteWalletDialog()
            }
        }
    }

    private fun showExportKeyDialog() {
        // Skip confirmation dialog, go directly to fetching and showing key
        exportPrivateKey()
    }

    private fun showDeleteWalletDialog() {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_delete_wallet, null)

        // Set up the view
        val walletNameText = view.findViewById<TextView>(R.id.walletNameText)
        val confirmCheckbox = view.findViewById<CheckBox>(R.id.confirmCheckbox)
        val deleteButton = view.findViewById<View>(R.id.deleteButton)
        val cancelButton = view.findViewById<View>(R.id.cancelButton)

        walletNameText.text = currentWalletName

        // Enable delete button only when checkbox is checked
        confirmCheckbox.setOnCheckedChangeListener { _, isChecked ->
            deleteButton.isEnabled = isChecked
            deleteButton.alpha = if (isChecked) 1.0f else 0.5f
        }

        deleteButton.setOnClickListener {
            bottomSheet.dismiss()
            deleteWallet()
        }

        cancelButton.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.setContentView(view)
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make background transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        bottomSheet.show()
    }

    private fun exportPrivateKey() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("WalletSettings", "Exporting private key for wallet: $currentWalletId")

                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val seedPhrase = keyManager.getWalletSeedPhrase(currentWalletId)

                if (seedPhrase == null) {
                    withContext(Dispatchers.Main) {
                        ThemedToast.showLong(
                            this@WalletSettingsActivity,
                            "Failed to retrieve wallet seed phrase"
                        )
                    }
                    return@launch
                }

                withContext(Dispatchers.Main) {
                    showPrivateKeyDialog(seedPhrase)
                }

            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to export key", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.showLong(
                        this@WalletSettingsActivity,
                        "Error: ${e.message}"
                    )
                }
            }
        }
    }

    private fun showPrivateKeyDialog(seedPhrase: String) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_private_key, null)

        // Set up the view
        val seedPhraseText = view.findViewById<TextView>(R.id.seedPhraseText)
        val copyButton = view.findViewById<View>(R.id.copyButton)
        val closeButton = view.findViewById<View>(R.id.closeButton)

        seedPhraseText.text = seedPhrase

        copyButton.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Seed Phrase", seedPhrase)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Seed phrase copied to clipboard")
            Log.i("WalletSettings", "Seed phrase copied to clipboard for wallet: $currentWalletId")
        }

        closeButton.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.setContentView(view)
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make background transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        bottomSheet.show()
    }

    private fun deleteWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("WalletSettings", "Deleting wallet: $currentWalletId")

                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val deleted = keyManager.deleteWallet(currentWalletId)

                if (!deleted) {
                    withContext(Dispatchers.Main) {
                        ThemedToast.showLong(
                            this@WalletSettingsActivity,
                            "Failed to delete wallet from secure storage"
                        )
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
                        ThemedToast.show(
                            this@WalletSettingsActivity,
                            "Wallet deleted successfully"
                        )
                        finish()
                    } else {
                        Log.w("WalletSettings", "Wallet not found in database: $currentWalletId")
                        ThemedToast.show(
                            this@WalletSettingsActivity,
                            "Wallet not found in database"
                        )
                    }
                }

            } catch (e: Exception) {
                Log.e("WalletSettings", "Failed to delete wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.showLong(
                        this@WalletSettingsActivity,
                        "Error deleting wallet: ${e.message}"
                    )
                }
            }
        }
    }
}
