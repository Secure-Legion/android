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
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.services.SolanaService
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bitcoinj.core.Base58

/** Settings and backup controls for local Solana wallets. */
class WalletSettingsActivity : BaseActivity() {

    private var currentWallet: Wallet? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ENABLE_SOLANA_WALLET) {
            finish()
            return
        }
        setContentView(R.layout.activity_wallet_settings)

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<View>(R.id.currentWalletSelector).setOnClickListener { showWalletSelector() }
        findViewById<View>(R.id.createWalletButton).setOnClickListener {
            startActivity(Intent(this, CreateWalletActivity::class.java))
        }
        findViewById<View>(R.id.importWalletButton).setOnClickListener {
            startActivity(Intent(this, ImportWalletActivity::class.java))
        }
        findViewById<View>(R.id.exportKeyButton).setOnClickListener { exportCurrentWallet() }
        findViewById<View>(R.id.deleteWalletButton).setOnClickListener {
            currentWallet?.let(::showDeleteConfirmation)
                ?: ThemedToast.show(this, "No wallet selected")
        }
        loadCurrentWallet()
    }

    override fun onResume() {
        super.onResume()
        loadCurrentWallet()
    }

    private fun loadCurrentWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val database = database()
                val requestedId = intent.getStringExtra("WALLET_ID")
                val wallets = database.walletDao().getAllWallets()
                    .filter { it.walletId != "main" && it.solanaAddress.isNotBlank() }
                val wallet = requestedId?.let { id -> wallets.firstOrNull { it.walletId == id } }
                    ?: wallets.maxByOrNull { it.lastUsedAt }
                currentWallet = wallet
                withContext(Dispatchers.Main) { displayWallet(wallet) }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallet", e)
                withContext(Dispatchers.Main) {
                    displayWallet(null)
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to load wallet")
                }
            }
        }
    }

    private fun displayWallet(wallet: Wallet?) {
        val name = findViewById<TextView>(R.id.currentWalletName)
        val balance = findViewById<TextView>(R.id.currentWalletBalance)
        val icon = findViewById<ImageView>(R.id.currentWalletIcon)
        icon.setImageResource(R.drawable.ic_solana)
        if (wallet == null) {
            name.text = "No wallet"
            balance.text = ""
            findViewById<View>(R.id.exportKeyButton).isEnabled = false
            findViewById<View>(R.id.deleteWalletButton).isEnabled = false
            return
        }
        name.text = wallet.name
        balance.text = "Loading..."
        findViewById<View>(R.id.exportKeyButton).isEnabled = true
        findViewById<View>(R.id.deleteWalletButton).isEnabled = !wallet.isMainWallet
        lifecycleScope.launch(Dispatchers.IO) {
            val amount = SolanaService(this@WalletSettingsActivity)
                .getBalance(wallet.solanaAddress)
                .getOrDefault(0.0)
            withContext(Dispatchers.Main) {
                if (currentWallet?.walletId == wallet.walletId) {
                    balance.text = formatBalance(amount) + " SOL"
                }
            }
        }
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val wallets = database().walletDao().getAllWallets()
                    .filter { it.walletId != "main" && it.solanaAddress.isNotBlank() }
                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletSettingsActivity, "No wallets found")
                        return@withContext
                    }
                    val sheet = GlassBottomSheetDialog(this@WalletSettingsActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)
                    val container = view.findViewById<LinearLayout>(R.id.walletListContainer)
                    wallets.forEach { wallet ->
                        val row = layoutInflater.inflate(R.layout.item_wallet_selector, container, false)
                        row.findViewById<TextView>(R.id.walletName).text = wallet.name
                        row.findViewById<TextView>(R.id.walletBalance).text = "Solana"
                        row.findViewById<ImageView>(R.id.walletIcon)?.setImageResource(R.drawable.ic_solana)
                        row.findViewById<TextView>(R.id.walletAddress)?.text =
                            shorten(wallet.solanaAddress)
                        row.findViewById<View>(R.id.walletSettingsBtn)?.visibility = View.GONE
                        row.setOnClickListener {
                            currentWallet = wallet
                            lifecycleScope.launch(Dispatchers.IO) {
                                database().walletDao().updateLastUsed(
                                    wallet.walletId,
                                    System.currentTimeMillis()
                                )
                            }
                            displayWallet(wallet)
                            sheet.dismiss()
                        }
                        container.addView(row)
                    }
                    sheet.setContentView(view)
                    sheet.show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to show wallet selector", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun exportCurrentWallet() {
        val wallet = currentWallet ?: return
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@WalletSettingsActivity)
                val seedPhrase = keyManager.getWalletSeedPhrase(wallet.walletId)
                val privateKeyBytes = keyManager.getWalletPrivateKey(wallet.walletId)
                val privateKey = privateKeyBytes?.let(Base58::encode)
                withContext(Dispatchers.Main) {
                    if (seedPhrase == null || privateKey == null) {
                        ThemedToast.show(
                            this@WalletSettingsActivity,
                            "Failed to retrieve wallet credentials"
                        )
                    } else {
                        showExportBottomSheet(wallet, seedPhrase, privateKey)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to export wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletSettingsActivity, "Failed to export wallet")
                }
            }
        }
    }

    private fun showExportBottomSheet(wallet: Wallet, seedPhrase: String, privateKey: String) {
        val sheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_private_key, null)
        val keyText = view.findViewById<TextView>(R.id.seedPhraseText)
        val infoText = view.findViewById<TextView>(R.id.infoText)
        val seedButton = view.findViewById<View>(R.id.seedPhraseTypeButton)
        val privateButton = view.findViewById<View>(R.id.privateKeyTypeButton)
        view.findViewById<ImageView>(R.id.walletChainIcon)?.setImageResource(R.drawable.ic_solana)
        view.findViewById<TextView>(R.id.walletAddressText)?.text = shorten(wallet.solanaAddress)
        view.findViewById<View>(R.id.exportTypeContainer)?.visibility = View.VISIBLE

        var displayedSecret = seedPhrase
        fun showSeed() {
            displayedSecret = seedPhrase
            keyText.text = seedPhrase
            infoText.text = "Your seed phrase:"
            seedButton.setBackgroundResource(R.drawable.swap_button_bg)
            privateButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)
        }
        fun showPrivateKey() {
            displayedSecret = privateKey
            keyText.text = privateKey
            infoText.text = "Your private key (Base58):"
            seedButton.setBackgroundResource(R.drawable.wallet_dropdown_bg)
            privateButton.setBackgroundResource(R.drawable.swap_button_bg)
        }
        showSeed()
        seedButton.setOnClickListener { showSeed() }
        privateButton.setOnClickListener { showPrivateKey() }
        view.findViewById<ImageView>(R.id.copyAddressIcon)?.setOnClickListener {
            copyToClipboard("Wallet Address", wallet.solanaAddress)
        }
        view.findViewById<ImageView>(R.id.copySeedPhraseIcon)?.setOnClickListener {
            copyToClipboard("Wallet Secret", displayedSecret)
        }
        view.findViewById<View>(R.id.closeButton)?.setOnClickListener { sheet.dismiss() }
        sheet.setContentView(view)
        sheet.show()
    }

    private fun showDeleteConfirmation(wallet: Wallet) {
        if (wallet.isMainWallet) {
            ThemedToast.show(this, "The account wallet cannot be deleted")
            return
        }
        val sheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_delete_wallet, null)
        view.findViewById<TextView>(R.id.walletNameText).text = wallet.name
        view.findViewById<TextView>(R.id.walletAddressText).text = shorten(wallet.solanaAddress)
        val checkbox = view.findViewById<CheckBox>(R.id.confirmCheckbox)
        val deleteButton = view.findViewById<View>(R.id.deleteButton)
        checkbox.setOnCheckedChangeListener { _, checked ->
            deleteButton.isEnabled = checked
            deleteButton.alpha = if (checked) 1f else 0.5f
        }
        deleteButton.setOnClickListener {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    database().walletDao().deleteWalletById(wallet.walletId)
                    KeyManager.getInstance(this@WalletSettingsActivity).deleteWallet(wallet.walletId)
                    currentWallet = null
                    withContext(Dispatchers.Main) {
                        sheet.dismiss()
                        ThemedToast.show(this@WalletSettingsActivity, "Wallet deleted")
                        loadCurrentWallet()
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to delete wallet", e)
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@WalletSettingsActivity, "Failed to delete wallet")
                    }
                }
            }
        }
        view.findViewById<View>(R.id.cancelButton).setOnClickListener { sheet.dismiss() }
        sheet.setContentView(view)
        sheet.show()
    }

    private fun database(): SecureLegionDatabase {
        val keyManager = KeyManager.getInstance(this)
        return SecureLegionDatabase.getInstance(this, keyManager.getDatabasePassphrase())
    }

    private fun copyToClipboard(label: String, value: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
        ThemedToast.show(this, label + " copied to clipboard")
    }

    private fun shorten(address: String): String =
        if (address.length > 15) address.take(6) + "..." + address.takeLast(6) else address

    private fun formatBalance(balance: Double): String =
        String.format("%.6f", balance).trimEnd('0').trimEnd('.').ifEmpty { "0" }

    private companion object {
        const val TAG = "WalletSettings"
    }
}
