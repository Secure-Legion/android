package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.services.SolanaService
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Solana wallet dashboard. Messaging and Tor identity state are not used by this screen. */
class WalletActivity : AppCompatActivity() {

    private lateinit var swipeRefreshLayout: SwipeRefreshLayout
    private var currentWallet: Wallet? = null
    private var walletBalanceSol = 0.0
    private var solPriceUsd = 0.0
    private var showingUsd = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ENABLE_SOLANA_WALLET) {
            finish()
            return
        }
        setContentView(R.layout.activity_wallet)
        configureInsets()
        setupUi()
        loadWallet()
    }

    override fun onResume() {
        super.onResume()
        loadWallet()
    }

    private fun configureInsets() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val root = findViewById<View>(android.R.id.content)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            bottomNav.setPadding(
                bottomNav.paddingLeft,
                bottomNav.paddingTop,
                bottomNav.paddingRight,
                bars.bottom
            )
            insets
        }
    }

    private fun setupUi() {
        swipeRefreshLayout = findViewById(R.id.swipeRefreshLayout)
        swipeRefreshLayout.setColorSchemeColors(0xFF6BA4FF.toInt(), 0xFF4CAF50.toInt())
        swipeRefreshLayout.setProgressBackgroundColorSchemeColor(
            ContextCompat.getColor(this, R.color.surface_variant)
        )
        swipeRefreshLayout.setOnRefreshListener { loadWallet() }

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<View>(R.id.walletSettingsButton).setOnClickListener {
            openWalletSettings()
        }
        findViewById<View>(R.id.sendButton).setOnClickListener {
            val wallet = currentWallet
            if (wallet == null) {
                ThemedToast.show(this, "Create a wallet first")
            } else {
                startActivity(Intent(this, SendActivity::class.java).apply {
                    putExtra("WALLET_ID", wallet.walletId)
                    putExtra("WALLET_NAME", wallet.name)
                    putExtra("WALLET_ADDRESS", wallet.solanaAddress)
                    putExtra("TOKEN_SYMBOL", "SOL")
                    putExtra("TOKEN_NAME", "Solana")
                })
            }
        }
        findViewById<View>(R.id.receiveButton).setOnClickListener {
            startActivity(Intent(this, ReceiveActivity::class.java))
        }
        findViewById<View>(R.id.shieldButton).setOnClickListener {
            startActivity(Intent(this, SwapActivity::class.java))
        }
        findViewById<TextView>(R.id.shieldButtonLabel).text = "Swap"
        findViewById<ImageView>(R.id.shieldButtonIcon).setImageResource(R.drawable.ic_swap)
        findViewById<View>(R.id.toggleCurrency).setOnClickListener {
            showingUsd = !showingUsd
            renderBalance()
        }
        findViewById<View>(R.id.navMessages).setOnClickListener {
            startActivity(Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            })
            finish()
        }
        findViewById<View>(R.id.navAccounts).setOnClickListener { showWalletSelector() }
        findViewById<View>(R.id.navNewWallet).setOnClickListener {
            startActivity(Intent(this, CreateWalletActivity::class.java))
        }
        findViewById<View>(R.id.navRecent).setOnClickListener {
            val wallet = currentWallet
            startActivity(Intent(this, RecentTransactionsActivity::class.java).apply {
                wallet?.let {
                    putExtra("WALLET_ID", it.walletId)
                    putExtra("WALLET_NAME", it.name)
                    putExtra("WALLET_ADDRESS", it.solanaAddress)
                }
            })
        }
    }

    private fun loadWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val wallets = database().walletDao().getAllWallets()
                    .filter { it.walletId != "main" && it.solanaAddress.isNotBlank() }
                val wallet = wallets.maxByOrNull { it.lastUsedAt }
                currentWallet = wallet
                if (wallet == null) {
                    walletBalanceSol = 0.0
                    solPriceUsd = 0.0
                    withContext(Dispatchers.Main) {
                        renderWallet(null)
                        swipeRefreshLayout.isRefreshing = false
                    }
                    return@launch
                }

                val service = SolanaService(this@WalletActivity)
                walletBalanceSol = service.getBalance(wallet.solanaAddress).getOrDefault(0.0)
                solPriceUsd = service.getSolPrice().getOrDefault(0.0)
                withContext(Dispatchers.Main) {
                    renderWallet(wallet)
                    swipeRefreshLayout.isRefreshing = false
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load Solana wallet", e)
                withContext(Dispatchers.Main) {
                    swipeRefreshLayout.isRefreshing = false
                    ThemedToast.show(this@WalletActivity, "Failed to load wallet")
                }
            }
        }
    }

    private fun renderWallet(wallet: Wallet?) {
        findViewById<ImageView>(R.id.walletChainIcon).setImageResource(R.drawable.ic_solana)
        findViewById<TextView>(R.id.walletTitle).text = wallet?.name ?: "No Wallet"
        renderBalance()
    }

    private fun renderBalance() {
        val usd = walletBalanceSol * solPriceUsd
        findViewById<TextView>(R.id.balanceAmount).text =
            if (showingUsd) "$" + String.format("%.2f", usd)
            else formatBalance(walletBalanceSol) + " SOL"
        findViewById<TextView>(R.id.solBalance).text = "$" + String.format("%.2f", usd)
        findViewById<TextView>(R.id.solAmount).text =
            formatBalance(walletBalanceSol) + " SOL"
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val wallets = database().walletDao().getAllWallets()
                    .filter { it.walletId != "main" && it.solanaAddress.isNotBlank() }
                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@WalletActivity, "No wallets found")
                        return@withContext
                    }
                    val sheet = GlassBottomSheetDialog(this@WalletActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)
                    val container = view.findViewById<LinearLayout>(R.id.walletListContainer)
                    wallets.forEach { wallet ->
                        val row = layoutInflater.inflate(R.layout.item_wallet_selector, container, false)
                        row.findViewById<TextView>(R.id.walletName).text = wallet.name
                        row.findViewById<TextView>(R.id.walletBalance).text = "Solana"
                        row.findViewById<TextView>(R.id.walletAddress)?.text =
                            shorten(wallet.solanaAddress)
                        row.findViewById<ImageView>(R.id.walletIcon)?.setImageResource(R.drawable.ic_solana)
                        row.findViewById<View>(R.id.walletSettingsBtn)?.setOnClickListener {
                            sheet.dismiss()
                            startActivity(Intent(this@WalletActivity, WalletSettingsActivity::class.java).apply {
                                putExtra("WALLET_ID", wallet.walletId)
                            })
                        }
                        row.setOnClickListener {
                            sheet.dismiss()
                            switchWallet(wallet)
                        }
                        container.addView(row)
                    }
                    sheet.setContentView(view)
                    sheet.show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to show wallet selector", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@WalletActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun switchWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            database().walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())
            withContext(Dispatchers.Main) { loadWallet() }
        }
    }

    private fun openWalletSettings() {
        startActivity(Intent(this, WalletSettingsActivity::class.java).apply {
            currentWallet?.let { putExtra("WALLET_ID", it.walletId) }
        })
    }

    private fun database(): SecureLegionDatabase {
        val keyManager = KeyManager.getInstance(this)
        return SecureLegionDatabase.getInstance(this, keyManager.getDatabasePassphrase())
    }

    private fun shorten(address: String): String =
        if (address.length > 15) address.take(6) + "..." + address.takeLast(6) else address

    private fun formatBalance(value: Double): String =
        String.format("%.6f", value).trimEnd('0').trimEnd('.').ifEmpty { "0" }

    private companion object {
        const val TAG = "WalletActivity"
    }
}
