package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.NLx402Manager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.services.MessageService
import com.securelegion.services.SolanaService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Activity for accepting an incoming payment.
 * When someone sends you money, you pick which wallet to receive it to.
 */
class AcceptPaymentActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "AcceptPaymentActivity"
        const val EXTRA_SENDER_NAME = "SENDER_NAME"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_PAYMENT_AMOUNT = "PAYMENT_AMOUNT"
        const val EXTRA_PAYMENT_TOKEN = "PAYMENT_TOKEN"
        const val EXTRA_PAYMENT_QUOTE_JSON = "PAYMENT_QUOTE_JSON"
        const val EXTRA_MESSAGE_ID = "MESSAGE_ID"
        const val EXTRA_EXPIRY_TIME = "EXPIRY_TIME"
    }

    private lateinit var backButton: View
    private lateinit var senderName: TextView
    private lateinit var amountDisplay: TextView
    private lateinit var amountUsd: TextView
    private lateinit var walletDropdown: View
    private lateinit var walletNameText: TextView
    private lateinit var walletAddressShort: TextView
    private lateinit var expiryText: TextView
    private lateinit var acceptButton: View
    private lateinit var declineButton: View

    private lateinit var keyManager: KeyManager
    private lateinit var solanaService: SolanaService

    private var contactId: Long = -1
    private var messageId: String = ""
    private var paymentAmount: Long = 0
    private var paymentToken: String = "SOL"
    private var paymentQuote: NLx402Manager.PaymentQuote? = null

    // Wallet selection
    private var currentWalletId: String = ""
    private var currentWalletName: String = "Wallet 1"
    private var currentWalletAddress: String = ""
    private var currentZcashAddress: String? = null

    private var currentSolPrice: Double = 0.0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_accept_payment)

        keyManager = KeyManager.getInstance(this)
        solanaService = SolanaService(this)

        // Get extras
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)
        messageId = intent.getStringExtra(EXTRA_MESSAGE_ID) ?: ""
        paymentAmount = intent.getLongExtra(EXTRA_PAYMENT_AMOUNT, 0)
        paymentToken = intent.getStringExtra(EXTRA_PAYMENT_TOKEN) ?: "SOL"

        val quoteJson = intent.getStringExtra(EXTRA_PAYMENT_QUOTE_JSON)
        if (quoteJson != null) {
            paymentQuote = NLx402Manager.PaymentQuote.fromJson(quoteJson)
        }

        initializeViews()
        setupClickListeners()
        loadSenderInfo()
        loadPaymentDetails()
        loadWalletInfo()
        fetchPrice()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        senderName = findViewById(R.id.senderName)
        amountDisplay = findViewById(R.id.amountDisplay)
        amountUsd = findViewById(R.id.amountUsd)
        walletDropdown = findViewById(R.id.walletDropdown)
        walletNameText = findViewById(R.id.walletNameText)
        walletAddressShort = findViewById(R.id.walletAddressShort)
        expiryText = findViewById(R.id.expiryText)
        acceptButton = findViewById(R.id.acceptButton)
        declineButton = findViewById(R.id.declineButton)
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener {
            finish()
        }

        walletDropdown.setOnClickListener {
            showWalletSelector()
        }

        acceptButton.setOnClickListener {
            acceptPayment()
        }

        declineButton.setOnClickListener {
            declinePayment()
        }
    }

    private fun loadSenderInfo() {
        val name = intent.getStringExtra(EXTRA_SENDER_NAME) ?: "Someone"
        senderName.text = name
    }

    private fun loadPaymentDetails() {
        // Convert amount to human readable
        val decimals = when (paymentToken.uppercase()) {
            "SOL" -> 9
            "ZEC" -> 8
            "USDC", "USDT" -> 6
            else -> 9
        }
        val divisor = Math.pow(10.0, decimals.toDouble())
        val humanAmount = paymentAmount.toDouble() / divisor

        amountDisplay.text = String.format(java.util.Locale.US, "%.4f %s", humanAmount, paymentToken)

        // Expiry
        val expiryTime = intent.getLongExtra(EXTRA_EXPIRY_TIME, 0)
        if (expiryTime > 0) {
            val remaining = expiryTime - System.currentTimeMillis()
            if (remaining > 0) {
                val hours = remaining / (1000 * 60 * 60)
                val minutes = (remaining % (1000 * 60 * 60)) / (1000 * 60)
                expiryText.text = if (hours > 0) "in ${hours}h ${minutes}m" else "in ${minutes}m"
            } else {
                expiryText.text = "Expired"
                acceptButton.isEnabled = false
                acceptButton.alpha = 0.5f
            }
        } else {
            expiryText.text = "24 hours"
        }
    }

    private fun loadWalletInfo() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@AcceptPaymentActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter wallets by token type
                val wallets = allWallets.filter { wallet ->
                    wallet.walletId != "main" && when (paymentToken.uppercase()) {
                        "ZEC" -> !wallet.zcashAddress.isNullOrEmpty()
                        else -> wallet.solanaAddress.isNotEmpty()
                    }
                }

                if (wallets.isNotEmpty()) {
                    val firstWallet = wallets.first()
                    currentWalletId = firstWallet.walletId
                    currentWalletName = firstWallet.name
                    currentWalletAddress = firstWallet.solanaAddress
                    currentZcashAddress = firstWallet.zcashAddress

                    val displayAddress = when (paymentToken.uppercase()) {
                        "ZEC" -> firstWallet.zcashAddress ?: ""
                        else -> firstWallet.solanaAddress
                    }

                    withContext(Dispatchers.Main) {
                        walletNameText.text = currentWalletName
                        walletAddressShort.text = formatAddressShort(displayAddress)
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        walletNameText.text = "No wallet"
                        walletAddressShort.text = "Set up $paymentToken wallet"
                        acceptButton.isEnabled = false
                        acceptButton.alpha = 0.5f
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallet info", e)
            }
        }
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@AcceptPaymentActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                val wallets = allWallets.filter { wallet ->
                    wallet.walletId != "main" && when (paymentToken.uppercase()) {
                        "ZEC" -> !wallet.zcashAddress.isNullOrEmpty()
                        else -> wallet.solanaAddress.isNotEmpty()
                    }
                }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@AcceptPaymentActivity, "No $paymentToken wallets found")
                        return@withContext
                    }

                    val bottomSheet = BottomSheetDialog(this@AcceptPaymentActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)

                    val displayMetrics = resources.displayMetrics
                    val screenHeight = displayMetrics.heightPixels
                    view.minimumHeight = (screenHeight * 0.6).toInt()

                    bottomSheet.setContentView(view)
                    bottomSheet.behavior.isDraggable = true
                    bottomSheet.behavior.isFitToContents = true
                    bottomSheet.behavior.skipCollapsed = true

                    bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
                    bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

                    view.post {
                        val parentView = view.parent as? View
                        parentView?.setBackgroundResource(android.R.color.transparent)
                    }

                    val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)

                    for (wallet in wallets) {
                        val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                        val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                        val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
                        val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

                        val displayAddress = when (paymentToken.uppercase()) {
                            "ZEC" -> wallet.zcashAddress ?: ""
                            else -> wallet.solanaAddress
                        }

                        walletName.text = wallet.name
                        walletBalance.text = formatAddressShort(displayAddress)

                        walletItemView.setOnClickListener {
                            switchToWallet(wallet)
                            bottomSheet.dismiss()
                        }

                        settingsBtn.visibility = View.GONE

                        walletListContainer.addView(walletItemView)
                    }

                    bottomSheet.show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallets", e)
            }
        }
    }

    private fun switchToWallet(wallet: Wallet) {
        currentWalletId = wallet.walletId
        currentWalletName = wallet.name
        currentWalletAddress = wallet.solanaAddress
        currentZcashAddress = wallet.zcashAddress

        val displayAddress = when (paymentToken.uppercase()) {
            "ZEC" -> wallet.zcashAddress ?: ""
            else -> wallet.solanaAddress
        }

        walletNameText.text = currentWalletName
        walletAddressShort.text = formatAddressShort(displayAddress)
    }

    private fun fetchPrice() {
        lifecycleScope.launch {
            try {
                val result = solanaService.getSolPrice()
                if (result.isSuccess) {
                    currentSolPrice = result.getOrNull() ?: 0.0
                    updateUsdDisplay()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch price", e)
            }
        }
    }

    private fun updateUsdDisplay() {
        if (currentSolPrice > 0 && paymentToken.uppercase() == "SOL") {
            val decimals = 9
            val divisor = Math.pow(10.0, decimals.toDouble())
            val humanAmount = paymentAmount.toDouble() / divisor
            val usdValue = humanAmount * currentSolPrice
            amountUsd.text = String.format("~ $%.2f USD", usdValue)
            amountUsd.visibility = View.VISIBLE
        } else {
            amountUsd.visibility = View.GONE
        }
    }

    private fun formatAddressShort(address: String): String {
        return if (address.length > 12) {
            "${address.take(6)}...${address.takeLast(4)}"
        } else {
            address
        }
    }

    private fun acceptPayment() {
        val receiveAddress = when (paymentToken.uppercase()) {
            "ZEC" -> currentZcashAddress
            else -> currentWalletAddress
        }

        if (receiveAddress.isNullOrEmpty()) {
            ThemedToast.show(this, "Please select a wallet to receive payment")
            return
        }

        acceptButton.isEnabled = false
        ThemedToast.show(this, "Accepting payment...")

        lifecycleScope.launch {
            try {
                if (contactId > 0 && paymentQuote != null) {
                    val messageService = MessageService(this@AcceptPaymentActivity)
                    val result = messageService.sendPaymentAcceptance(
                        contactId = contactId,
                        originalQuote = paymentQuote!!,
                        receiveAddress = receiveAddress
                    )

                    withContext(Dispatchers.Main) {
                        if (result.isSuccess) {
                            ThemedToast.show(this@AcceptPaymentActivity, "Payment accepted! Waiting for transfer...")
                            finish()
                        } else {
                            acceptButton.isEnabled = true
                            ThemedToast.show(this@AcceptPaymentActivity, "Failed to accept payment")
                        }
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        acceptButton.isEnabled = true
                        ThemedToast.show(this@AcceptPaymentActivity, "Invalid payment data")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to accept payment", e)
                withContext(Dispatchers.Main) {
                    acceptButton.isEnabled = true
                    ThemedToast.show(this@AcceptPaymentActivity, "Error: ${e.message}")
                }
            }
        }
    }

    private fun declinePayment() {
        ThemedToast.show(this, "Payment declined")
        finish()
    }
}
