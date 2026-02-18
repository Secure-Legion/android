package com.securelegion

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.services.JupiterService
import com.securelegion.services.SolanaService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SwapActivity : AppCompatActivity() {

    private lateinit var backButton: View

    // From (top) card
    private lateinit var fromTokenSelector: View
    private lateinit var fromTokenIcon: ImageView
    private lateinit var fromTokenText: TextView
    private lateinit var fromBalanceText: TextView
    private lateinit var fromAmountInput: EditText

    // To (bottom) card
    private lateinit var toTokenSelector: View
    private lateinit var toTokenIcon: ImageView
    private lateinit var toTokenText: TextView
    private lateinit var toBalanceText: TextView
    private lateinit var toAmountText: TextView

    // Swap button
    private lateinit var swapDirectionButton: View
    private lateinit var swapButton: Button

    private var fromToken = "SOL"
    private var toToken = "USDC"
    private var fromBalance = 0.0
    private var toBalance = 0.0

    // Selected wallets
    private var fromWallet: Wallet? = null
    private var toWallet: Wallet? = null
    private var availableWallets: List<Wallet> = emptyList()

    // Jupiter integration
    private val jupiterService = JupiterService()
    private var currentOrder: JupiterService.JupiterOrder? = null
    private val quoteHandler = Handler(Looper.getMainLooper())
    private var quoteRunnable: Runnable? = null
    private var isFetchingQuote = false

    // Supported tokens for Solana swap
    private val supportedTokens = listOf("SOL", "USDC", "USDT", "ZEC", "USD1", "SECURE")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_swap)

        initializeViews()
        setupClickListeners()
        setupTextWatcher()
        loadWalletBalances()
    }

    override fun onDestroy() {
        super.onDestroy()
        quoteRunnable?.let { quoteHandler.removeCallbacks(it) }
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)

        fromTokenSelector = findViewById(R.id.fromTokenSelector)
        fromTokenIcon = findViewById(R.id.fromTokenIcon)
        fromTokenText = findViewById(R.id.fromTokenText)
        fromBalanceText = findViewById(R.id.fromBalanceText)
        fromAmountInput = findViewById(R.id.fromAmountInput)

        toTokenSelector = findViewById(R.id.toTokenSelector)
        toTokenIcon = findViewById(R.id.toTokenIcon)
        toTokenText = findViewById(R.id.toTokenText)
        toBalanceText = findViewById(R.id.toBalanceText)
        toAmountText = findViewById(R.id.toAmountText)

        swapDirectionButton = findViewById(R.id.swapDirectionButton)
        swapButton = findViewById(R.id.swapButton)

        updateDisplay()
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener { finish() }

        swapDirectionButton.setOnClickListener { swapDirection() }

        swapButton.setOnClickListener { showSwapConfirmation() }

        fromTokenSelector.setOnClickListener { showTokenPicker(isFromToken = true) }

        toTokenSelector.setOnClickListener { showTokenPicker(isFromToken = false) }
    }

    private fun setupTextWatcher() {
        fromAmountInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}

            override fun afterTextChanged(s: Editable?) {
                // Cancel any pending quote fetch
                quoteRunnable?.let { quoteHandler.removeCallbacks(it) }
                currentOrder = null

                val inputText = s.toString()
                val inputAmount = inputText.toDoubleOrNull() ?: 0.0

                if (inputAmount <= 0) {
                    toAmountText.text = "0"
                    return
                }

                // Show loading state
                toAmountText.text = "..."

                // Debounce: fetch quote after 500ms of no typing
                quoteRunnable = Runnable { fetchQuote() }
                quoteHandler.postDelayed(quoteRunnable!!, 500)
            }
        })
    }

    private fun loadWalletBalances() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@SwapActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@SwapActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter to wallets with Solana addresses
                availableWallets = allWallets.filter {
                    it.walletId != "main" && it.solanaAddress.isNotEmpty()
                }

                withContext(Dispatchers.Main) {
                    if (availableWallets.isNotEmpty()) {
                        val defaultWallet = availableWallets.maxByOrNull { it.lastUsedAt }
                        if (defaultWallet != null) {
                            fromWallet = defaultWallet
                            toWallet = defaultWallet
                            loadBalanceForWallet(defaultWallet)
                        }
                    }
                    updateDisplay()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load wallet balances", e)
                withContext(Dispatchers.Main) {
                    updateDisplay()
                }
            }
        }
    }

    private fun loadBalanceForWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val solanaService = SolanaService(this@SwapActivity)

                // Load SOL balance
                val solBalanceResult = solanaService.getBalance(wallet.solanaAddress)
                val solBalance = solBalanceResult.getOrDefault(0.0)

                // Load SPL token balances
                val tokenResult = solanaService.getTokenAccounts(wallet.solanaAddress)
                val tokens = tokenResult.getOrDefault(emptyList())

                val usdcBalance = tokens.find { it.mint == JupiterService.USDC_MINT }?.balance ?: 0.0
                val usdtBalance = tokens.find { it.mint == JupiterService.USDT_MINT }?.balance ?: 0.0
                val zecBalance = tokens.find { it.mint == JupiterService.ZEC_MINT }?.balance ?: 0.0
                val usd1Balance = tokens.find { it.mint == JupiterService.USD1_MINT }?.balance ?: 0.0
                val secureBalance = tokens.find { it.mint == JupiterService.SECURE_MINT }?.balance ?: 0.0

                withContext(Dispatchers.Main) {
                    fromBalance = getTokenBalance(fromToken, solBalance, usdcBalance, usdtBalance, zecBalance, usd1Balance, secureBalance)
                    toBalance = getTokenBalance(toToken, solBalance, usdcBalance, usdtBalance, zecBalance, usd1Balance, secureBalance)
                    updateDisplay()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load balance for wallet ${wallet.name}", e)
            }
        }
    }

    private fun getTokenBalance(
        token: String,
        sol: Double,
        usdc: Double,
        usdt: Double,
        zec: Double = 0.0,
        usd1: Double = 0.0,
        secure: Double = 0.0
    ): Double = when (token) {
        "SOL" -> sol
        "USDC" -> usdc
        "USDT" -> usdt
        "ZEC" -> zec
        "USD1" -> usd1
        "SECURE" -> secure
        else -> 0.0
    }

    private fun swapDirection() {
        val tempToken = fromToken
        fromToken = toToken
        toToken = tempToken

        val tempBalance = fromBalance
        fromBalance = toBalance
        toBalance = tempBalance

        // Clear input and quote
        fromAmountInput.setText("")
        currentOrder = null

        updateDisplay()
    }

    private fun updateDisplay() {
        // Token names
        fromTokenText.text = fromToken
        toTokenText.text = toToken

        // Token icons
        fromTokenIcon.setImageResource(getTokenIcon(fromToken))
        toTokenIcon.setImageResource(getTokenIcon(toToken))

        // Balances
        fromBalanceText.text = "Balance: ${String.format("%.4f", fromBalance)} $fromToken"
        toBalanceText.text = "Balance: ${String.format("%.4f", toBalance)} $toToken"
    }

    private fun fetchQuote() {
        val inputText = fromAmountInput.text.toString()
        val inputAmount = inputText.toDoubleOrNull() ?: return

        if (inputAmount <= 0) return

        val wallet = fromWallet
        if (wallet == null) {
            ThemedToast.show(this, "No wallet selected")
            return
        }

        if (fromToken == toToken) {
            ThemedToast.show(this, "Select different tokens")
            return
        }

        isFetchingQuote = true
        toAmountText.text = "..."

        val inputMint = jupiterService.getMint(fromToken)
        val outputMint = jupiterService.getMint(toToken)
        val amountSmallest = jupiterService.toSmallestUnits(inputAmount, inputMint)

        lifecycleScope.launch {
            try {
                // Try with referral first, fallback without if it fails
                var result = withContext(Dispatchers.IO) {
                    jupiterService.getOrder(
                        inputMint = inputMint,
                        outputMint = outputMint,
                        amount = amountSmallest,
                        taker = wallet.solanaAddress
                    )
                }

                // If referral caused an error, retry without it
                if (result.isFailure) {
                    Log.w(TAG, "Quote with referral failed, retrying without: ${result.exceptionOrNull()?.message}")
                    result = withContext(Dispatchers.IO) {
                        jupiterService.getOrder(
                            inputMint = inputMint,
                            outputMint = outputMint,
                            amount = amountSmallest,
                            taker = wallet.solanaAddress,
                            referralAccount = null,
                            referralFee = null
                        )
                    }
                }

                result.onSuccess { order ->
                    currentOrder = order
                    val outputAmount = jupiterService.fromSmallestUnits(order.outAmount, outputMint)
                    toAmountText.text = String.format("%.4f", outputAmount)
                }.onFailure { e ->
                    Log.e(TAG, "Quote fetch failed", e)
                    toAmountText.text = "Error"
                    currentOrder = null
                    ThemedToast.show(this@SwapActivity, "Quote failed: ${e.message?.take(80)}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Quote fetch exception", e)
                toAmountText.text = "Error"
                currentOrder = null
                ThemedToast.show(this@SwapActivity, "Quote failed: ${e.message?.take(80)}")
            } finally {
                isFetchingQuote = false
            }
        }
    }

    private fun showSwapConfirmation() {
        val order = currentOrder
        if (order == null) {
            ThemedToast.show(this, "Enter an amount and wait for a quote")
            return
        }

        val inputText = fromAmountInput.text.toString()
        val inputAmount = inputText.toDoubleOrNull()
        if (inputAmount == null || inputAmount <= 0) {
            ThemedToast.show(this, "Enter a valid amount")
            return
        }

        if (inputAmount > fromBalance) {
            ThemedToast.show(this, "Insufficient balance")
            return
        }

        val inputMint = jupiterService.getMint(fromToken)
        val outputMint = jupiterService.getMint(toToken)
        val outputAmount = jupiterService.fromSmallestUnits(order.outAmount, outputMint)
        val platformFee = jupiterService.fromSmallestUnits(order.platformFeeAmount, inputMint)
        val networkFeeSol = order.signatureFeeLamports.toDouble() / 1_000_000_000.0

        val bottomSheetDialog = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_swap_confirm, null)
        bottomSheetDialog.setContentView(view)

        view.findViewById<TextView>(R.id.fromAmount).text =
            "${String.format("%.4f", inputAmount)} $fromToken"
        view.findViewById<TextView>(R.id.toAmount).text =
            "${String.format("%.4f", outputAmount)} $toToken"

        view.findViewById<TextView>(R.id.fromWallet).text =
            "$fromToken - ${fromWallet?.name ?: "Wallet"}"
        view.findViewById<TextView>(R.id.toWallet).text =
            "$toToken - ${fromWallet?.name ?: "Wallet"}"

        view.findViewById<TextView>(R.id.exchangeFee).text =
            if (platformFee > 0) String.format("%.6f %s", platformFee, fromToken) else "Free"
        view.findViewById<TextView>(R.id.networkFee).text =
            String.format("%.6f SOL", networkFeeSol)

        view.findViewById<Button>(R.id.confirmButton).setOnClickListener {
            bottomSheetDialog.dismiss()
            executeSwap()
        }

        bottomSheetDialog.show()
    }

    private fun executeSwap() {
        val order = currentOrder ?: return

        lifecycleScope.launch {
            try {
                swapButton.isEnabled = false
                swapButton.text = "Swapping..."

                val keyManager = KeyManager.getInstance(this@SwapActivity)
                val wallet = fromWallet ?: throw Exception("No wallet selected")

                val privateKey = if (!wallet.isMainWallet) {
                    keyManager.getWalletPrivateKey(wallet.walletId)
                        ?: throw Exception("Wallet key not found")
                } else {
                    keyManager.getSigningKeyBytes()
                }

                val signedTx = withContext(Dispatchers.IO) {
                    jupiterService.signTransaction(order.transaction, privateKey)
                }

                val result = withContext(Dispatchers.IO) {
                    jupiterService.execute(signedTx, order.requestId)
                }

                result.onSuccess { execResult ->
                    if (execResult.status == "Success") {
                        showSwapSuccess(order, execResult.signature)
                        fromWallet?.let { loadBalanceForWallet(it) }
                    } else {
                        ThemedToast.show(this@SwapActivity, "Swap failed: ${execResult.status}")
                    }
                }.onFailure { e ->
                    ThemedToast.show(this@SwapActivity, "Swap failed: ${e.message}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Swap execution failed", e)
                ThemedToast.show(this@SwapActivity, "Swap failed: ${e.message}")
            } finally {
                swapButton.isEnabled = true
                swapButton.text = "Swap"
                currentOrder = null
                fromAmountInput.setText("")
            }
        }
    }

    private fun showSwapSuccess(order: JupiterService.JupiterOrder, txSignature: String) {
        val bottomSheetDialog = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_swap_success, null)
        bottomSheetDialog.setContentView(view)

        val inputMint = jupiterService.getMint(fromToken)
        val outputMint = jupiterService.getMint(toToken)
        val inAmount = jupiterService.fromSmallestUnits(order.inAmount, inputMint)
        val outAmount = jupiterService.fromSmallestUnits(order.outAmount, outputMint)
        val platformFee = jupiterService.fromSmallestUnits(order.platformFeeAmount, inputMint)
        val networkFeeSol = order.signatureFeeLamports.toDouble() / 1_000_000_000.0

        val rate = if (inAmount > 0) outAmount / inAmount else 0.0

        view.findViewById<TextView>(R.id.fromDetails).text =
            "${String.format("%.4f", inAmount)} $fromToken"
        view.findViewById<TextView>(R.id.toDetails).text =
            "${String.format("%.4f", outAmount)} $toToken"
        view.findViewById<TextView>(R.id.exchangeRate).text =
            "1 $fromToken = ${String.format("%.4f", rate)} $toToken"
        view.findViewById<TextView>(R.id.exchangeFeeDetails).text =
            if (platformFee > 0) String.format("%.6f %s", platformFee, fromToken) else "Free"
        view.findViewById<TextView>(R.id.networkFeeDetails).text =
            String.format("%.6f SOL", networkFeeSol)

        val shortSig = if (txSignature.length > 16) {
            "${txSignature.take(8)}...${txSignature.takeLast(8)}"
        } else {
            txSignature
        }
        view.findViewById<TextView>(R.id.transactionId).text = shortSig

        view.findViewById<Button>(R.id.backToHomeButton).setOnClickListener {
            bottomSheetDialog.dismiss()
            finish()
        }

        bottomSheetDialog.show()
    }

    private fun showTokenPicker(isFromToken: Boolean) {
        val currentOther = if (isFromToken) toToken else fromToken

        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)
        bottomSheet.setContentView(view)

        val container = view.findViewById<LinearLayout>(R.id.walletListContainer)
            ?: run { bottomSheet.dismiss(); return }

        container.removeAllViews()

        // Hide the chain selector buttons (we're using this as a token picker)
        view.findViewById<View>(R.id.solanaChainButton)?.visibility = View.GONE
        view.findViewById<View>(R.id.zcashChainButton)?.visibility = View.GONE

        for (token in supportedTokens) {
            if (token == currentOther) continue

            val item = layoutInflater.inflate(R.layout.item_wallet_selector, container, false)
            item.findViewById<TextView>(R.id.walletName)?.text = token
            item.findViewById<TextView>(R.id.walletBalance)?.text = when (token) {
                "SOL" -> "Solana"
                "USDC" -> "USD Coin"
                "USDT" -> "Tether"
                "ZEC" -> "Zcash"
                "USD1" -> "World Liberty Financial USD"
                "SECURE" -> "Secure Legion"
                else -> ""
            }

            item.findViewById<ImageView>(R.id.walletIcon)?.setImageResource(getTokenIcon(token))
            item.findViewById<View>(R.id.walletSettingsBtn)?.visibility = View.GONE

            item.setOnClickListener {
                if (isFromToken) {
                    fromToken = token
                } else {
                    toToken = token
                }
                currentOrder = null
                fromAmountInput.setText("")
                updateDisplay()
                fromWallet?.let { loadBalanceForWallet(it) }
                bottomSheet.dismiss()
            }

            container.addView(item)
        }

        // Show wallet selector if multiple wallets
        if (availableWallets.size > 1) {
            val divider = TextView(this).apply {
                text = "Change Wallet"
                setTextColor(resources.getColor(R.color.text_gray, theme))
                textSize = 14f
                setPadding(20, 24, 20, 8)
            }
            container.addView(divider)

            for (wallet in availableWallets) {
                val item = layoutInflater.inflate(R.layout.item_wallet_selector, container, false)
                item.findViewById<TextView>(R.id.walletName)?.text = wallet.name
                val address = wallet.solanaAddress
                val shortAddr = if (address.length > 15) {
                    "${address.take(5)}.....${address.takeLast(6)}"
                } else {
                    address
                }
                item.findViewById<TextView>(R.id.walletBalance)?.text = shortAddr

                item.setOnClickListener {
                    fromWallet = wallet
                    toWallet = wallet
                    currentOrder = null
                    fromAmountInput.setText("")
                    loadBalanceForWallet(wallet)
                    bottomSheet.dismiss()
                }

                container.addView(item)
            }
        }

        bottomSheet.show()
    }

    private fun getTokenIcon(token: String): Int = when (token) {
        "SOL" -> R.drawable.ic_solana
        "USDC" -> R.drawable.ic_usdc
        "USDT" -> R.drawable.ic_usdt
        "ZEC" -> R.drawable.ic_zcash
        "USD1" -> R.drawable.ic_usd1
        "SECURE" -> R.drawable.ic_secure
        else -> R.drawable.ic_solana
    }

    companion object {
        private const val TAG = "SwapActivity"
    }
}
