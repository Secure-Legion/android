package com.securelegion

import android.graphics.LinearGradient
import android.graphics.Shader
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SwapActivity : AppCompatActivity() {

    private lateinit var backButton: View
    private lateinit var menuButton: View

    // Currency dropdown
    private lateinit var currencyDropdown: View
    private lateinit var currencyLabel: TextView

    // From (top) card
    private lateinit var fromTokenText: TextView
    private lateinit var fromBalanceText: TextView
    private lateinit var fromAmountInput: EditText

    // To (bottom) card
    private lateinit var toTokenText: TextView
    private lateinit var toBalanceText: TextView
    private lateinit var toAmountText: TextView

    // Swap button
    private lateinit var swapDirectionButton: ImageView
    private lateinit var swapButton: Button

    private var fromToken = "SOL"
    private var toToken = "ZEC"
    private var fromBalance = 12000.00
    private var toBalance = 10399.00
    private var showUSD = true  // Toggle between USD and token display

    // Exchange rate (example, would come from API)
    private val exchangeRate = 0.9347  // 1 SOL = 0.9347 ZEC

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_swap)

        initializeViews()
        setupClickListeners()
        setupTextWatcher()
        loadWalletBalances()
        applySilverGradient()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        menuButton = findViewById(R.id.menuButton)

        currencyDropdown = findViewById(R.id.currencyDropdown)
        currencyLabel = findViewById(R.id.currencyLabel)

        fromTokenText = findViewById(R.id.fromTokenText)
        fromBalanceText = findViewById(R.id.fromBalanceText)
        fromAmountInput = findViewById(R.id.fromAmountInput)

        toTokenText = findViewById(R.id.toTokenText)
        toBalanceText = findViewById(R.id.toBalanceText)
        toAmountText = findViewById(R.id.toAmountText)

        swapDirectionButton = findViewById(R.id.swapDirectionButton)
        swapButton = findViewById(R.id.swapButton)

        updateDisplay()
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener {
            finish()
        }

        menuButton.setOnClickListener {
            // Show options menu (history, settings, etc.)
            ThemedToast.show(this, "Menu coming soon")
        }

        swapDirectionButton.setOnClickListener {
            swapDirection()
        }

        swapButton.setOnClickListener {
            showSwapConfirmation()
        }

        currencyDropdown.setOnClickListener {
            toggleCurrencyDisplay()
        }
    }

    private fun setupTextWatcher() {
        fromAmountInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}

            override fun afterTextChanged(s: Editable?) {
                updateToAmount()
            }
        })
    }

    private fun loadWalletBalances() {
        // TODO: Load real balances from blockchain services
        // For now, using placeholder values
        lifecycleScope.launch {
            try {
                // Placeholder values - will be replaced with real API calls
                fromBalance = 12000.00
                toBalance = 10399.00

                updateDisplay()
            } catch (e: Exception) {
                android.util.Log.e("SwapActivity", "Failed to load wallet balances", e)
            }
        }
    }

    private fun applySilverGradient() {
        // Apply silver gradient to amount text views
        fromAmountInput.post {
            val width = fromAmountInput.width.toFloat()
            if (width > 0) {
                val shader = LinearGradient(
                    0f, 0f, width, 0f,
                    intArrayOf(0xFFE8E8E8.toInt(), 0xFFC0C0C0.toInt(), 0xFFA8A8A8.toInt()),
                    floatArrayOf(0f, 0.5f, 1f),
                    Shader.TileMode.CLAMP
                )
                fromAmountInput.paint.shader = shader
                fromAmountInput.invalidate()
            }
        }

        toAmountText.post {
            val width = toAmountText.width.toFloat()
            if (width > 0) {
                val shader = LinearGradient(
                    0f, 0f, width, 0f,
                    intArrayOf(0xFFE8E8E8.toInt(), 0xFFC0C0C0.toInt(), 0xFFA8A8A8.toInt()),
                    floatArrayOf(0f, 0.5f, 1f),
                    Shader.TileMode.CLAMP
                )
                toAmountText.paint.shader = shader
                toAmountText.invalidate()
            }
        }
    }

    private fun toggleCurrencyDisplay() {
        showUSD = !showUSD
        currencyLabel.text = if (showUSD) "USD" else fromToken
        updateDisplay()
        updateToAmount()
    }

    private fun swapDirection() {
        // Swap from/to tokens
        val tempToken = fromToken
        fromToken = toToken
        toToken = tempToken

        val tempBalance = fromBalance
        fromBalance = toBalance
        toBalance = tempBalance

        // Clear input when swapping
        fromAmountInput.setText("")

        // Update currency label if not showing USD
        if (!showUSD) {
            currencyLabel.text = fromToken
        }

        updateDisplay()
    }

    private fun updateDisplay() {
        // Update token names
        fromTokenText.text = fromToken
        toTokenText.text = toToken

        // Update balances
        if (showUSD) {
            fromBalanceText.text = "Balance $${String.format("%,.2f", fromBalance)}"
            toBalanceText.text = "Balance $${String.format("%,.2f", toBalance)}"
        } else {
            // Show token amounts instead of USD
            val fromTokenBalance = fromBalance / 100.0  // Placeholder conversion
            val toTokenBalance = toBalance / 100.0  // Placeholder conversion
            fromBalanceText.text = "Balance ${String.format("%.4f", fromTokenBalance)} $fromToken"
            toBalanceText.text = "Balance ${String.format("%.4f", toTokenBalance)} $toToken"
        }
    }

    private fun updateToAmount() {
        val inputText = fromAmountInput.text.toString()

        if (inputText.isEmpty() || inputText == "$") {
            toAmountText.text = if (showUSD) "$0.00" else "0.0000"
            return
        }

        // Remove $ if present
        val cleanInput = inputText.replace("$", "")

        val inputAmount = cleanInput.toDoubleOrNull() ?: 0.0

        // Calculate exchange amount
        val outputAmount = inputAmount * exchangeRate

        if (showUSD) {
            toAmountText.text = "$${String.format("%.2f", outputAmount)}"
        } else {
            toAmountText.text = String.format("%.4f", outputAmount)
        }

        // Reapply gradient after text change
        applySilverGradient()
    }

    private fun showSwapConfirmation() {
        val inputText = fromAmountInput.text.toString().replace("$", "")

        if (inputText.isEmpty()) {
            ThemedToast.show(this, "Please enter an amount")
            return
        }

        val inputAmount = inputText.toDoubleOrNull()

        if (inputAmount == null) {
            ThemedToast.show(this, "Invalid amount")
            return
        }

        if (inputAmount <= 0) {
            ThemedToast.show(this, "Amount must be greater than zero")
            return
        }

        if (inputAmount > fromBalance) {
            ThemedToast.show(this, "Insufficient balance")
            return
        }

        val outputAmount = inputAmount * exchangeRate
        val exchangeFee = inputAmount * 0.005  // 0.5% fee
        val networkFee = 0.0

        // Create and show bottom sheet
        val bottomSheetDialog = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_swap_confirm, null)
        bottomSheetDialog.setContentView(view)

        // Populate amounts
        val fromAmountView = view.findViewById<TextView>(R.id.fromAmount)
        val toAmountView = view.findViewById<TextView>(R.id.toAmount)

        if (showUSD) {
            fromAmountView.text = "$${String.format("%.2f", inputAmount)}"
            toAmountView.text = "$${String.format("%.2f", outputAmount)}"
        } else {
            fromAmountView.text = String.format("%.4f", inputAmount)
            toAmountView.text = String.format("%.4f", outputAmount)
        }

        // Populate wallet details
        view.findViewById<TextView>(R.id.fromWallet).text = "$fromToken - Wallet 1"
        view.findViewById<TextView>(R.id.toWallet).text = "$toToken - Wallet 2"

        // Populate fees
        view.findViewById<TextView>(R.id.exchangeFee).text = String.format("%.2f", exchangeFee)
        view.findViewById<TextView>(R.id.networkFee).text = String.format("%.2f", networkFee)

        // Set up confirm button
        view.findViewById<Button>(R.id.confirmButton).setOnClickListener {
            bottomSheetDialog.dismiss()
            executeSwap()
        }

        bottomSheetDialog.show()
    }

    private fun executeSwap() {
        val inputText = fromAmountInput.text.toString().replace("$", "")

        if (inputText.isEmpty()) {
            ThemedToast.show(this, "Please enter an amount")
            return
        }

        val inputAmount = inputText.toDoubleOrNull()

        if (inputAmount == null) {
            ThemedToast.show(this, "Invalid amount")
            return
        }

        if (inputAmount <= 0) {
            ThemedToast.show(this, "Amount must be greater than zero")
            return
        }

        if (inputAmount > fromBalance) {
            ThemedToast.show(this, "Insufficient balance")
            return
        }

        lifecycleScope.launch {
            try {
                // TODO: Implement actual swap functionality with blockchain APIs
                // For now, just simulate the swap
                val outputAmount: Double
                val exchangeFee: Double

                withContext(Dispatchers.IO) {
                    outputAmount = inputAmount * exchangeRate
                    exchangeFee = inputAmount * 0.005

                    // Update local balances (placeholder - not persisted)
                    fromBalance -= inputAmount
                    toBalance += outputAmount

                    // Simulate network delay
                    kotlinx.coroutines.delay(500)
                }

                withContext(Dispatchers.Main) {
                    fromAmountInput.setText("")
                    updateDisplay()
                    showSwapSuccess(inputAmount, outputAmount, exchangeFee)
                }
            } catch (e: Exception) {
                android.util.Log.e("SwapActivity", "Failed to execute swap", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@SwapActivity, "Swap failed: ${e.message}")
                }
            }
        }
    }

    private fun showSwapSuccess(inputAmount: Double, outputAmount: Double, exchangeFee: Double) {
        val bottomSheetDialog = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_swap_success, null)
        bottomSheetDialog.setContentView(view)

        // Populate swap details
        if (showUSD) {
            view.findViewById<TextView>(R.id.fromDetails).text = "$${String.format("%.2f", inputAmount)} $fromToken"
            view.findViewById<TextView>(R.id.toDetails).text = "$${String.format("%.2f", outputAmount)} $toToken"
            view.findViewById<TextView>(R.id.exchangeFeeDetails).text = "$${String.format("%.2f", exchangeFee)}"
        } else {
            view.findViewById<TextView>(R.id.fromDetails).text = "${String.format("%.4f", inputAmount)} $fromToken"
            view.findViewById<TextView>(R.id.toDetails).text = "${String.format("%.4f", outputAmount)} $toToken"
            view.findViewById<TextView>(R.id.exchangeFeeDetails).text = "${String.format("%.4f", exchangeFee)}"
        }

        view.findViewById<TextView>(R.id.exchangeRate).text = "1 $fromToken = $exchangeRate $toToken"
        view.findViewById<TextView>(R.id.networkFeeDetails).text = "$0.00"
        view.findViewById<TextView>(R.id.transactionId).text = "0x${System.currentTimeMillis().toString(16).takeLast(8)}"

        // Set up back to home button
        view.findViewById<Button>(R.id.backToHomeButton).setOnClickListener {
            bottomSheetDialog.dismiss()
            finish()
        }

        bottomSheetDialog.show()
    }
}
