package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import android.widget.Button
import com.securelegion.crypto.KeyManager
import com.securelegion.services.ShadowWireService
import com.securelegion.services.SolanaService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * ShadowWire Privacy Pool Activity
 *
 * Provides UI for depositing, withdrawing, and transferring SOL
 * through the ShadowWire privacy pool using Bulletproof ZK proofs.
 */
class ShadowWireActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ShadowWireActivity"
        private const val LAMPORTS_PER_SOL = 1_000_000_000L
        private const val MIN_SOL = 0.01
    }

    private lateinit var keyManager: KeyManager
    private lateinit var shadowWireService: ShadowWireService
    private lateinit var solanaService: SolanaService

    private lateinit var poolBalanceAmount: TextView
    private lateinit var poolBalanceSubtext: TextView

    private var currentPoolBalance = 0.0
    private var currentSolPrice = 0.0
    private var isShowingUSD = false
    private var walletId: String = "main"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_shadowwire)

        walletId = intent.getStringExtra("WALLET_ID") ?: "main"
        keyManager = KeyManager.getInstance(this)
        shadowWireService = ShadowWireService(this, walletId)
        solanaService = SolanaService(this)

        initializeViews()
        setupClickListeners()
        loadPoolBalance()
    }

    private fun initializeViews() {
        poolBalanceAmount = findViewById(R.id.poolBalanceAmount)
        poolBalanceSubtext = findViewById(R.id.poolBalanceSubtext)

        // Pool balance USD/SOL toggle
        findViewById<View>(R.id.poolBalanceToggle).setOnClickListener {
            isShowingUSD = !isShowingUSD
            updatePoolBalanceDisplay()
        }
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<View>(R.id.historyButton).setOnClickListener {
            val intent = Intent(this, PoolActivityActivity::class.java)
            intent.putExtra("WALLET_ID", walletId)
            startActivity(intent)
        }
        findViewById<View>(R.id.depositButton).setOnClickListener { showActionDialog(ActionType.DEPOSIT) }
        findViewById<View>(R.id.withdrawButton).setOnClickListener { showActionDialog(ActionType.WITHDRAW) }
        findViewById<View>(R.id.privateSendButton).setOnClickListener { showActionDialog(ActionType.PRIVATE_SEND) }
        findViewById<View>(R.id.anonSendButton).setOnClickListener { showActionDialog(ActionType.ANON_SEND) }
    }

    private fun loadPoolBalance() {
        poolBalanceSubtext.text = "Loading..."
        lifecycleScope.launch {
            // Fetch SOL price in parallel
            val priceResult = withContext(Dispatchers.IO) {
                solanaService.getSolPrice()
            }
            priceResult.onSuccess { price -> currentSolPrice = price }

            val result = withContext(Dispatchers.IO) {
                shadowWireService.getPoolBalance()
            }
            result.onSuccess { balance ->
                currentPoolBalance = balance.available
                updatePoolBalanceDisplay()
                poolBalanceSubtext.text = "Total deposited: ${formatSol(balance.deposited)} SOL"
            }
            result.onFailure { e ->
                Log.e(TAG, "Failed to load pool balance", e)
                poolBalanceAmount.text = "-- SOL"
                poolBalanceSubtext.text = "Could not load balance"
            }
        }
    }

    private fun updatePoolBalanceDisplay() {
        if (isShowingUSD && currentSolPrice > 0) {
            val usdValue = currentPoolBalance * currentSolPrice
            poolBalanceAmount.text = String.format("$%,.2f", usdValue)
        } else {
            poolBalanceAmount.text = "${formatSol(currentPoolBalance)} SOL"
        }
    }

    // --- Action Dialog ---

    private enum class ActionType {
        DEPOSIT, WITHDRAW, PRIVATE_SEND, ANON_SEND
    }

    private fun showActionDialog(type: ActionType) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.dialog_shadowwire_action, null)
        bottomSheet.setContentView(view)

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Transparent backgrounds
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        // Get views
        val dialogTitle = view.findViewById<TextView>(R.id.dialogTitle)
        val recipientContainer = view.findViewById<View>(R.id.recipientContainer)
        val recipientInput = view.findViewById<EditText>(R.id.recipientInput)
        val amountLabel = view.findViewById<TextView>(R.id.amountLabel)
        val amountInput = view.findViewById<EditText>(R.id.amountInput)
        val currencyToggleLabel = view.findViewById<TextView>(R.id.currencyToggleLabel)
        val currencyToggle = view.findViewById<ImageView>(R.id.currencyToggle)
        val feeAmount = view.findViewById<TextView>(R.id.feeAmount)
        val netLabel = view.findViewById<TextView>(R.id.netLabel)
        val netAmount = view.findViewById<TextView>(R.id.netAmount)
        val confirmButton = view.findViewById<Button>(R.id.confirmButton)
        val progressBar = view.findViewById<ProgressBar>(R.id.progressBar)

        // Dialog currency toggle state
        var dialogShowingUSD = false
        fun updateDialogCurrency() {
            if (dialogShowingUSD) {
                amountLabel.text = "Amount (USD)"
                currencyToggleLabel.text = "USD"
                amountInput.hint = "0.00"
            } else {
                amountLabel.text = "Amount (SOL)"
                currencyToggleLabel.text = "SOL"
                amountInput.hint = "0.00"
            }
            // Clear input on toggle to avoid confusion
            amountInput.text.clear()
        }
        currencyToggle.setOnClickListener {
            dialogShowingUSD = !dialogShowingUSD
            updateDialogCurrency()
        }

        // Configure based on action type
        when (type) {
            ActionType.DEPOSIT -> {
                dialogTitle.text = "Deposit to Pool"
                netLabel.text = "Pool receives"
                confirmButton.text = "Deposit"
            }
            ActionType.WITHDRAW -> {
                dialogTitle.text = "Withdraw from Pool"
                netLabel.text = "You receive"
                confirmButton.text = "Withdraw"
            }
            ActionType.PRIVATE_SEND -> {
                dialogTitle.text = "Private Send"
                recipientContainer.visibility = View.VISIBLE
                netLabel.text = "Recipient receives"
                confirmButton.text = "Send Privately"
            }
            ActionType.ANON_SEND -> {
                dialogTitle.text = "Anonymous Send"
                recipientContainer.visibility = View.VISIBLE
                netLabel.text = "Recipient receives"
                confirmButton.text = "Send Anonymously"
            }
        }

        // Live fee calculation
        amountInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val inputVal = s.toString().toDoubleOrNull() ?: 0.0
                val amountSol = if (dialogShowingUSD && currentSolPrice > 0) inputVal / currentSolPrice else inputVal
                val amountLamports = (amountSol * LAMPORTS_PER_SOL).toLong()
                val fee = shadowWireService.calculateFee(amountLamports)
                feeAmount.text = "${formatSol(fee.feeLamports.toDouble() / LAMPORTS_PER_SOL)} SOL"
                netAmount.text = "${formatSol(fee.netLamports.toDouble() / LAMPORTS_PER_SOL)} SOL"
            }
        })

        // Confirm action
        confirmButton.setOnClickListener {
            val amountStr = amountInput.text.toString()
            val inputVal = amountStr.toDoubleOrNull()
            if (inputVal == null || inputVal <= 0) {
                ThemedToast.show(this, "Enter a valid amount")
                return@setOnClickListener
            }

            // Convert USD to SOL if needed
            val amountSol = if (dialogShowingUSD && currentSolPrice > 0) inputVal / currentSolPrice else inputVal

            // Minimum amount check (on-chain program requires >= 0.01 SOL)
            if (amountSol < MIN_SOL) {
                ThemedToast.show(this, "Minimum amount is $MIN_SOL SOL")
                return@setOnClickListener
            }

            val amountLamports = (amountSol * LAMPORTS_PER_SOL).toLong()
            val displayStr = formatSol(amountSol)

            // Withdraw: must withdraw all or leave at least 0.01 SOL in pool
            if (type == ActionType.WITHDRAW && currentPoolBalance > 0) {
                val remaining = currentPoolBalance - amountSol
                if (remaining > 0 && remaining < MIN_SOL) {
                    ThemedToast.show(this, "Withdraw all or leave at least $MIN_SOL SOL in the pool")
                    return@setOnClickListener
                }
            }

            // Validate recipient for transfer types
            val recipient = recipientInput.text.toString().trim()
            if ((type == ActionType.PRIVATE_SEND || type == ActionType.ANON_SEND) && recipient.isEmpty()) {
                ThemedToast.show(this, "Enter a recipient address")
                return@setOnClickListener
            }

            // Show loading state
            confirmButton.visibility = View.INVISIBLE
            progressBar.visibility = View.VISIBLE

            lifecycleScope.launch {
                val result = withContext(Dispatchers.IO) {
                    when (type) {
                        ActionType.DEPOSIT -> {
                            shadowWireService.deposit(amountLamports).fold(
                                onSuccess = { depositResult ->
                                    if (depositResult.unsignedTx.isNotEmpty()) {
                                        shadowWireService.signAndBroadcast(depositResult.unsignedTx).map { txSig ->
                                            "Deposited $displayStr SOL to privacy pool\nTx: ${txSig.take(16)}..."
                                        }
                                    } else {
                                        Result.success("Deposited $displayStr SOL to privacy pool")
                                    }
                                },
                                onFailure = { Result.failure(it) }
                            )
                        }
                        ActionType.WITHDRAW -> {
                            shadowWireService.withdraw(amountLamports).map { withdrawResult ->
                                "Withdrew $displayStr SOL from privacy pool" +
                                    if (withdrawResult.txSignature.isNotEmpty()) "\nTx: ${withdrawResult.txSignature.take(16)}..." else ""
                            }
                        }
                        ActionType.PRIVATE_SEND -> shadowWireService.internalTransfer(recipient, amountLamports)
                            .map { "Sent $displayStr SOL privately" + if (it.txSignature.isNotEmpty()) "\nTx: ${it.txSignature.take(16)}..." else "" }
                        ActionType.ANON_SEND -> shadowWireService.externalTransfer(recipient, amountLamports)
                            .map { "Sent $displayStr SOL anonymously" + if (it.txSignature.isNotEmpty()) "\nTx: ${it.txSignature.take(16)}..." else "" }
                    }
                }

                result.onSuccess { message ->
                    Log.i(TAG, "Action success: $message")

                    // Save activity locally
                    val activityType = when (type) {
                        ActionType.DEPOSIT -> "deposit"
                        ActionType.WITHDRAW -> "withdraw"
                        ActionType.PRIVATE_SEND -> "internal_transfer"
                        ActionType.ANON_SEND -> "external_transfer"
                    }
                    // Extract tx signature from message if present
                    val txSig = Regex("Tx: ([A-Za-z0-9]+)").find(message)?.groupValues?.getOrNull(1) ?: ""
                    shadowWireService.savePoolActivity(
                        ShadowWireService.PoolActivityItem(
                            type = activityType,
                            amount = amountSol,
                            timestamp = System.currentTimeMillis(),
                            txSignature = txSig,
                            recipient = if (type == ActionType.PRIVATE_SEND || type == ActionType.ANON_SEND) recipient else "",
                            status = "confirmed"
                        )
                    )

                    bottomSheet.dismiss()
                    showSuccessDialog(type, displayStr, message)
                    loadPoolBalance()
                }
                result.onFailure { e ->
                    Log.e(TAG, "Action failed", e)
                    ThemedToast.show(this@ShadowWireActivity, e.message ?: "Operation failed")
                    confirmButton.visibility = View.VISIBLE
                    progressBar.visibility = View.GONE
                }
            }
        }

        bottomSheet.show()
    }

    private fun showSuccessDialog(type: ActionType, amount: String, details: String) {
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_transaction_detail, null)

        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        view.minimumHeight = (screenHeight * 0.85).toInt()

        bottomSheet.setContentView(view)
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        view.post { (view.parent as? View)?.setBackgroundResource(android.R.color.transparent) }

        // Type title
        val txType = view.findViewById<TextView>(R.id.txDetailType)
        val title = when (type) {
            ActionType.DEPOSIT -> "Deposit Successful"
            ActionType.WITHDRAW -> "Withdrawal Successful"
            ActionType.PRIVATE_SEND -> "Private Send Successful"
            ActionType.ANON_SEND -> "Anonymous Send Successful"
        }
        txType?.text = title

        // Chain icon
        view.findViewById<ImageView>(R.id.txDetailChainIcon)?.setImageResource(R.drawable.ic_solana)

        // Amount
        val prefix = when (type) {
            ActionType.DEPOSIT -> "+"
            ActionType.WITHDRAW -> "-"
            ActionType.PRIVATE_SEND, ActionType.ANON_SEND -> "-"
        }
        view.findViewById<TextView>(R.id.txDetailAmount)?.text = "$prefix$amount SOL"

        // Date — now
        val dateFormat = java.text.SimpleDateFormat("MMM dd, yyyy 'at' h:mm a", java.util.Locale.US)
        view.findViewById<TextView>(R.id.txDetailDate)?.text = dateFormat.format(java.util.Date())

        // Status
        val txStatus = view.findViewById<TextView>(R.id.txDetailStatus)
        txStatus?.text = "Confirmed"
        txStatus?.setTextColor(0xFF4CAF50.toInt())

        // Tx signature — extract from details message
        val txSig = Regex("Tx: ([A-Za-z0-9]+)").find(details)?.groupValues?.getOrNull(1) ?: ""
        val txAddressLabel = view.findViewById<TextView>(R.id.txDetailAddressLabel)
        val txAddress = view.findViewById<TextView>(R.id.txDetailAddress)

        if (txSig.isNotEmpty()) {
            txAddressLabel?.text = "Tx"
            txAddress?.text = "${txSig.take(8)}...${txSig.takeLast(4)}"
        } else {
            txAddressLabel?.text = "Type"
            txAddress?.text = title.replace(" Successful", "")
        }

        // Network
        view.findViewById<TextView>(R.id.txDetailNetwork)?.text = "Solana (Privacy Pool)"

        // Fee
        val fee = shadowWireService.calculateFee((amount.toDoubleOrNull()?.times(LAMPORTS_PER_SOL))?.toLong() ?: 0L)
        view.findViewById<TextView>(R.id.txDetailNetworkFee)?.text = "${formatSol(fee.feeLamports.toDouble() / LAMPORTS_PER_SOL)} SOL (0.5%)"

        // Copy tx signature
        view.findViewById<View>(R.id.txDetailCopyAddress)?.setOnClickListener {
            if (txSig.isNotEmpty()) {
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Transaction", txSig))
                ThemedToast.show(this, "Tx signature copied")
            }
        }

        bottomSheet.show()
    }

    private fun formatSol(amount: Double): String {
        return if (amount == 0.0) "0.000" else String.format("%.4f", amount)
    }
}
