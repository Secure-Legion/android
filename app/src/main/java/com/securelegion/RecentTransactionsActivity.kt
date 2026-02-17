package com.securelegion

import com.securelegion.utils.GlassBottomSheetDialog
import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.TransactionAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.services.SolanaService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class RecentTransactionsActivity : AppCompatActivity() {

    private lateinit var transactionsList: RecyclerView
    private lateinit var loadingState: View
    private lateinit var emptyState: View

    private var walletAddress: String? = null
    private var walletZcashAddress: String? = null
    private var walletName: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_recent_transactions)

        transactionsList = findViewById(R.id.transactionsList)
        loadingState = findViewById(R.id.loadingState)
        emptyState = findViewById(R.id.emptyState)

        // Get wallet info from intent
        walletAddress = intent.getStringExtra("WALLET_ADDRESS")
        walletZcashAddress = intent.getStringExtra("WALLET_ZCASH_ADDRESS")
        walletName = intent.getStringExtra("WALLET_NAME")

        Log.d("RecentTransactions", "Opened for wallet: $walletName, SOL: $walletAddress, ZEC: $walletZcashAddress")

        setupClickListeners()
        loadTransactions()
    }

    override fun onResume() {
        super.onResume()
        // Auto-refresh transactions when returning to this page
        loadTransactions()
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Refresh button
        findViewById<View>(R.id.refreshButton).setOnClickListener {
            ThemedToast.show(this, "Refreshing transactions...")
            loadTransactions()
        }
    }

    private fun loadTransactions() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.d("RecentTransactions", "Loading transactions from blockchain")

                // Show loading state
                withContext(Dispatchers.Main) {
                    loadingState.visibility = View.VISIBLE
                    transactionsList.visibility = View.GONE
                    emptyState.visibility = View.GONE
                }

                // Get wallet address - use passed wallet or fallback to main wallet
                val solanaAddress = if (!walletAddress.isNullOrEmpty()) {
                    walletAddress!!
                } else {
                    val keyManager = KeyManager.getInstance(this@RecentTransactionsActivity)
                    keyManager.getSolanaAddress()
                }

                Log.d("RecentTransactions", "Fetching transactions for wallet: $walletName (this may take 30-60 seconds)")

                // Fetch transactions from blockchain (may take time for API to index new transactions)
                val solanaService = SolanaService(this@RecentTransactionsActivity)
                val result = solanaService.getRecentTransactions(solanaAddress, limit = 20)

                withContext(Dispatchers.Main) {
                    loadingState.visibility = View.GONE

                    if (result.isSuccess) {
                        val transactions = result.getOrNull() ?: emptyList()

                        if (transactions.isNotEmpty()) {
                            Log.i("RecentTransactions", "Loaded ${transactions.size} transactions")
                            transactionsList.visibility = View.VISIBLE
                            transactionsList.layoutManager = LinearLayoutManager(this@RecentTransactionsActivity)
                            transactionsList.adapter = TransactionAdapter(transactions) { transaction ->
                                openTransactionDetail(transaction)
                            }
                        } else {
                            Log.i("RecentTransactions", "No transactions found - blockchain may still be indexing recent activity")
                            emptyState.visibility = View.VISIBLE
                            ThemedToast.show(this@RecentTransactionsActivity, "No transactions found. If you just received funds, please wait 30-60 seconds and refresh.")
                        }
                    } else {
                        val errorMsg = result.exceptionOrNull()?.message ?: "Unknown error"
                        Log.e("RecentTransactions", "Failed to load transactions: $errorMsg")
                        emptyState.visibility = View.VISIBLE
                        ThemedToast.show(this@RecentTransactionsActivity, "Failed to load transactions: $errorMsg")
                    }
                }

            } catch (e: Exception) {
                Log.e("RecentTransactions", "Error loading transactions", e)
                withContext(Dispatchers.Main) {
                    loadingState.visibility = View.GONE
                    emptyState.visibility = View.VISIBLE
                    ThemedToast.show(this@RecentTransactionsActivity, "Error loading transactions: ${e.message}")
                }
            }
        }
    }

    private fun openTransactionDetail(transaction: SolanaService.TransactionInfo) {
        // Create bottom sheet dialog
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_transaction_detail, null)

        // Set minimum height
        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        val desiredHeight = (screenHeight * 0.85).toInt()
        view.minimumHeight = desiredHeight

        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Populate transaction details
        val txType = view.findViewById<android.widget.TextView>(R.id.txDetailType)
        val txChainIcon = view.findViewById<android.widget.ImageView>(R.id.txDetailChainIcon)
        val txAmount = view.findViewById<android.widget.TextView>(R.id.txDetailAmount)
        val txDate = view.findViewById<android.widget.TextView>(R.id.txDetailDate)
        val txStatus = view.findViewById<android.widget.TextView>(R.id.txDetailStatus)
        val txAddressLabel = view.findViewById<android.widget.TextView>(R.id.txDetailAddressLabel)
        val txAddress = view.findViewById<android.widget.TextView>(R.id.txDetailAddress)
        val txNetwork = view.findViewById<android.widget.TextView>(R.id.txDetailNetwork)
        val txNetworkFee = view.findViewById<android.widget.TextView>(R.id.txDetailNetworkFee)

        // Set transaction type
        val typeText = if (transaction.type == "send") "Sent" else "Received"
        txType?.text = typeText

        // Set chain icon
        txChainIcon?.setImageResource(R.drawable.ic_solana)

        // Set amount with prefix
        val prefix = if (transaction.type == "send") "-" else "+"
        txAmount?.text = "$prefix${String.format("%.6f", transaction.amount)} SOL"

        // Set date
        val dateFormat = java.text.SimpleDateFormat("MMM dd, yyyy 'at' h:mm a", java.util.Locale.US)
        val dateStr = dateFormat.format(java.util.Date(transaction.timestamp))
        txDate?.text = dateStr

        // Set status
        val statusText = transaction.status.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        txStatus?.text = statusText
        txStatus?.setTextColor(if (transaction.status == "success") 0xFF4CAF50.toInt() else 0xFFFF9800.toInt())

        // Set address label and value
        txAddressLabel?.text = if (transaction.type == "send") "To" else "From"
        val shortAddress = "${transaction.otherPartyAddress.take(4)}...${transaction.otherPartyAddress.takeLast(4)}"
        txAddress?.text = shortAddress

        // Set network
        txNetwork?.text = "Solana"

        // Set network fee
        txNetworkFee?.text = "~< 0.00001 SOL"

        // Copy address button
        view.findViewById<View>(R.id.txDetailCopyAddress)?.setOnClickListener {
            val clipboard = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            val clip = android.content.ClipData.newPlainText("Address", transaction.otherPartyAddress)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Address copied")
        }

        bottomSheet.show()
    }

}
