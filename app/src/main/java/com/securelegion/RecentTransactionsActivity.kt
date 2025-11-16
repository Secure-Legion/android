package com.securelegion

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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class RecentTransactionsActivity : AppCompatActivity() {

    private lateinit var transactionsList: RecyclerView
    private lateinit var loadingState: View
    private lateinit var emptyState: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_recent_transactions)

        transactionsList = findViewById(R.id.transactionsList)
        loadingState = findViewById(R.id.loadingState)
        emptyState = findViewById(R.id.emptyState)

        setupBottomNavigation()
        setupClickListeners()
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

                // Get wallet address
                val keyManager = KeyManager.getInstance(this@RecentTransactionsActivity)
                val solanaAddress = keyManager.getSolanaAddress()

                Log.d("RecentTransactions", "Fetching transactions for: $solanaAddress")

                // Fetch transactions from blockchain
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
                            Log.i("RecentTransactions", "No transactions found")
                            emptyState.visibility = View.VISIBLE
                        }
                    } else {
                        Log.e("RecentTransactions", "Failed to load transactions: ${result.exceptionOrNull()?.message}")
                        emptyState.visibility = View.VISIBLE
                    }
                }

            } catch (e: Exception) {
                Log.e("RecentTransactions", "Error loading transactions", e)
                withContext(Dispatchers.Main) {
                    loadingState.visibility = View.GONE
                    emptyState.visibility = View.VISIBLE
                }
            }
        }
    }

    private fun openTransactionDetail(transaction: SolanaService.TransactionInfo) {
        val intent = Intent(this, TransactionDetailActivity::class.java)
        intent.putExtra("TRANSACTION_SIGNATURE", transaction.signature)
        intent.putExtra("TRANSACTION_TYPE", transaction.type)
        intent.putExtra("TRANSACTION_AMOUNT", transaction.amount)
        intent.putExtra("TRANSACTION_TIMESTAMP", transaction.timestamp)
        intent.putExtra("TRANSACTION_STATUS", transaction.status)
        intent.putExtra("TRANSACTION_ADDRESS", transaction.otherPartyAddress)
        startActivity(intent)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
        } else {
            @Suppress("DEPRECATION")
            overridePendingTransition(0, 0)
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }
    }
}
