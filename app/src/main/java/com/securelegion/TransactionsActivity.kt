package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.securelegion.utils.ThemedToast
// import com.securelegion.utils.finishWithSlideAnimation
// import com.securelegion.utils.startActivityWithSlideAnimation

class TransactionsActivity : AppCompatActivity() {

    private lateinit var swipeRefresh: SwipeRefreshLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transactions)

        setupSwipeRefresh()
        setupClickListeners()
        setupBottomNav()
    }

    private fun setupSwipeRefresh() {
        swipeRefresh = findViewById(R.id.swipeRefresh)
        swipeRefresh.setColorSchemeResources(
            R.color.primary_blue,
            R.color.success_green,
            R.color.text_white
        )
        swipeRefresh.setOnRefreshListener {
            // Simulate refreshing transactions
            Handler(Looper.getMainLooper()).postDelayed({
                swipeRefresh.isRefreshing = false
                ThemedToast.show(this, "Transactions updated")
            }, 1500)
        }
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Transaction 1 - Received SOL
        findViewById<View>(R.id.transaction1).setOnClickListener {
            openTransactionDetail("Received", "+0.0008 SOL", "Dec 28, 2024 at 2:45 PM")
        }

        // Transaction 2 - Sent SOL
        findViewById<View>(R.id.transaction2).setOnClickListener {
            openTransactionDetail("Sent", "-0.0002 SOL", "Dec 23, 2024 at 10:30 AM")
        }

        // Transaction 3 - Received USDC
        findViewById<View>(R.id.transaction3).setOnClickListener {
            openTransactionDetail("Received", "+10.00 USDC", "Dec 21, 2024 at 4:15 PM")
        }

        // Transaction 4 - Sent USDC
        findViewById<View>(R.id.transaction4).setOnClickListener {
            openTransactionDetail("Sent", "-5.00 USDC", "Dec 14, 2024 at 9:20 AM")
        }

        // Transaction 5 - Received SOL
        findViewById<View>(R.id.transaction5).setOnClickListener {
            openTransactionDetail("Received", "+0.0005 SOL", "Dec 7, 2024 at 3:50 PM")
        }
    }

    private fun openTransactionDetail(type: String, amount: String, date: String) {
        val intent = Intent(this, TransactionDetailActivity::class.java)
        intent.putExtra("TRANSACTION_TYPE", type)
        intent.putExtra("TRANSACTION_AMOUNT", amount)
        intent.putExtra("TRANSACTION_DATE", date)
        startActivity(intent)
    }

    private fun setupBottomNav() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { _, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            bottomNav.setPadding(bottomNav.paddingLeft, bottomNav.paddingTop, bottomNav.paddingRight, 0)
            windowInsets
        }

        BottomNavigationHelper.setupBottomNavigation(this)
    }
}
