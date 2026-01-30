package com.securelegion

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.adapters.PoolActivityAdapter
import com.securelegion.services.ShadowWireService
import com.securelegion.utils.ThemedToast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class PoolActivityActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PoolActivityActivity"
    }

    private lateinit var activityList: RecyclerView
    private lateinit var loadingState: View
    private lateinit var emptyState: View

    private var walletId: String = "main"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pool_activity)

        walletId = intent.getStringExtra("WALLET_ID") ?: "main"

        activityList = findViewById(R.id.activityList)
        loadingState = findViewById(R.id.loadingState)
        emptyState = findViewById(R.id.emptyState)

        setupClickListeners()
        loadPoolActivity()
    }

    override fun onResume() {
        super.onResume()
        loadPoolActivity()
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        findViewById<View>(R.id.refreshButton).setOnClickListener {
            ThemedToast.show(this, "Refreshing pool activity...")
            loadPoolActivity()
        }
    }

    private fun loadPoolActivity() {
        Log.d(TAG, "Loading pool activity from local storage")

        loadingState.visibility = View.GONE

        val shadowWireService = ShadowWireService(this, walletId)
        val items = shadowWireService.getPoolHistory(limit = 20)

        if (items.isNotEmpty()) {
            Log.i(TAG, "Loaded ${items.size} pool activity items")
            activityList.visibility = View.VISIBLE
            emptyState.visibility = View.GONE
            activityList.layoutManager = LinearLayoutManager(this)
            activityList.adapter = PoolActivityAdapter(items) { item ->
                openActivityDetail(item)
            }
        } else {
            Log.i(TAG, "No pool activity found")
            activityList.visibility = View.GONE
            emptyState.visibility = View.VISIBLE
        }
    }

    private fun openActivityDetail(item: ShadowWireService.PoolActivityItem) {
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
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        // Populate detail views
        val txType = view.findViewById<TextView>(R.id.txDetailType)
        val txChainIcon = view.findViewById<ImageView>(R.id.txDetailChainIcon)
        val txAmount = view.findViewById<TextView>(R.id.txDetailAmount)
        val txDate = view.findViewById<TextView>(R.id.txDetailDate)
        val txStatus = view.findViewById<TextView>(R.id.txDetailStatus)
        val txAddressLabel = view.findViewById<TextView>(R.id.txDetailAddressLabel)
        val txAddress = view.findViewById<TextView>(R.id.txDetailAddress)
        val txNetwork = view.findViewById<TextView>(R.id.txDetailNetwork)
        val txNetworkFee = view.findViewById<TextView>(R.id.txDetailNetworkFee)

        // Type
        val typeText = when (item.type) {
            "deposit" -> "Deposited"
            "withdraw" -> "Withdrew"
            "internal_transfer" -> "Private Send"
            "external_transfer" -> "Anonymous Send"
            else -> item.type.replaceFirstChar { it.uppercase() }
        }
        txType?.text = typeText

        txChainIcon?.setImageResource(R.drawable.ic_solana)

        // Amount
        val prefix = when (item.type) {
            "deposit" -> "+"
            "withdraw" -> "-"
            "internal_transfer", "external_transfer" -> "-"
            else -> ""
        }
        txAmount?.text = "$prefix${String.format("%.4f", item.amount)} SOL"

        // Date
        if (item.timestamp > 0) {
            val dateFormat = SimpleDateFormat("MMM dd, yyyy 'at' h:mm a", Locale.US)
            txDate?.text = dateFormat.format(Date(item.timestamp))
        } else {
            txDate?.text = "Pending"
        }

        // Status
        val statusText = item.status.replaceFirstChar { it.uppercase() }
        txStatus?.text = statusText
        txStatus?.setTextColor(
            when (item.status) {
                "confirmed" -> 0xFF4CAF50.toInt()
                "failed" -> 0xFFFF5252.toInt()
                else -> 0xFFFF9800.toInt()
            }
        )

        // Address
        if (item.recipient.isNotEmpty()) {
            txAddressLabel?.text = "To"
            txAddress?.text = "${item.recipient.take(4)}...${item.recipient.takeLast(4)}"
        } else if (item.txSignature.isNotEmpty()) {
            txAddressLabel?.text = "Tx"
            txAddress?.text = "${item.txSignature.take(8)}...${item.txSignature.takeLast(4)}"
        } else {
            txAddressLabel?.text = "Type"
            txAddress?.text = typeText
        }

        txNetwork?.text = "Solana (Privacy Pool)"
        txNetworkFee?.text = "0.5% pool fee"

        // Copy tx signature
        view.findViewById<View>(R.id.txDetailCopyAddress)?.setOnClickListener {
            val textToCopy = if (item.txSignature.isNotEmpty()) item.txSignature else item.recipient
            if (textToCopy.isNotEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Transaction", textToCopy))
                ThemedToast.show(this, "Copied to clipboard")
            }
        }

        bottomSheet.show()
    }
}
