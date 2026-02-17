package com.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.securelegion.R
import com.securelegion.services.SolanaService

class TransactionAdapter(
    private val transactions: List<SolanaService.TransactionInfo>,
    private val onTransactionClick: (SolanaService.TransactionInfo) -> Unit
) : RecyclerView.Adapter<TransactionAdapter.TransactionViewHolder>() {

    class TransactionViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val typeText: TextView = view.findViewById(R.id.transactionType)
        val addressText: TextView = view.findViewById(R.id.transactionAddress)
        val amountText: TextView = view.findViewById(R.id.transactionAmount)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): TransactionViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_transaction, parent, false)
        return TransactionViewHolder(view)
    }

    override fun onBindViewHolder(holder: TransactionViewHolder, position: Int) {
        val transaction = transactions[position]

        // Set type (Sent or Received)
        holder.typeText.text = if (transaction.type == "send") "Sent" else "Received"

        // Format address (first 4 ... last 4)
        val address = transaction.otherPartyAddress
        val formattedAddress = if (address.length >= 8) {
            "${address.take(4)}...${address.takeLast(4)}"
        } else {
            address
        }
        holder.addressText.text = formattedAddress

        // Format amount with + or - prefix
        val prefix = if (transaction.type == "send") "-" else "+"
        val formattedAmount = String.format("%.4f SOL", transaction.amount)
        holder.amountText.text = "$prefix$formattedAmount"

        // Set color based on type
        val color = if (transaction.type == "send") {
            MaterialColors.getColor(holder.itemView, com.google.android.material.R.attr.colorOnSurface)
        } else {
            ContextCompat.getColor(holder.itemView.context, R.color.success_green)
        }
        holder.amountText.setTextColor(color)

        // Click listener
        holder.itemView.setOnClickListener {
            onTransactionClick(transaction)
        }
    }

    override fun getItemCount() = transactions.size
}
