package com.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.services.ShadowWireService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class PoolActivityAdapter(
    private val items: List<ShadowWireService.PoolActivityItem>,
    private val onItemClick: (ShadowWireService.PoolActivityItem) -> Unit
) : RecyclerView.Adapter<PoolActivityAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val icon: ImageView = view.findViewById(R.id.activityIcon)
        val type: TextView = view.findViewById(R.id.activityType)
        val date: TextView = view.findViewById(R.id.activityDate)
        val amount: TextView = view.findViewById(R.id.activityAmount)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_pool_activity, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]

        // Set type label and icon
        when (item.type) {
            "deposit" -> {
                holder.type.text = "Deposit"
                holder.icon.setImageResource(R.drawable.ic_deposit)
            }
            "withdraw" -> {
                holder.type.text = "Withdrawal"
                holder.icon.setImageResource(R.drawable.ic_withdraw)
            }
            "internal_transfer" -> {
                holder.type.text = "Private Send"
                holder.icon.setImageResource(R.drawable.ic_shield)
            }
            "external_transfer" -> {
                holder.type.text = "Anonymous Send"
                holder.icon.setImageResource(R.drawable.ic_incognito)
            }
            else -> {
                holder.type.text = item.type.replaceFirstChar { it.uppercase() }
                holder.icon.setImageResource(R.drawable.ic_solana)
            }
        }

        // Set date
        if (item.timestamp > 0) {
            val dateFormat = SimpleDateFormat("MMM dd, yyyy 'at' h:mm a", Locale.US)
            holder.date.text = dateFormat.format(Date(item.timestamp))
        } else {
            holder.date.text = "Pending"
        }

        // Set amount with sign
        val prefix = when (item.type) {
            "deposit" -> "+"
            "withdraw" -> "-"
            "internal_transfer", "external_transfer" -> "-"
            else -> ""
        }
        holder.amount.text = "$prefix${String.format("%.4f", item.amount)} SOL"

        // Color: green for deposits, white for others
        holder.amount.setTextColor(
            if (item.type == "deposit") 0xFF4CAF50.toInt() else 0xFFFFFFFF.toInt()
        )

        holder.itemView.setOnClickListener { onItemClick(item) }
    }

    override fun getItemCount() = items.size
}
