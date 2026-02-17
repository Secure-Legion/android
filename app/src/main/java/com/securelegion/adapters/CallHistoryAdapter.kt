package com.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import androidx.core.content.ContextCompat
import com.google.android.material.color.MaterialColors
import com.securelegion.R
import com.securelegion.database.entities.CallHistory
import com.securelegion.database.entities.CallType
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * Adapter for Call History page
 */
class CallHistoryAdapter(
    private var callHistory: List<CallHistory> = emptyList(),
    private val onReCallClick: (CallHistory) -> Unit,
    private val onItemClick: (CallHistory) -> Unit
) : RecyclerView.Adapter<CallHistoryAdapter.HistoryViewHolder>() {

    class HistoryViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val callTypeIcon: ImageView = view.findViewById(R.id.callTypeIcon)
        val contactName: TextView = view.findViewById(R.id.contactName)
        val callInfo: TextView = view.findViewById(R.id.callInfo)
        val reCallButton: ImageView = view.findViewById(R.id.reCallButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): HistoryViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_call_history, parent, false)
        return HistoryViewHolder(view)
    }

    override fun onBindViewHolder(holder: HistoryViewHolder, position: Int) {
        val call = callHistory[position]

        // Set contact name
        holder.contactName.text = call.contactName

        // Set call type icon and color
        when (call.type) {
            CallType.OUTGOING -> {
                holder.callTypeIcon.setImageResource(R.drawable.ic_call)
                holder.callTypeIcon.setColorFilter(ContextCompat.getColor(holder.itemView.context, R.color.success_green))
            }
            CallType.INCOMING -> {
                holder.callTypeIcon.setImageResource(R.drawable.ic_call)
                holder.callTypeIcon.setColorFilter(MaterialColors.getColor(holder.itemView, androidx.appcompat.R.attr.colorPrimary))
            }
            CallType.MISSED -> {
                holder.callTypeIcon.setImageResource(R.drawable.ic_call)
                holder.callTypeIcon.setColorFilter(ContextCompat.getColor(holder.itemView.context, R.color.warning_red))
            }
        }

        // Format call info: "Incoming • Yesterday • 12:45"
        val callTypeText = when (call.type) {
            CallType.OUTGOING -> "Outgoing"
            CallType.INCOMING -> "Incoming"
            CallType.MISSED -> "Missed call"
        }
        val dateText = formatDate(call.timestamp)
        val timeText = formatTime(call.timestamp)
        val durationText = if (call.duration > 0) formatDuration(call.duration) else ""

        val infoText = if (durationText.isNotEmpty()) {
            "$callTypeText • $dateText • $durationText"
        } else {
            "$callTypeText • $dateText • $timeText"
        }
        holder.callInfo.text = infoText

        // Re-call button click
        holder.reCallButton.setOnClickListener {
            onReCallClick(call)
        }

        // Item click
        holder.itemView.setOnClickListener {
            onItemClick(call)
        }
    }

    override fun getItemCount(): Int = callHistory.size

    /**
     * Update call history list
     */
    fun updateHistory(newHistory: List<CallHistory>) {
        callHistory = newHistory
        notifyDataSetChanged()
    }

    /**
     * Format date to relative (Today, Yesterday, etc.)
     */
    private fun formatDate(timestamp: Long): String {
        val calendar = Calendar.getInstance()
        val today = calendar.get(Calendar.DAY_OF_YEAR)
        val todayYear = calendar.get(Calendar.YEAR)

        calendar.timeInMillis = timestamp
        val callDay = calendar.get(Calendar.DAY_OF_YEAR)
        val callYear = calendar.get(Calendar.YEAR)

        return when {
            callDay == today && callYear == todayYear -> "Today"
            callDay == today - 1 && callYear == todayYear -> "Yesterday"
            callYear == todayYear -> {
                val dateFormat = SimpleDateFormat("MMM d", Locale.getDefault())
                dateFormat.format(Date(timestamp))
            }
            else -> {
                val dateFormat = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
                dateFormat.format(Date(timestamp))
            }
        }
    }

    /**
     * Format time (e.g., "14:30")
     */
    private fun formatTime(timestamp: Long): String {
        val timeFormat = SimpleDateFormat("HH:mm", Locale.getDefault())
        return timeFormat.format(Date(timestamp))
    }

    /**
     * Format call duration (e.g., "5:23" for 5 minutes 23 seconds)
     */
    private fun formatDuration(durationSeconds: Long): String {
        val minutes = durationSeconds / 60
        val seconds = durationSeconds % 60
        return if (minutes > 0) {
            String.format("%d:%02d", minutes, seconds)
        } else {
            "${seconds}s"
        }
    }
}
