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
import java.util.Date
import java.util.Locale

/**
 * Data class for contacts that can be called
 */
data class CallableContact(
    val contactId: Long,
    val contactName: String,
    val voiceOnion: String,
    val lastCall: CallHistory? = null
)

/**
 * Adapter for New Call page contact list
 */
class NewCallContactsAdapter(
    private var contacts: List<CallableContact> = emptyList(),
    private val onCallClick: (CallableContact) -> Unit
) : RecyclerView.Adapter<NewCallContactsAdapter.ContactViewHolder>() {

    private var filteredContacts: List<CallableContact> = contacts

    class ContactViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val contactInitial: TextView = view.findViewById(R.id.contactInitial)
        val contactName: TextView = view.findViewById(R.id.contactName)
        val lastCallStatus: TextView = view.findViewById(R.id.lastCallStatus)
        val callButton: ImageView = view.findViewById(R.id.callButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_new_call_contact, parent, false)
        return ContactViewHolder(view)
    }

    override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
        val contact = filteredContacts[position]

        // Set contact initial
        val initial = contact.contactName.firstOrNull()?.uppercase() ?: "?"
        holder.contactInitial.text = initial

        // Set contact name
        holder.contactName.text = contact.contactName

        // Set last call status
        if (contact.lastCall != null) {
            val timeAgo = formatTimeAgo(contact.lastCall.timestamp)
            when (contact.lastCall.type) {
                CallType.MISSED -> {
                    holder.lastCallStatus.text = "Missed call - $timeAgo"
                    holder.lastCallStatus.setTextColor(ContextCompat.getColor(holder.itemView.context, R.color.warning_red))
                }
                CallType.INCOMING, CallType.OUTGOING -> {
                    holder.lastCallStatus.text = "Last call: $timeAgo"
                    holder.lastCallStatus.setTextColor(MaterialColors.getColor(holder.itemView, com.google.android.material.R.attr.colorOnSurfaceVariant))
                }
            }
        } else {
            holder.lastCallStatus.text = "Never called"
            holder.lastCallStatus.setTextColor(MaterialColors.getColor(holder.itemView, com.google.android.material.R.attr.colorOnSurfaceVariant))
        }

        // Call button click
        holder.callButton.setOnClickListener {
            onCallClick(contact)
        }

        // Item click also initiates call
        holder.itemView.setOnClickListener {
            onCallClick(contact)
        }
    }

    override fun getItemCount(): Int = filteredContacts.size

    /**
     * Update contacts list
     */
    fun updateContacts(newContacts: List<CallableContact>) {
        contacts = newContacts
        filteredContacts = newContacts
        notifyDataSetChanged()
    }

    /**
     * Filter contacts by search query
     */
    fun filter(query: String) {
        filteredContacts = if (query.isEmpty()) {
            contacts
        } else {
            contacts.filter { it.contactName.contains(query, ignoreCase = true) }
        }
        notifyDataSetChanged()
    }

    /**
     * Format timestamp to relative time
     */
    private fun formatTimeAgo(timestamp: Long): String {
        val now = System.currentTimeMillis()
        val diff = now - timestamp
        val seconds = diff / 1000
        val minutes = seconds / 60
        val hours = minutes / 60
        val days = hours / 24

        return when {
            minutes < 1 -> "Just now"
            minutes < 60 -> "$minutes ${if (minutes == 1L) "minute" else "minutes"} ago"
            hours < 24 -> "$hours ${if (hours == 1L) "hour" else "hours"} ago"
            days == 1L -> "Yesterday"
            days < 7 -> "$days days ago"
            else -> {
                val dateFormat = SimpleDateFormat("MMM d", Locale.getDefault())
                dateFormat.format(Date(timestamp))
            }
        }
    }
}
