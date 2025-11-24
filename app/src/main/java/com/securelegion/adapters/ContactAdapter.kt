package com.securelegion.adapters

import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.models.Contact

class ContactAdapter(
    private var contacts: List<Contact>,
    private val onContactClick: (Contact) -> Unit
) : RecyclerView.Adapter<ContactAdapter.ContactViewHolder>() {

    class ContactViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val nameView: TextView = view.findViewById(R.id.contactName)
        val addressView: TextView = view.findViewById(R.id.contactAddress)
        val friendsIcon: ImageView = view.findViewById(R.id.friendsIcon)
        val pendingBadge: TextView = view.findViewById(R.id.pendingBadge)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact, parent, false)
        return ContactViewHolder(view)
    }

    override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
        val contact = contacts[position]

        // Display contact name
        holder.nameView.text = contact.name

        // Display truncated Solana address
        val truncatedAddress = if (contact.address.length > 40) {
            contact.address.take(40) + "..."
        } else {
            contact.address
        }
        holder.addressView.text = truncatedAddress

        // Show friendship status
        when (contact.friendshipStatus) {
            "CONFIRMED" -> {
                holder.friendsIcon.visibility = View.VISIBLE
                holder.pendingBadge.visibility = View.GONE
            }
            "PENDING_SENT" -> {
                holder.friendsIcon.visibility = View.GONE
                holder.pendingBadge.visibility = View.VISIBLE
            }
            else -> {
                // Default to PENDING if unknown status
                holder.friendsIcon.visibility = View.GONE
                holder.pendingBadge.visibility = View.VISIBLE
            }
        }

        Log.d("ContactAdapter", "Binding contact: ${contact.name}, status: ${contact.friendshipStatus}")

        holder.itemView.setOnClickListener { onContactClick(contact) }
    }

    override fun getItemCount() = contacts.size

    fun updateContacts(newContacts: List<Contact>) {
        contacts = newContacts
        notifyDataSetChanged()
    }
}
