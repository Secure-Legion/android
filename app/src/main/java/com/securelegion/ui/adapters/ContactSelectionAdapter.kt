package com.securelegion.ui.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.database.entities.Contact

/**
 * Adapter for contact selection in bottom sheet
 */
class ContactSelectionAdapter(
    private val selectedIds: MutableSet<Long> = mutableSetOf()
) : ListAdapter<Contact, ContactSelectionAdapter.ContactViewHolder>(ContactDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact_selectable, parent, false)
        return ContactViewHolder(view)
    }

    override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
        holder.bind(getItem(position), selectedIds)
    }

    fun getSelectedContacts(): List<Contact> {
        return currentList.filter { selectedIds.contains(it.id) }
    }

    class ContactViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val contactInitial: TextView = itemView.findViewById(R.id.contactInitial)
        private val contactName: TextView = itemView.findViewById(R.id.contactName)
        private val contactCheckbox: CheckBox = itemView.findViewById(R.id.contactCheckbox)

        fun bind(contact: Contact, selectedIds: MutableSet<Long>) {
            contactName.text = contact.displayName
            contactInitial.text = contact.displayName.firstOrNull()?.uppercase() ?: "?"
            contactCheckbox.isChecked = selectedIds.contains(contact.id)

            // Handle checkbox click
            contactCheckbox.setOnCheckedChangeListener(null) // Remove old listener
            contactCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedIds.add(contact.id)
                } else {
                    selectedIds.remove(contact.id)
                }
            }

            // Handle row click
            itemView.setOnClickListener {
                contactCheckbox.toggle()
            }
        }
    }

    private class ContactDiffCallback : DiffUtil.ItemCallback<Contact>() {
        override fun areItemsTheSame(oldItem: Contact, newItem: Contact): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: Contact, newItem: Contact): Boolean {
            return oldItem == newItem
        }
    }
}
