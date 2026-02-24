package com.securelegion.ui.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.database.entities.Contact
import com.securelegion.views.AvatarView

/**
 * Adapter for full-screen contact selection when adding members to a group.
 * Shows contacts in the same style as the contacts page with an add/check icon on the right.
 */
class AddToGroupAdapter(
    private val selectedIds: MutableSet<Long> = mutableSetOf()
) : ListAdapter<Contact, AddToGroupAdapter.ContactViewHolder>(ContactDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact_add_to_group, parent, false)
        return ContactViewHolder(view)
    }

    override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
        holder.bind(getItem(position), selectedIds) { contact ->
            if (selectedIds.contains(contact.id)) {
                selectedIds.remove(contact.id)
            } else {
                selectedIds.add(contact.id)
            }
            notifyItemChanged(position)
        }
    }

    fun getSelectedContacts(): List<Contact> {
        return currentList.filter { selectedIds.contains(it.id) }
    }

    class ContactViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val contactAvatar: AvatarView = itemView.findViewById(R.id.contactAvatar)
        private val contactName: TextView = itemView.findViewById(R.id.contactName)
        private val contactUsername: TextView = itemView.findViewById(R.id.contactUsername)
        private val addButton: ImageView = itemView.findViewById(R.id.addToGroupButton)

        fun bind(contact: Contact, selectedIds: Set<Long>, onToggle: (Contact) -> Unit) {
            val name = contact.displayName
            contactName.text = name
            contactUsername.text = "@${name.removePrefix("@").lowercase()}"

            contactAvatar.setName(name)
            if (!contact.profilePictureBase64.isNullOrEmpty()) {
                contactAvatar.setPhotoBase64(contact.profilePictureBase64)
            } else {
                contactAvatar.clearPhoto()
            }

            val isSelected = selectedIds.contains(contact.id)
            if (isSelected) {
                addButton.setImageResource(R.drawable.ic_check)
                addButton.alpha = 0.5f
            } else {
                addButton.setImageResource(R.drawable.ic_add_friend)
                addButton.alpha = 1.0f
            }

            addButton.setOnClickListener { onToggle(contact) }
            itemView.setOnClickListener { onToggle(contact) }
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
