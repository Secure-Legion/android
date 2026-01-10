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

/**
 * Adapter for displaying selected group members as horizontal chips
 */
class SelectedMembersAdapter(
    private val onRemove: (Contact) -> Unit
) : ListAdapter<Contact, SelectedMembersAdapter.MemberViewHolder>(ContactDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MemberViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_selected_member, parent, false)
        return MemberViewHolder(view)
    }

    override fun onBindViewHolder(holder: MemberViewHolder, position: Int) {
        holder.bind(getItem(position), onRemove)
    }

    class MemberViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val memberInitial: TextView = itemView.findViewById(R.id.memberInitial)
        private val memberName: TextView = itemView.findViewById(R.id.memberName)
        private val removeButton: ImageView = itemView.findViewById(R.id.removeButton)

        fun bind(contact: Contact, onRemove: (Contact) -> Unit) {
            memberName.text = contact.displayName
            memberInitial.text = contact.displayName.firstOrNull()?.uppercase() ?: "?"

            removeButton.setOnClickListener {
                onRemove(contact)
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
