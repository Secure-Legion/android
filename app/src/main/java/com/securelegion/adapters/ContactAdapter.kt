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
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    companion object {
        private const val VIEW_TYPE_SECTION = 0
        private const val VIEW_TYPE_CONTACT = 1
    }

    // Data structure to hold sections and contacts
    private data class ListItem(
        val type: Int,
        val contact: Contact? = null,
        val sectionHeader: String? = null
    )

    private var listItems = mutableListOf<ListItem>()

    init {
        buildListItems()
    }

    private fun buildListItems() {
        listItems.clear()

        // Sort contacts alphabetically by name
        val sortedContacts = contacts.sortedBy {
            it.name.removePrefix("@").uppercase()
        }

        var currentSection = ""
        sortedContacts.forEach { contact ->
            val firstLetter = contact.name.removePrefix("@").firstOrNull()?.uppercaseChar()?.toString() ?: "#"

            // Add section header if it's a new section
            if (firstLetter != currentSection) {
                currentSection = firstLetter
                listItems.add(ListItem(VIEW_TYPE_SECTION, sectionHeader = firstLetter))
            }

            // Add contact
            listItems.add(ListItem(VIEW_TYPE_CONTACT, contact = contact))
        }
    }

    class SectionViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val sectionHeader: TextView = view.findViewById(R.id.sectionHeader)
    }

    class ContactViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val nameView: TextView = view.findViewById(R.id.contactName)
        val initialView: TextView = view.findViewById(R.id.contactInitial)
        val lastMessageView: TextView = view.findViewById(R.id.lastMessage)
        val timestampView: TextView = view.findViewById(R.id.messageTimestamp)
    }

    override fun getItemViewType(position: Int): Int {
        return listItems[position].type
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        return when (viewType) {
            VIEW_TYPE_SECTION -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_contact_section, parent, false)
                SectionViewHolder(view)
            }
            else -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_contact, parent, false)
                ContactViewHolder(view)
            }
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val item = listItems[position]

        when (holder) {
            is SectionViewHolder -> {
                holder.sectionHeader.text = item.sectionHeader
            }
            is ContactViewHolder -> {
                val contact = item.contact ?: return

                // Display contact name (without @ prefix, normal case)
                val displayName = contact.name.removePrefix("@")
                holder.nameView.text = displayName

                // Display first letter of name as initial (uppercase)
                val initial = contact.name.removePrefix("@").firstOrNull()?.uppercaseChar()?.toString() ?: "?"
                holder.initialView.text = initial

                Log.d("ContactAdapter", "Binding contact: ${contact.name}, display: $displayName, initial: $initial")

                holder.itemView.setOnClickListener { onContactClick(contact) }
            }
        }
    }

    override fun getItemCount() = listItems.size

    fun updateContacts(newContacts: List<Contact>) {
        contacts = newContacts
        buildListItems()
        notifyDataSetChanged()
    }
}
