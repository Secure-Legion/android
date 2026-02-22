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
        val usernameView: TextView = view.findViewById(R.id.contactUsername)
        val avatarView: com.securelegion.views.AvatarView = view.findViewById(R.id.contactAvatar)
        val contactRow: View = view.findViewById(R.id.contactRow)
        val divider: View = view.findViewById(R.id.contactDivider)
        val dividerTop: View = view.findViewById(R.id.contactDividerTop)
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

                // Display nickname if set, otherwise username
                val displayName = contact.nickname ?: contact.name.removePrefix("@")
                holder.nameView.text = displayName
                holder.nameView.paint.shader = null
                com.securelegion.utils.TextGradient.apply(holder.nameView)

                // Always show @username on second line
                val username = "@${contact.name.removePrefix("@")}"
                holder.usernameView.text = username
                holder.usernameView.visibility = View.VISIBLE

                // Set avatar
                holder.avatarView.setName(contact.name.removePrefix("@"))
                if (!contact.profilePhotoBase64.isNullOrEmpty()) {
                    holder.avatarView.setPhotoBase64(contact.profilePhotoBase64)
                } else {
                    holder.avatarView.clearPhoto()
                }

                // Top divider: show on first contact in each section (after section header or at start)
                val isFirstInSection = position == 0 || listItems[position - 1].type == VIEW_TYPE_SECTION
                holder.dividerTop.visibility = if (isFirstInSection) View.VISIBLE else View.GONE

                // Bottom divider: always show (closes off the last contact in each section too)
                holder.divider.visibility = View.VISIBLE

                holder.contactRow.setOnClickListener { onContactClick(contact) }
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
