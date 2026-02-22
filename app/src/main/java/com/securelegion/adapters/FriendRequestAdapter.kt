package com.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.models.PendingFriendRequest

class FriendRequestAdapter(
    private val onAccept: (PendingFriendRequest) -> Unit,
    private val onDecline: (PendingFriendRequest) -> Unit,
    private val onCancelSent: (PendingFriendRequest) -> Unit
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    companion object {
        private const val VIEW_TYPE_SECTION = 0
        private const val VIEW_TYPE_RECEIVED = 1
        private const val VIEW_TYPE_SENT = 2
    }

    private sealed class ListItem {
        data class Section(val title: String) : ListItem()
        data class ReceivedRequest(val request: PendingFriendRequest) : ListItem()
        data class SentRequest(val request: PendingFriendRequest) : ListItem()
    }

    private var listItems = mutableListOf<ListItem>()

    fun updateRequests(requests: List<PendingFriendRequest>) {
        listItems.clear()

        val received = requests.filter { it.direction == PendingFriendRequest.DIRECTION_INCOMING && it.status == PendingFriendRequest.STATUS_PENDING }
        val sent = requests.filter { it.direction == PendingFriendRequest.DIRECTION_OUTGOING }

        if (received.isNotEmpty()) {
            listItems.add(ListItem.Section("RECEIVED REQUESTS"))
            received.forEach { listItems.add(ListItem.ReceivedRequest(it)) }
        }

        if (sent.isNotEmpty()) {
            listItems.add(ListItem.Section("SENT REQUESTS"))
            sent.forEach { listItems.add(ListItem.SentRequest(it)) }
        }

        notifyDataSetChanged()
    }

    override fun getItemViewType(position: Int) = when (listItems[position]) {
        is ListItem.Section -> VIEW_TYPE_SECTION
        is ListItem.ReceivedRequest -> VIEW_TYPE_RECEIVED
        is ListItem.SentRequest -> VIEW_TYPE_SENT
    }

    class SectionViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(R.id.sectionTitle)
    }

    class ReceivedViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val displayName: TextView = view.findViewById(R.id.requestDisplayName)
        val username: TextView = view.findViewById(R.id.requestUsername)
        val avatar: com.securelegion.views.AvatarView = view.findViewById(R.id.requestAvatar)
        val acceptBtn: View = view.findViewById(R.id.acceptButton)
        val declineBtn: View = view.findViewById(R.id.declineButton)
    }

    class SentViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val displayName: TextView = view.findViewById(R.id.requestDisplayName)
        val username: TextView = view.findViewById(R.id.requestUsername)
        val avatar: com.securelegion.views.AvatarView = view.findViewById(R.id.requestAvatar)
        val cancelBtn: View = view.findViewById(R.id.cancelButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            VIEW_TYPE_SECTION -> SectionViewHolder(inflater.inflate(R.layout.item_request_section_header, parent, false))
            VIEW_TYPE_RECEIVED -> ReceivedViewHolder(inflater.inflate(R.layout.item_received_request, parent, false))
            VIEW_TYPE_SENT -> SentViewHolder(inflater.inflate(R.layout.item_sent_request, parent, false))
            else -> throw IllegalArgumentException("Unknown view type")
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val item = listItems[position]) {
            is ListItem.Section -> {
                (holder as SectionViewHolder).title.text = item.title
            }
            is ListItem.ReceivedRequest -> {
                val h = holder as ReceivedViewHolder
                val name = item.request.displayName.removePrefix("@")
                h.displayName.text = name
                h.username.text = "@$name"
                h.avatar.setName(name)
                h.acceptBtn.setOnClickListener { onAccept(item.request) }
                h.declineBtn.setOnClickListener { onDecline(item.request) }
            }
            is ListItem.SentRequest -> {
                val h = holder as SentViewHolder
                val name = item.request.displayName.removePrefix("@")
                h.displayName.text = name
                h.username.text = "@$name"
                h.avatar.setName(name)
                h.cancelBtn.setOnClickListener { onCancelSent(item.request) }
            }
        }
    }

    override fun getItemCount() = listItems.size

    fun isEmpty() = listItems.none { it !is ListItem.Section }
}
