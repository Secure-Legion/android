package com.securelegion.adapters

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.models.Chat

class ChatAdapter(
    private val chats: List<Chat>,
    private val onChatClick: (Chat) -> Unit,
    private val onDownloadClick: ((Chat) -> Unit)? = null
) : RecyclerView.Adapter<ChatAdapter.ChatViewHolder>() {

    class ChatViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val chatName: TextView = view.findViewById(R.id.chatName)
        val chatMessage: TextView = view.findViewById(R.id.chatMessage)
        val chatTime: TextView = view.findViewById(R.id.chatTime)
        val unreadBadge: TextView = view.findViewById(R.id.unreadBadge)
        val securityBadge: TextView = view.findViewById(R.id.securityBadge)
        val onlineIndicator: TextView = view.findViewById(R.id.onlineIndicator)
        val downloadButton: Button = view.findViewById(R.id.downloadButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChatViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)
        return ChatViewHolder(view)
    }

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int) {
        val chat = chats[position]
        val context = holder.itemView.context

        // Set chat name (add @ if not present)
        holder.chatName.text = if (chat.nickname.startsWith("@")) {
            chat.nickname
        } else {
            "@${chat.nickname}"
        }

        // Set message preview
        holder.chatMessage.text = chat.lastMessage

        // Set timestamp
        holder.chatTime.text = chat.time

        // Check for pending Pings
        val prefs = context.getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
        val hasPendingPing = prefs.contains("ping_${chat.id}_id")

        // Show download button if there's a pending Ping, otherwise show unread badge
        if (hasPendingPing) {
            holder.downloadButton.visibility = View.VISIBLE
            holder.unreadBadge.visibility = View.GONE

            // Set download button click listener
            holder.downloadButton.setOnClickListener {
                onDownloadClick?.invoke(chat)
            }
        } else {
            holder.downloadButton.visibility = View.GONE

            // Show/hide unread badge
            if (chat.unreadCount > 0) {
                holder.unreadBadge.visibility = View.VISIBLE
                holder.unreadBadge.text = chat.unreadCount.toString()
            } else {
                holder.unreadBadge.visibility = View.GONE
            }
        }

        // Show/hide security badge
        if (chat.securityBadge.isNotEmpty()) {
            holder.securityBadge.visibility = View.VISIBLE
            holder.securityBadge.text = chat.securityBadge
        } else {
            holder.securityBadge.visibility = View.GONE
        }

        // Show/hide online indicator
        holder.onlineIndicator.visibility = if (chat.isOnline) View.VISIBLE else View.GONE

        holder.itemView.setOnClickListener { onChatClick(chat) }
    }

    override fun getItemCount() = chats.size
}
