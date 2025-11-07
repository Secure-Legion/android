package com.example.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.example.securelegion.R
import com.example.securelegion.models.Chat

class ChatAdapter(
    private val chats: List<Chat>,
    private val onChatClick: (Chat) -> Unit
) : RecyclerView.Adapter<ChatAdapter.ChatViewHolder>() {

    class ChatViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val name: TextView = view.findViewById(R.id.chatName)
        val message: TextView = view.findViewById(R.id.chatMessage)
        val time: TextView = view.findViewById(R.id.chatTime)
        val unreadBadge: TextView = view.findViewById(R.id.unreadBadge)
        val onlineIndicator: TextView = view.findViewById(R.id.onlineIndicator)
        val securityBadge: TextView = view.findViewById(R.id.securityBadge)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChatViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)
        return ChatViewHolder(view)
    }

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int) {
        val chat = chats[position]

        holder.name.text = chat.nickname
        holder.message.text = chat.lastMessage
        holder.time.text = chat.time

        // Show/hide online indicator (inline green dot)
        holder.onlineIndicator.visibility = if (chat.isOnline) View.VISIBLE else View.GONE

        // Show/hide unread badge
        if (chat.unreadCount > 0) {
            holder.unreadBadge.visibility = View.VISIBLE
            holder.unreadBadge.text = chat.unreadCount.toString()
        } else {
            holder.unreadBadge.visibility = View.GONE
        }

        // Show/hide security badge
        if (chat.securityBadge.isNotEmpty()) {
            holder.securityBadge.visibility = View.VISIBLE
            holder.securityBadge.text = chat.securityBadge
        } else {
            holder.securityBadge.visibility = View.GONE
        }

        holder.itemView.setOnClickListener {
            onChatClick(chat)
        }
    }

    override fun getItemCount() = chats.size
}
