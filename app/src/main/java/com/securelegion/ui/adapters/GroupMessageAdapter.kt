package com.securelegion.ui.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.database.entities.GroupMessage
import java.text.SimpleDateFormat
import java.util.*

/**
 * RecyclerView adapter for group chat messages
 *
 * IMPORTANT: Click handlers should NEVER update message timestamps
 * Messages are always sorted by their original timestamp (ORDER BY timestamp ASC)
 * Clicking a message should only update status fields like isRead, NOT timestamp
 */
class GroupMessageAdapter(
    private val onMessageClick: (GroupMessage) -> Unit = {},
    private val onMessageLongClick: (GroupMessage) -> Unit = {}
) : ListAdapter<GroupMessage, RecyclerView.ViewHolder>(GroupMessageDiffCallback()) {

    companion object {
        private const val VIEW_TYPE_SENT = 1
        private const val VIEW_TYPE_RECEIVED = 2
    }

    override fun getItemViewType(position: Int): Int {
        val message = getItem(position)
        return if (message.isSentByMe) VIEW_TYPE_SENT else VIEW_TYPE_RECEIVED
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            VIEW_TYPE_SENT -> {
                val view = inflater.inflate(R.layout.item_message_sent, parent, false)
                SentMessageViewHolder(view)
            }
            VIEW_TYPE_RECEIVED -> {
                val view = inflater.inflate(R.layout.item_message_received, parent, false)
                ReceivedMessageViewHolder(view)
            }
            else -> throw IllegalArgumentException("Invalid view type: $viewType")
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val message = getItem(position)
        when (holder) {
            is SentMessageViewHolder -> holder.bind(message, onMessageClick, onMessageLongClick)
            is ReceivedMessageViewHolder -> holder.bind(message, onMessageClick, onMessageLongClick)
        }
    }

    /**
     * ViewHolder for sent messages
     */
    class SentMessageViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val messageText: TextView = itemView.findViewById(R.id.messageText)
        private val messageStatus: TextView = itemView.findViewById(R.id.messageStatus)
        private val swipeRevealedTime: TextView = itemView.findViewById(R.id.swipeRevealedTime)

        fun bind(
            message: GroupMessage,
            onClick: (GroupMessage) -> Unit,
            onLongClick: (GroupMessage) -> Unit
        ) {
            messageText.text = message.decryptedContent ?: "[Encrypted]"
            swipeRevealedTime.text = formatTimestamp(message.timestamp)

            // Show delivery status
            messageStatus.text = when (message.status) {
                GroupMessage.STATUS_PENDING -> "-"
                GroupMessage.STATUS_SENT -> "Sent"
                GroupMessage.STATUS_DELIVERED -> "Delivered"
                GroupMessage.STATUS_READ -> "Read"
                GroupMessage.STATUS_FAILED -> "Failed"
                else -> "Sent"
            }
            messageStatus.visibility = View.VISIBLE

            // Click handlers - DO NOT update timestamp!
            itemView.setOnClickListener { onClick(message) }
            itemView.setOnLongClickListener {
                onLongClick(message)
                true
            }
        }

        private fun formatTimestamp(timestamp: Long): String {
            val sdf = SimpleDateFormat("HH:mm", Locale.getDefault())
            return sdf.format(Date(timestamp))
        }
    }

    /**
     * ViewHolder for received messages
     */
    class ReceivedMessageViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val messageText: TextView = itemView.findViewById(R.id.messageText)
        private val swipeRevealedTime: TextView = itemView.findViewById(R.id.swipeRevealedTime)

        fun bind(
            message: GroupMessage,
            onClick: (GroupMessage) -> Unit,
            onLongClick: (GroupMessage) -> Unit
        ) {
            // Show sender name + message text (TODO: Add sender name to layout later)
            val displayText = if (message.senderName.isNotEmpty()) {
                "${message.senderName}: ${message.decryptedContent ?: "[Encrypted]"}"
            } else {
                message.decryptedContent ?: "[Encrypted]"
            }
            messageText.text = displayText
            swipeRevealedTime.text = formatTimestamp(message.timestamp)

            // Click handlers - DO NOT update timestamp!
            itemView.setOnClickListener { onClick(message) }
            itemView.setOnLongClickListener {
                onLongClick(message)
                true
            }
        }

        private fun formatTimestamp(timestamp: Long): String {
            val sdf = SimpleDateFormat("HH:mm", Locale.getDefault())
            return sdf.format(Date(timestamp))
        }
    }

    /**
     * DiffUtil callback for efficient list updates
     * Uses message ID as stable identifier, NOT timestamp
     */
    private class GroupMessageDiffCallback : DiffUtil.ItemCallback<GroupMessage>() {
        override fun areItemsTheSame(oldItem: GroupMessage, newItem: GroupMessage): Boolean {
            // Use messageId as stable identifier - timestamp should NEVER be used here
            return oldItem.messageId == newItem.messageId
        }

        override fun areContentsTheSame(oldItem: GroupMessage, newItem: GroupMessage): Boolean {
            // Check if message content changed (status updates, decryption, etc.)
            // This allows status changes without reordering
            return oldItem == newItem
        }
    }
}
