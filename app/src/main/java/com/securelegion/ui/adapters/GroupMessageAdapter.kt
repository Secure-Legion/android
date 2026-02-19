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
import java.text.SimpleDateFormat
import java.util.*

/**
 * RecyclerView adapter for CRDT group chat messages.
 *
 * Uses GroupChatMessage — a UI-only data class mapped from CrdtGroupManager.CrdtMessage.
 */
class GroupMessageAdapter(
    private val onMessageClick: (GroupChatMessage) -> Unit = {},
    private val onMessageLongClick: (GroupChatMessage) -> Unit = {}
) : ListAdapter<GroupChatMessage, RecyclerView.ViewHolder>(GroupChatMessageDiffCallback()) {

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

    class SentMessageViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val messageText: TextView = itemView.findViewById(R.id.messageText)
        private val messageStatus: ImageView = itemView.findViewById(R.id.messageStatus)
        private val swipeRevealedTime: TextView = itemView.findViewById(R.id.swipeRevealedTime)

        fun bind(
            message: GroupChatMessage,
            onClick: (GroupChatMessage) -> Unit,
            onLongClick: (GroupChatMessage) -> Unit
        ) {
            messageText.text = message.text
            swipeRevealedTime.text = formatTimestamp(message.timestamp)
            // Hide delivery status for group messages (no per-message ACK in CRDT groups)
            messageStatus.visibility = View.GONE

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

    class ReceivedMessageViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val messageText: TextView = itemView.findViewById(R.id.messageText)
        private val swipeRevealedTime: TextView = itemView.findViewById(R.id.swipeRevealedTime)

        fun bind(
            message: GroupChatMessage,
            onClick: (GroupChatMessage) -> Unit,
            onLongClick: (GroupChatMessage) -> Unit
        ) {
            val displayText = if (message.senderName.isNotEmpty()) {
                "${message.senderName}: ${message.text}"
            } else {
                message.text
            }
            messageText.text = displayText
            swipeRevealedTime.text = formatTimestamp(message.timestamp)

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

    private class GroupChatMessageDiffCallback : DiffUtil.ItemCallback<GroupChatMessage>() {
        override fun areItemsTheSame(oldItem: GroupChatMessage, newItem: GroupChatMessage): Boolean {
            return oldItem.messageId == newItem.messageId
        }

        override fun areContentsTheSame(oldItem: GroupChatMessage, newItem: GroupChatMessage): Boolean {
            return oldItem == newItem
        }
    }
}

/**
 * UI data class for group chat messages.
 * Mapped from CrdtGroupManager.CrdtMessage in the activity layer.
 */
data class GroupChatMessage(
    val messageId: String,
    val text: String,
    val timestamp: Long,
    val isSentByMe: Boolean,
    val senderName: String = ""
)
