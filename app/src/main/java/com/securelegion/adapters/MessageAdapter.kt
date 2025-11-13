package com.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.database.entities.Message
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MessageAdapter(
    private var messages: List<Message> = emptyList()
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    companion object {
        private const val VIEW_TYPE_SENT = 1
        private const val VIEW_TYPE_RECEIVED = 2
    }

    class SentMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val messageText: TextView = view.findViewById(R.id.messageText)
        val messageTime: TextView = view.findViewById(R.id.messageTime)
        val messageStatus: TextView = view.findViewById(R.id.messageStatus)
    }

    class ReceivedMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val messageText: TextView = view.findViewById(R.id.messageText)
        val messageTime: TextView = view.findViewById(R.id.messageTime)
    }

    override fun getItemViewType(position: Int): Int {
        return if (messages[position].isSentByMe) VIEW_TYPE_SENT else VIEW_TYPE_RECEIVED
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        return if (viewType == VIEW_TYPE_SENT) {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_message_sent, parent, false)
            SentMessageViewHolder(view)
        } else {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_message_received, parent, false)
            ReceivedMessageViewHolder(view)
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val message = messages[position]

        when (holder) {
            is SentMessageViewHolder -> {
                holder.messageText.text = message.encryptedContent // Will be decrypted content
                holder.messageTime.text = formatTime(message.timestamp)
                holder.messageStatus.text = getStatusIcon(message.status)
            }
            is ReceivedMessageViewHolder -> {
                holder.messageText.text = message.encryptedContent // Will be decrypted content
                holder.messageTime.text = formatTime(message.timestamp)
            }
        }
    }

    override fun getItemCount() = messages.size

    fun updateMessages(newMessages: List<Message>) {
        messages = newMessages
        notifyDataSetChanged()
    }

    private fun formatTime(timestamp: Long): String {
        val sdf = SimpleDateFormat("h:mm a", Locale.getDefault())
        return sdf.format(Date(timestamp))
    }

    private fun getStatusIcon(status: Int): String {
        return when (status) {
            Message.STATUS_PENDING -> "○"  // Pending
            Message.STATUS_SENT -> "✓"     // Sent
            Message.STATUS_DELIVERED -> "✓✓" // Delivered
            Message.STATUS_READ -> "✓✓"    // Read (could make blue)
            Message.STATUS_FAILED -> "✗"   // Failed
            else -> ""
        }
    }
}
