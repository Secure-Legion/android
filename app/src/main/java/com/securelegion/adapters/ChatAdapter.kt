package com.securelegion.adapters

import android.content.Context
import android.view.GestureDetector
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.models.Chat
import kotlin.math.max

class ChatAdapter(
    private val chats: List<Chat>,
    private val onChatClick: (Chat) -> Unit,
    private val onDownloadClick: ((Chat) -> Unit)? = null,
    private val onDeleteClick: ((Chat) -> Unit)? = null
) : RecyclerView.Adapter<ChatAdapter.ChatViewHolder>() {

    class ChatViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val chatAvatar: TextView = view.findViewById(R.id.chatAvatar)
        val chatName: TextView = view.findViewById(R.id.chatName)
        val chatMessage: TextView = view.findViewById(R.id.chatMessage)
        val chatTime: TextView = view.findViewById(R.id.chatTime)
        val chatMessageStatus: android.widget.ImageView = view.findViewById(R.id.chatMessageStatus)
        val unreadBadge: TextView = view.findViewById(R.id.unreadBadge)
        val securityBadge: TextView = view.findViewById(R.id.securityBadge)
        val onlineIndicator: TextView = view.findViewById(R.id.onlineIndicator)
        val downloadButton: Button = view.findViewById(R.id.downloadButton)
        val foreground: View = view.findViewById(R.id.chatItemForeground)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChatViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)
        return ChatViewHolder(view)
    }

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int) {
        val chat = chats[position]
        val context = holder.itemView.context

        // Set avatar (first letter of nickname)
        holder.chatAvatar.text = chat.avatar.uppercase()

        // Set chat name (remove @ symbol)
        holder.chatName.text = chat.nickname.removePrefix("@")

        // Set message preview
        holder.chatMessage.text = chat.lastMessage

        // Set timestamp
        holder.chatTime.text = chat.time

        // Show message status indicator (only for sent messages)
        if (chat.lastMessageIsSent) {
            holder.chatMessageStatus.visibility = View.VISIBLE
            // Check ACK flags instead of status to show accurate delivery state
            val statusIcon = when {
                chat.lastMessageStatus == 6 -> R.drawable.status_failed  // STATUS_FAILED
                chat.lastMessageMessageDelivered -> R.drawable.status_delivered  // MESSAGE_ACK received (2 checkmarks)
                chat.lastMessagePingDelivered -> R.drawable.status_sent  // PING_ACK received (1 checkmark)
                else -> R.drawable.status_pending  // No PING_ACK yet (empty circle)
            }
            holder.chatMessageStatus.setImageResource(statusIcon)
        } else {
            holder.chatMessageStatus.visibility = View.GONE
        }

        // Never show download button in preview - only inside the chat
        holder.downloadButton.visibility = View.GONE

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

        // Show/hide online indicator
        holder.onlineIndicator.visibility = if (chat.isOnline) View.VISIBLE else View.GONE

        // Reset foreground position for all items
        holder.foreground.translationX = 0f

        // Swipe-to-delete gesture handling with smooth resistance
        var startX = 0f
        var startTranslationX = 0f
        var isSwiping = false

        holder.foreground.setOnTouchListener { v, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    startX = event.rawX
                    startTranslationX = holder.foreground.translationX
                    isSwiping = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val deltaX = event.rawX - startX

                    // Mark as swiping if moved more than threshold
                    if (kotlin.math.abs(deltaX) > 10) {
                        isSwiping = true
                    }

                    // Apply resistance to make swiping feel smoother and less sensitive
                    val resistance = 0.8f // Lower = more resistance (harder to swipe)
                    val newTranslation = startTranslationX + (deltaX * resistance)

                    // Allow swiping left only (negative translation)
                    holder.foreground.translationX = newTranslation.coerceAtMost(0f)
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    val currentTranslation = holder.foreground.translationX
                    val itemWidth = holder.foreground.width.toFloat()
                    val deleteThreshold = itemWidth * 0.3f // 30% of item width (easier to trigger delete)

                    // Handle click if it was a tap (not a swipe)
                    if (!isSwiping) {
                        // Open chat on tap
                        onChatClick(chat)
                    } else {
                        // Check if swiped past threshold
                        if (kotlin.math.abs(currentTranslation) > deleteThreshold) {
                            // Animate off screen then delete
                            holder.foreground.animate()
                                .translationX(-itemWidth)
                                .setDuration(200)
                                .withEndAction {
                                    onDeleteClick?.invoke(chat)
                                }
                                .start()
                        } else {
                            // Snap back to original position with bounce
                            holder.foreground.animate()
                                .translationX(0f)
                                .setDuration(250)
                                .start()
                        }
                    }

                    v.performClick()
                    true
                }
                else -> false
            }
        }
    }

    override fun getItemCount() = chats.size
}
