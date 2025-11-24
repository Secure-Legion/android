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

    // Track which item is currently open
    private var openItemPosition: Int = RecyclerView.NO_POSITION

    class ChatViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val chatName: TextView = view.findViewById(R.id.chatName)
        val chatMessage: TextView = view.findViewById(R.id.chatMessage)
        val chatTime: TextView = view.findViewById(R.id.chatTime)
        val unreadBadge: TextView = view.findViewById(R.id.unreadBadge)
        val securityBadge: TextView = view.findViewById(R.id.securityBadge)
        val onlineIndicator: TextView = view.findViewById(R.id.onlineIndicator)
        val downloadButton: Button = view.findViewById(R.id.downloadButton)
        val foreground: View = view.findViewById(R.id.chatItemForeground)
        val deleteButtonContainer: View = view.findViewById(R.id.deleteButtonContainer)
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

        // Reset foreground position only if this is not the currently open item
        val deleteButtonWidth = 80 * context.resources.displayMetrics.density
        if (position != openItemPosition) {
            holder.foreground.translationX = 0f
        } else {
            // Restore open position for currently open item
            holder.foreground.translationX = -deleteButtonWidth
        }

        // Swipe-to-reveal gesture handling
        var startX = 0f
        var startTranslationX = 0f

        holder.foreground.setOnTouchListener { v, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    startX = event.rawX
                    startTranslationX = holder.foreground.translationX
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val deltaX = event.rawX - startX
                    val newTranslation = startTranslationX + deltaX
                    // Clamp between -deleteButtonWidth (fully open) and 0 (fully closed)
                    holder.foreground.translationX = newTranslation.coerceIn(-deleteButtonWidth, 0f)
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    val currentTranslation = holder.foreground.translationX

                    // Snap logic: if past 1/4 threshold, snap open; otherwise snap closed
                    if (currentTranslation < -deleteButtonWidth / 4) {
                        // Close any previously open item
                        if (openItemPosition != RecyclerView.NO_POSITION && openItemPosition != holder.adapterPosition) {
                            notifyItemChanged(openItemPosition)
                        }
                        // Snap to open
                        holder.foreground.animate().translationX(-deleteButtonWidth).setDuration(150).start()
                        openItemPosition = holder.adapterPosition
                    } else {
                        // Snap to closed
                        holder.foreground.animate().translationX(0f).setDuration(150).start()
                        if (openItemPosition == holder.adapterPosition) {
                            openItemPosition = RecyclerView.NO_POSITION
                        }
                    }

                    // Handle click if it was a tap (not a swipe)
                    val deltaX = event.rawX - startX
                    if (kotlin.math.abs(deltaX) < 10) { // Tap threshold
                        if (holder.foreground.translationX < -10f) {
                            // Item is open - close it
                            holder.foreground.animate().translationX(0f).setDuration(200).start()
                            openItemPosition = RecyclerView.NO_POSITION
                        } else {
                            // Item is closed - open chat
                            onChatClick(chat)
                        }
                    }

                    v.performClick()
                    true
                }
                else -> false
            }
        }

        holder.deleteButtonContainer.setOnClickListener {
            // Close the item before deleting
            holder.foreground.animate().translationX(0f).setDuration(200).start()
            openItemPosition = RecyclerView.NO_POSITION
            onDeleteClick?.invoke(chat)
        }
    }

    override fun getItemCount() = chats.size

    fun getOpenItemPosition(): Int = openItemPosition

    fun setOpenItemPosition(position: Int) {
        openItemPosition = position
    }
}
