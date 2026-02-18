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
import com.securelegion.views.AvatarView
import kotlin.math.abs

class ChatAdapter(
    private val chats: List<Chat>,
    private val onChatClick: (Chat) -> Unit,
    private val onDownloadClick: ((Chat) -> Unit)? = null,
    private val onDeleteClick: ((Chat) -> Unit)? = null,
    private val onMuteClick: ((Chat) -> Unit)? = null,
    private val onPinClick: ((Chat) -> Unit)? = null
) : RecyclerView.Adapter<ChatAdapter.ChatViewHolder>() {

    // Track which item is currently swiped open (-1 = none)
    private var openPosition = -1

    class ChatViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val chatAvatar: AvatarView = view.findViewById(R.id.chatAvatar)
        val chatName: TextView = view.findViewById(R.id.chatName)
        val chatMessage: TextView = view.findViewById(R.id.chatMessage)
        val chatTime: TextView = view.findViewById(R.id.chatTime)
        val chatMessageStatus: android.widget.ImageView = view.findViewById(R.id.chatMessageStatus)
        val unreadBadge: TextView = view.findViewById(R.id.unreadBadge)
        val securityBadge: TextView = view.findViewById(R.id.securityBadge)
        val onlineIndicator: TextView = view.findViewById(R.id.onlineIndicator)
        val pinIcon: android.widget.ImageView = view.findViewById(R.id.pinIcon)
        val downloadButton: Button = view.findViewById(R.id.downloadButton)
        val foreground: View = view.findViewById(R.id.chatItemForeground)
        val actionMute: View = view.findViewById(R.id.actionMute)
        val actionDelete: View = view.findViewById(R.id.actionDelete)
        val actionPin: View = view.findViewById(R.id.actionPin)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChatViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)
        return ChatViewHolder(view)
    }

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int) {
        val chat = chats[position]

        // Set avatar photo or initials
        holder.chatAvatar.setName(chat.nickname.removePrefix("@"))
        if (!chat.profilePictureBase64.isNullOrEmpty()) {
            holder.chatAvatar.setPhotoBase64(chat.profilePictureBase64)
        } else {
            holder.chatAvatar.clearPhoto()
        }

        // Set chat name (remove @ symbol)
        holder.chatName.text = chat.nickname.removePrefix("@")

        // Set message preview
        holder.chatMessage.text = chat.lastMessage

        // Set timestamp
        holder.chatTime.text = chat.time

        // Show message status indicator (only for sent messages)
        if (chat.lastMessageIsSent) {
            holder.chatMessageStatus.visibility = View.VISIBLE
            val statusIcon = when {
                chat.lastMessageStatus == 6 -> R.drawable.status_failed
                chat.lastMessageMessageDelivered -> R.drawable.status_delivered
                chat.lastMessagePingDelivered -> R.drawable.status_sent
                else -> R.drawable.status_pending
            }
            holder.chatMessageStatus.setImageResource(statusIcon)
        } else {
            holder.chatMessageStatus.visibility = View.GONE
        }

        // Never show download button in preview
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

        // Show/hide pin icon
        holder.pinIcon.visibility = if (chat.isPinned) View.VISIBLE else View.GONE

        // Reset foreground position
        holder.foreground.translationX = if (position == openPosition) ACTION_WIDTH else 0f

        // Action button click handlers
        holder.actionMute.setOnClickListener {
            closeItem(holder)
            onMuteClick?.invoke(chat)
        }

        holder.actionDelete.setOnClickListener {
            closeItem(holder)
            onDeleteClick?.invoke(chat)
        }

        holder.actionPin.setOnClickListener {
            closeItem(holder)
            onPinClick?.invoke(chat)
        }

        // Swipe gesture handling
        var startX = 0f
        var startTranslationX = 0f
        var isSwiping = false
        val touchSlop = 10f

        holder.foreground.setOnTouchListener { v, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    startX = event.rawX
                    startTranslationX = holder.foreground.translationX
                    isSwiping = false

                    // If another item is open, close it
                    if (openPosition != -1 && openPosition != holder.adapterPosition) {
                        notifyItemChanged(openPosition)
                        openPosition = -1
                    }

                    // Request parent to not intercept touch (so we handle swipe)
                    v.parent?.requestDisallowInterceptTouchEvent(false)
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val deltaX = event.rawX - startX

                    if (abs(deltaX) > touchSlop && !isSwiping) {
                        isSwiping = true
                        // Once swiping starts, prevent parent from stealing the touch
                        v.parent?.requestDisallowInterceptTouchEvent(true)
                    }

                    if (isSwiping) {
                        val newTranslation = startTranslationX + deltaX
                        // Clamp between 0 and ACTION_WIDTH (only swipe right)
                        holder.foreground.translationX = newTranslation.coerceIn(0f, ACTION_WIDTH)
                    }
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    v.parent?.requestDisallowInterceptTouchEvent(false)

                    if (!isSwiping) {
                        // Tap: if item is open, close it; otherwise trigger click
                        if (holder.foreground.translationX > 0f) {
                            closeItem(holder)
                            openPosition = -1
                        } else {
                            onChatClick(chat)
                        }
                    } else {
                        val currentTranslation = holder.foreground.translationX
                        val threshold = ACTION_WIDTH * 0.35f

                        if (currentTranslation > threshold) {
                            // Snap open
                            holder.foreground.animate()
                                .translationX(ACTION_WIDTH)
                                .setDuration(200)
                                .start()
                            openPosition = holder.adapterPosition
                        } else {
                            // Snap closed
                            closeItem(holder)
                            openPosition = -1
                        }
                    }

                    v.performClick()
                    true
                }
                else -> false
            }
        }
    }

    private fun closeItem(holder: ChatViewHolder) {
        holder.foreground.animate()
            .translationX(0f)
            .setDuration(200)
            .start()
    }

    override fun getItemCount() = chats.size

    companion object {
        // Width of all 3 action buttons combined (80dp * 3 = 240dp)
        // Using pixels calculated at bind time would be more accurate,
        // but we use a fixed dp value converted at first use
        private var ACTION_WIDTH = 0f

        fun getActionWidth(context: Context): Float {
            if (ACTION_WIDTH == 0f) {
                ACTION_WIDTH = 240 * context.resources.displayMetrics.density
            }
            return ACTION_WIDTH
        }
    }

    override fun onAttachedToRecyclerView(recyclerView: RecyclerView) {
        super.onAttachedToRecyclerView(recyclerView)
        getActionWidth(recyclerView.context)
    }
}
