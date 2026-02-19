package com.securelegion.adapters

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.BitmapFactory
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.view.GestureDetector
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.crypto.NLx402Manager
import com.securelegion.database.entities.Message
import com.securelegion.utils.ThemedToast
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * Sealed class for list items in chat - combines messages and pending pings into one list
 * DiffUtil will efficiently compute changes between lists of these items
 */
sealed class ChatListItem {
    data class MessageItem(val message: Message) : ChatListItem() {
        override fun getStableId() = "msg_${message.messageId}".hashCode().toLong() and 0x7FFFFFFFL
    }

    data class PendingPingItem(
        val pingInbox: com.securelegion.database.entities.PingInbox,
        val isDownloading: Boolean = false,
        val isAutoDownloading: Boolean = false
    ) : ChatListItem() {
        override fun getStableId() = "ping_${pingInbox.pingId}".hashCode().toLong() and 0x7FFFFFFFL
    }

    abstract fun getStableId(): Long
}

/**
 * DiffUtil callback for efficiently computing changes between chat lists
 * Compares items by ID and content to enable smooth animations and no flicker
 */
private object ChatListItemDiffCallback : DiffUtil.ItemCallback<ChatListItem>() {
    override fun areItemsTheSame(oldItem: ChatListItem, newItem: ChatListItem): Boolean {
        // Items are the same if they have the same stable ID (message ID or ping ID)
        return when {
            oldItem is ChatListItem.MessageItem && newItem is ChatListItem.MessageItem ->
                oldItem.message.messageId == newItem.message.messageId
            oldItem is ChatListItem.PendingPingItem && newItem is ChatListItem.PendingPingItem ->
                oldItem.pingInbox.pingId == newItem.pingInbox.pingId
            else -> false
        }
    }

    override fun areContentsTheSame(oldItem: ChatListItem, newItem: ChatListItem): Boolean {
        // Content is the same if all relevant fields are identical
        return when {
            oldItem is ChatListItem.MessageItem && newItem is ChatListItem.MessageItem ->
                // Compare all fields that affect display
                oldItem.message.messageId == newItem.message.messageId &&
                oldItem.message.encryptedContent == newItem.message.encryptedContent &&
                oldItem.message.status == newItem.message.status &&
                oldItem.message.isSentByMe == newItem.message.isSentByMe &&
                // Compare delivery status fields so ACK arrivals trigger UI updates
                oldItem.message.pingDelivered == newItem.message.pingDelivered &&
                oldItem.message.pongDelivered == newItem.message.pongDelivered &&
                oldItem.message.messageDelivered == newItem.message.messageDelivered
            oldItem is ChatListItem.PendingPingItem && newItem is ChatListItem.PendingPingItem ->
                // Compare all fields that affect display
                oldItem.pingInbox.pingId == newItem.pingInbox.pingId &&
                oldItem.pingInbox.state == newItem.pingInbox.state &&
                oldItem.isDownloading == newItem.isDownloading &&
                oldItem.isAutoDownloading == newItem.isAutoDownloading
            else -> false
        }
    }

    override fun getChangePayload(oldItem: ChatListItem, newItem: ChatListItem): Any? {
        // Return payload to enable partial updates (only update changed fields)
        return when {
            oldItem is ChatListItem.MessageItem && newItem is ChatListItem.MessageItem -> {
                if (oldItem.message.status != newItem.message.status ||
                    oldItem.message.pingDelivered != newItem.message.pingDelivered ||
                    oldItem.message.pongDelivered != newItem.message.pongDelivered ||
                    oldItem.message.messageDelivered != newItem.message.messageDelivered) {
                    "status_changed" // Only update status icon, not entire row (handles ACK updates)
                } else null
            }
            oldItem is ChatListItem.PendingPingItem && newItem is ChatListItem.PendingPingItem -> {
                if (oldItem.pingInbox.state != newItem.pingInbox.state) {
                    "state_changed" // Update pending state
                } else if (oldItem.isDownloading != newItem.isDownloading) {
                    "downloading_changed" // Update download status
                } else null
            }
            else -> null
        }
    }
}

class MessageAdapter(
    private var downloadingPingIds: Set<String> = emptySet(), // Track which pings are being downloaded
    private var autoPongPingIds: Set<String> = emptySet(), // Track auto-downloading pings (show typing indicator)
    private val onDownloadClick: ((String) -> Unit)? = null, // Now passes ping ID
    private val onVoicePlayClick: ((Message) -> Unit)? = null,
    private var currentlyPlayingMessageId: String? = null,
    private val onMessageLongClick: (() -> Unit)? = null,
    private val onImageClick: ((String) -> Unit)? = null, // Base64 image data
    private val onPaymentRequestClick: ((Message) -> Unit)? = null, // Click on payment request (to pay)
    private val onPaymentDetailsClick: ((Message) -> Unit)? = null, // Click on completed payment (for details)
    private val onPriceRefreshClick: ((Message, TextView, TextView) -> Unit)? = null, // Refresh price callback
    private val onDeleteMessage: ((Message) -> Unit)? = null, // Delete single message callback
    private val onResendMessage: ((Message) -> Unit)? = null // Resend failed message callback
) : ListAdapter<ChatListItem, RecyclerView.ViewHolder>(ChatListItemDiffCallback) {

    companion object {
        private const val TAG = "MessageAdapter"
        private const val VIEW_TYPE_SENT = 1
        private const val VIEW_TYPE_RECEIVED = 2
        private const val VIEW_TYPE_PENDING = 3
        private const val VIEW_TYPE_VOICE_SENT = 4
        private const val VIEW_TYPE_VOICE_RECEIVED = 5
        private const val VIEW_TYPE_IMAGE_SENT = 6
        private const val VIEW_TYPE_IMAGE_RECEIVED = 7
        private const val VIEW_TYPE_PAYMENT_REQUEST_SENT = 8
        private const val VIEW_TYPE_PAYMENT_REQUEST_RECEIVED = 9
        private const val VIEW_TYPE_PAYMENT_SENT = 10
        private const val VIEW_TYPE_PAYMENT_RECEIVED = 11

        // Cached prices for display (updated by ChatActivity)
        var cachedSolPrice: Double = 0.0
        var cachedZecPrice: Double = 0.0
    }

    // Track which message is currently showing swipe-revealed time
    private var currentSwipeRevealedPosition = -1

    // Selection mode for deletion
    private var isSelectionMode = false
    private val selectedMessages = mutableSetOf<String>() // Use String to support both message IDs and ping IDs

    // Track animated ellipsis for downloading/decrypting states
    private val ellipsisAnimations = mutableMapOf<TextView, Runnable>()
    private val ellipsisHandler = Handler(Looper.getMainLooper())

    override fun getItemId(position: Int): Long {
        // Return stable IDs for DiffUtil - prevents bubble jumping
        return if (position < currentList.size) {
            currentList[position].getStableId()
        } else {
            RecyclerView.NO_ID
        }
    }

    fun setSelectionMode(enabled: Boolean) {
        isSelectionMode = enabled
        if (!enabled) {
            selectedMessages.clear()
        }
        // Update all items to show/hide selection checkboxes
        if (itemCount > 0) {
            notifyItemRangeChanged(0, itemCount)
        }
    }

    fun getSelectedMessageIds(): Set<String> = selectedMessages.toSet()

    fun clearSelection() {
        selectedMessages.clear()
        // Update all items since checkboxes may be unchecked
        if (itemCount > 0) {
            notifyItemRangeChanged(0, itemCount)
        }
    }

    /**
     * Start animated ellipsis for loading states (Downloading, Decrypting, etc.)
     * Cycles through: "Text", "Text.", "Text..", "Text..."
     */
    private fun startEllipsisAnimation(textView: TextView, baseText: String) {
        // Stop any existing animation on this view
        stopEllipsisAnimation(textView)

        var dotCount = 0
        val runnable = object : Runnable {
            override fun run() {
                val dots = ".".repeat(dotCount)
                textView.text = "$baseText$dots"
                dotCount = (dotCount + 1) % 4 // Cycle 0, 1, 2, 3
                ellipsisHandler.postDelayed(this, 500) // Update every 500ms
            }
        }

        ellipsisAnimations[textView] = runnable
        ellipsisHandler.post(runnable)
    }

    /**
     * Stop ellipsis animation for a TextView
     */
    private fun stopEllipsisAnimation(textView: TextView) {
        ellipsisAnimations[textView]?.let { runnable ->
            ellipsisHandler.removeCallbacks(runnable)
            ellipsisAnimations.remove(textView)
        }
    }

    /**
     * Animate typing indicator dots (bouncing effect like iMessage/WhatsApp)
     * Each dot fades up and down in sequence
     */
    private fun startTypingAnimation(dot1: TextView, dot2: TextView, dot3: TextView) {
        Log.d(TAG, "startTypingAnimation() called - starting bounce animation")

        // Stop any existing animation on these views first (important for RecyclerView recycling)
        stopTypingAnimation(dot1, dot2, dot3)

        val dots = listOf(dot1, dot2, dot3)

        // Set initial state - all dots at normal size
        dots.forEach {
            it.scaleX = 1.0f
            it.scaleY = 1.0f
        }

        var currentDot = 0
        val runnable = object : Runnable {
            override fun run() {
                // Safety check: make sure views are still attached before animating
                if (dot1.parent == null) {
                    Log.d(TAG, "Typing animation stopped - views detached")
                    stopTypingAnimation(dot1, dot2, dot3)
                    return
                }

                Log.d(TAG, "Typing animation tick - bouncing dot $currentDot")

                // Reset all dots to normal size
                dots.forEach {
                    it.animate()
                        .scaleX(1.0f)
                        .scaleY(1.0f)
                        .setDuration(200)
                        .start()
                }

                // Bounce current dot (scale up)
                dots[currentDot].animate()
                    .scaleX(1.4f)
                    .scaleY(1.4f)
                    .setDuration(200)
                    .start()

                // Move to next dot
                currentDot = (currentDot + 1) % 3

                ellipsisHandler.postDelayed(this, 400) // Update every 400ms
            }
        }

        // Store runnable using first dot as key (representative)
        ellipsisAnimations[dot1] = runnable
        ellipsisHandler.post(runnable)
        Log.d(TAG, "Typing animation runnable posted to handler")
    }

    /**
     * Stop typing indicator animation
     */
    private fun stopTypingAnimation(dot1: TextView, dot2: TextView? = null, dot3: TextView? = null) {
        ellipsisAnimations[dot1]?.let { runnable ->
            ellipsisHandler.removeCallbacks(runnable)
            ellipsisAnimations.remove(dot1)

            // Reset all dots to normal size
            listOf(dot1, dot2, dot3).forEach { dot ->
                dot?.scaleX = 1.0f
                dot?.scaleY = 1.0f
            }
        }
    }

    class SentMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: LinearLayout = view.findViewById(R.id.messageBubble)
        val messageText: TextView = view.findViewById(R.id.messageText)
        val messageStatus: ImageView = view.findViewById(R.id.messageStatus)
        val swipeRevealedTime: TextView = view.findViewById(R.id.swipeRevealedTime)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    class ReceivedMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: LinearLayout = view.findViewById(R.id.messageBubble)
        val messageText: TextView = view.findViewById(R.id.messageText)
        val swipeRevealedTime: TextView = view.findViewById(R.id.swipeRevealedTime)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    class PendingMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: LinearLayout = view.findViewById(R.id.messageBubble)
        val downloadButton: ImageView = view.findViewById(R.id.downloadButton)
        val downloadingText: TextView = view.findViewById(R.id.downloadingText)
        val swipeRevealedTime: TextView = view.findViewById(R.id.swipeRevealedTime)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
        val typingIndicator: LinearLayout = view.findViewById(R.id.typingIndicator)
        val typingDot1: TextView = view.findViewById(R.id.typingDot1)
        val typingDot2: TextView = view.findViewById(R.id.typingDot2)
        val typingDot3: TextView = view.findViewById(R.id.typingDot3)
    }

    class VoiceSentMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val voiceBubble: LinearLayout = view.findViewById(R.id.voiceBubble)
        val playButton: ImageView = view.findViewById(R.id.playButton)
        val progressBar: android.widget.ProgressBar = view.findViewById(R.id.progressBar)
        val waveformProgress: ImageView = view.findViewById(R.id.waveformProgress)
        val durationText: TextView = view.findViewById(R.id.durationText)
        val timestampText: TextView = view.findViewById(R.id.timestampText)
        val statusIcon: ImageView = view.findViewById(R.id.statusIcon)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    class VoiceReceivedMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val voiceBubble: LinearLayout = view.findViewById(R.id.voiceBubble)
        val playButton: ImageView = view.findViewById(R.id.playButton)
        val progressBar: android.widget.ProgressBar = view.findViewById(R.id.progressBar)
        val waveformProgress: ImageView = view.findViewById(R.id.waveformProgress)
        val durationText: TextView = view.findViewById(R.id.durationText)
        val timestampText: TextView = view.findViewById(R.id.timestampText)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    class ImageSentMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: CardView = view.findViewById(R.id.messageBubble)
        val messageImage: ImageView = view.findViewById(R.id.messageImage)
        val messageStatus: ImageView = view.findViewById(R.id.messageStatus)
        val swipeRevealedTime: TextView = view.findViewById(R.id.swipeRevealedTime)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    class ImageReceivedMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: CardView = view.findViewById(R.id.messageBubble)
        val messageImage: ImageView = view.findViewById(R.id.messageImage)
        val swipeRevealedTime: TextView = view.findViewById(R.id.swipeRevealedTime)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    // Payment request sent by me (I'm requesting money from them)
    class PaymentRequestSentViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: CardView = view.findViewById(R.id.messageBubble)
        val paymentLabel: TextView = view.findViewById(R.id.paymentLabel)
        val paymentAmount: TextView = view.findViewById(R.id.paymentAmount)
        val paymentAmountUsd: TextView = view.findViewById(R.id.paymentAmountUsd)
        val paymentStatus: TextView = view.findViewById(R.id.paymentStatus)
        val messageStatus: ImageView = view.findViewById(R.id.messageStatus)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    // Payment request received (they're requesting money from me)
    class PaymentRequestReceivedViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: CardView = view.findViewById(R.id.messageBubble)
        val paymentLabel: TextView = view.findViewById(R.id.paymentLabel)
        val paymentAmount: TextView = view.findViewById(R.id.paymentAmount)
        val paymentAmountUsd: TextView = view.findViewById(R.id.paymentAmountUsd)
        val payButton: TextView = view.findViewById(R.id.payButton)
        val paymentStatus: TextView = view.findViewById(R.id.paymentStatus)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    // Payment sent by me (I paid them)
    class PaymentSentViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: CardView = view.findViewById(R.id.messageBubble)
        val paymentLabel: TextView = view.findViewById(R.id.paymentLabel)
        val paymentAmount: TextView = view.findViewById(R.id.paymentAmount)
        val paymentAmountUsd: TextView = view.findViewById(R.id.paymentAmountUsd)
        val tapForDetails: TextView = view.findViewById(R.id.tapForDetails)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    // Payment received (they paid me)
    class PaymentReceivedViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: CardView = view.findViewById(R.id.messageBubble)
        val paymentLabel: TextView = view.findViewById(R.id.paymentLabel)
        val paymentAmount: TextView = view.findViewById(R.id.paymentAmount)
        val paymentAmountUsd: TextView = view.findViewById(R.id.paymentAmountUsd)
        val tapForDetails: TextView = view.findViewById(R.id.tapForDetails)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    override fun getItemViewType(position: Int): Int {
        Log.d(TAG, "getItemViewType() called for position $position (currentList.size=${currentList.size})")

        if (position >= currentList.size) {
            Log.e(TAG, "getItemViewType: position $position >= currentList.size ${currentList.size}")
            return VIEW_TYPE_SENT // Fallback
        }

        val item = currentList[position]

        return when (item) {
            is ChatListItem.PendingPingItem -> {
                Log.d(TAG, "-> VIEW_TYPE_PENDING (ping: ${item.pingInbox.pingId.take(8)})")
                VIEW_TYPE_PENDING
            }
            is ChatListItem.MessageItem -> {
                val message = item.message
                val viewType = when {
                    message.messageType == Message.MESSAGE_TYPE_VOICE && message.isSentByMe -> VIEW_TYPE_VOICE_SENT
                    message.messageType == Message.MESSAGE_TYPE_VOICE && !message.isSentByMe -> VIEW_TYPE_VOICE_RECEIVED
                    message.messageType == Message.MESSAGE_TYPE_IMAGE && message.isSentByMe -> VIEW_TYPE_IMAGE_SENT
                    message.messageType == Message.MESSAGE_TYPE_IMAGE && !message.isSentByMe -> VIEW_TYPE_IMAGE_RECEIVED
                    message.messageType == Message.MESSAGE_TYPE_PAYMENT_REQUEST && message.isSentByMe -> VIEW_TYPE_PAYMENT_REQUEST_SENT
                    message.messageType == Message.MESSAGE_TYPE_PAYMENT_REQUEST && !message.isSentByMe -> VIEW_TYPE_PAYMENT_REQUEST_RECEIVED
                    message.messageType == Message.MESSAGE_TYPE_PAYMENT_SENT && message.isSentByMe -> VIEW_TYPE_PAYMENT_SENT
                    message.messageType == Message.MESSAGE_TYPE_PAYMENT_SENT && !message.isSentByMe -> VIEW_TYPE_PAYMENT_RECEIVED
                    message.isSentByMe -> VIEW_TYPE_SENT
                    else -> VIEW_TYPE_RECEIVED
                }
                Log.d(TAG, "-> viewType=$viewType (type=${message.messageType}, sentByMe=${message.isSentByMe})")
                viewType
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        Log.d(TAG, "onCreateViewHolder() called for viewType=$viewType")
        return when (viewType) {
            VIEW_TYPE_SENT -> {
                Log.d(TAG, "-> Creating SentMessageViewHolder")
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_sent, parent, false)
                SentMessageViewHolder(view)
            }
            VIEW_TYPE_PENDING -> {
                Log.d(TAG, "-> Creating PendingMessageViewHolder")
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_pending, parent, false)
                PendingMessageViewHolder(view)
            }
            VIEW_TYPE_VOICE_SENT -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_voice_sent, parent, false)
                VoiceSentMessageViewHolder(view)
            }
            VIEW_TYPE_VOICE_RECEIVED -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_voice_received, parent, false)
                VoiceReceivedMessageViewHolder(view)
            }
            VIEW_TYPE_IMAGE_SENT -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_image_sent, parent, false)
                ImageSentMessageViewHolder(view)
            }
            VIEW_TYPE_IMAGE_RECEIVED -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_image_received, parent, false)
                ImageReceivedMessageViewHolder(view)
            }
            VIEW_TYPE_PAYMENT_REQUEST_SENT -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_payment_request_sent, parent, false)
                PaymentRequestSentViewHolder(view)
            }
            VIEW_TYPE_PAYMENT_REQUEST_RECEIVED -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_payment_request_received, parent, false)
                PaymentRequestReceivedViewHolder(view)
            }
            VIEW_TYPE_PAYMENT_SENT -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_payment_sent, parent, false)
                PaymentSentViewHolder(view)
            }
            VIEW_TYPE_PAYMENT_RECEIVED -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_payment_received, parent, false)
                PaymentReceivedViewHolder(view)
            }
            else -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_received, parent, false)
                ReceivedMessageViewHolder(view)
            }
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        Log.d(TAG, "onBindViewHolder() called for position=$position, holder type=${holder.javaClass.simpleName}")
        val item = getItem(position)
        when (holder) {
            is SentMessageViewHolder -> {
                Log.d(TAG, "-> Binding SentMessageViewHolder")
                val message = (item as ChatListItem.MessageItem).message
                bindSentMessage(holder, message, position)
            }
            is ReceivedMessageViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindReceivedMessage(holder, message, position)
            }
            is VoiceSentMessageViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindVoiceSentMessage(holder, message, position)
            }
            is VoiceReceivedMessageViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindVoiceReceivedMessage(holder, message, position)
            }
            is ImageSentMessageViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindImageSentMessage(holder, message, position)
            }
            is ImageReceivedMessageViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindImageReceivedMessage(holder, message, position)
            }
            is PaymentRequestSentViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindPaymentRequestSent(holder, message, position)
            }
            is PaymentRequestReceivedViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindPaymentRequestReceived(holder, message, position)
            }
            is PaymentSentViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindPaymentSent(holder, message, position)
            }
            is PaymentReceivedViewHolder -> {
                val message = (item as ChatListItem.MessageItem).message
                bindPaymentReceived(holder, message, position)
            }
            is PendingMessageViewHolder -> {
                bindPendingMessage(holder, position)
            }
        }
    }

    private fun bindSentMessage(holder: SentMessageViewHolder, message: Message, position: Int) {
        holder.messageText.text = message.encryptedContent
        holder.messageStatus.setImageResource(getStatusIcon(message))

        // Show timestamp header if this is the first message or date changed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Set swipe-revealed time
        holder.swipeRevealedTime.text = formatTime(message.timestamp)
        holder.swipeRevealedTime.visibility = if (position == currentSwipeRevealedPosition) View.VISIBLE else View.GONE

        // Handle selection mode
        if (isSelectionMode) {
            holder.messageCheckbox.visibility = View.VISIBLE
            val messageIdStr = message.id.toString()
            holder.messageCheckbox.isChecked = selectedMessages.contains(messageIdStr)
            holder.messageCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(messageIdStr)
                } else {
                    selectedMessages.remove(messageIdStr)
                }
            }

            // Allow tapping message bubble to toggle selection
            holder.messageBubble.setOnClickListener {
                val isSelected = selectedMessages.contains(messageIdStr)
                if (isSelected) {
                    selectedMessages.remove(messageIdStr)
                    holder.messageCheckbox.isChecked = false
                } else {
                    selectedMessages.add(messageIdStr)
                    holder.messageCheckbox.isChecked = true
                }
            }
        } else {
            holder.messageCheckbox.visibility = View.GONE
            holder.messageCheckbox.setOnCheckedChangeListener(null)
            holder.messageBubble.setOnClickListener(null)

            // Add long-press listener to show popup menu with Copy and Delete options
            holder.messageBubble.setOnLongClickListener {
                showMessagePopupMenu(it, message)
                true
            }
        }

        // Setup swipe gesture (disabled in selection mode)
        if (!isSelectionMode) {
            setupSwipeGesture(holder.messageBubble, holder.swipeRevealedTime, holder.messageStatus, position, isSent = true)
        }
    }

    private fun bindReceivedMessage(holder: ReceivedMessageViewHolder, message: Message, position: Int) {
        holder.messageText.text = message.encryptedContent

        // Show timestamp header if this is the first message or date changed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Set swipe-revealed time
        holder.swipeRevealedTime.text = formatTime(message.timestamp)
        holder.swipeRevealedTime.visibility = if (position == currentSwipeRevealedPosition) View.VISIBLE else View.GONE

        // Handle selection mode
        if (isSelectionMode) {
            holder.messageCheckbox.visibility = View.VISIBLE
            val messageIdStr = message.id.toString()
            holder.messageCheckbox.isChecked = selectedMessages.contains(messageIdStr)
            holder.messageCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(messageIdStr)
                } else {
                    selectedMessages.remove(messageIdStr)
                }
            }

            // Allow tapping message bubble to toggle selection
            holder.messageBubble.setOnClickListener {
                val isSelected = selectedMessages.contains(messageIdStr)
                if (isSelected) {
                    selectedMessages.remove(messageIdStr)
                    holder.messageCheckbox.isChecked = false
                } else {
                    selectedMessages.add(messageIdStr)
                    holder.messageCheckbox.isChecked = true
                }
            }
        } else {
            holder.messageCheckbox.visibility = View.GONE
            holder.messageCheckbox.setOnCheckedChangeListener(null)
            holder.messageBubble.setOnClickListener(null)

            // Add long-press listener to show popup menu with Copy and Delete options
            holder.messageBubble.setOnLongClickListener {
                showMessagePopupMenu(it, message)
                true
            }
        }

        // Setup swipe gesture (disabled in selection mode)
        if (!isSelectionMode) {
            setupSwipeGesture(holder.messageBubble, holder.swipeRevealedTime, null, position, isSent = false)
        }
    }

    private fun bindPendingMessage(holder: PendingMessageViewHolder, position: Int) {
        // Get the specific pending ping for this position
        val item = getItem(position)
        val pingInbox = (item as ChatListItem.PendingPingItem).pingInbox
        val timestamp = pingInbox.firstSeenAt

        // In-memory sets override DB state for immediate UI feedback
        // (DB state lags behind because download service hasn't transitioned yet)
        val isAutoPong = pingInbox.pingId in autoPongPingIds
        val isDownloading = pingInbox.pingId in downloadingPingIds

        // Priority: autoPong (typing) > downloading (manual) > DB state
        when {
            isAutoPong -> {
                // Auto-PONG in progress: show typing indicator with animated dots
                holder.downloadButton.visibility = View.GONE
                holder.downloadingText.visibility = View.GONE
                holder.typingIndicator.visibility = View.VISIBLE
                stopEllipsisAnimation(holder.downloadingText)
                startTypingAnimation(holder.typingDot1, holder.typingDot2, holder.typingDot3)
            }
            isDownloading || pingInbox.state == com.securelegion.database.entities.PingInbox.STATE_DOWNLOAD_QUEUED -> {
                // Download actively in progress (in-memory flag OR DB state DOWNLOAD_QUEUED)
                holder.downloadButton.visibility = View.GONE
                holder.downloadingText.visibility = View.VISIBLE
                holder.typingIndicator.visibility = View.GONE
                stopTypingAnimation(holder.typingDot1, holder.typingDot2, holder.typingDot3)
                startEllipsisAnimation(holder.downloadingText, "Downloading")
            }
            pingInbox.state == com.securelegion.database.entities.PingInbox.STATE_PING_SEEN
                || pingInbox.state == com.securelegion.database.entities.PingInbox.STATE_FAILED_TEMP
                || pingInbox.state == com.securelegion.database.entities.PingInbox.STATE_MANUAL_REQUIRED
                || pingInbox.state == com.securelegion.database.entities.PingInbox.STATE_PONG_SENT -> {
                // Lock icon — user action required
                // PONG_SENT included: stale state after logout/login (process died mid-download)
                holder.downloadButton.visibility = View.VISIBLE
                holder.downloadingText.visibility = View.GONE
                holder.typingIndicator.visibility = View.GONE
                stopEllipsisAnimation(holder.downloadingText)
                stopTypingAnimation(holder.typingDot1, holder.typingDot2, holder.typingDot3)
            }
            else -> {
                // Fallback: show lock icon
                holder.downloadButton.visibility = View.VISIBLE
                holder.downloadingText.visibility = View.GONE
                holder.typingIndicator.visibility = View.GONE
                stopEllipsisAnimation(holder.downloadingText)
                stopTypingAnimation(holder.typingDot1, holder.typingDot2, holder.typingDot3)
            }
        }

        // Show timestamp header if this is the first message or date changed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Set swipe-revealed time
        holder.swipeRevealedTime.text = formatTime(timestamp)
        holder.swipeRevealedTime.visibility = if (position == currentSwipeRevealedPosition) View.VISIBLE else View.GONE

        // Handle selection mode for pending messages
        if (isSelectionMode) {
            holder.messageCheckbox.visibility = View.VISIBLE
            // Use pingId directly as identifier
            val pingIdStr = "ping:" + pingInbox.pingId
            val isPendingSelected = selectedMessages.contains(pingIdStr)
            holder.messageCheckbox.isChecked = isPendingSelected

            holder.messageCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(pingIdStr)
                } else {
                    selectedMessages.remove(pingIdStr)
                }
            }

            // Allow tapping bubble to toggle selection
            holder.messageBubble.setOnClickListener {
                val isSelected = selectedMessages.contains(pingIdStr)
                if (isSelected) {
                    selectedMessages.remove(pingIdStr)
                    holder.messageCheckbox.isChecked = false
                } else {
                    selectedMessages.add(pingIdStr)
                    holder.messageCheckbox.isChecked = true
                }
            }

            // Disable download button in selection mode
            holder.downloadButton.setOnClickListener(null)
            holder.downloadButton.isEnabled = false
        } else {
            holder.messageCheckbox.visibility = View.GONE
            holder.messageCheckbox.setOnCheckedChangeListener(null)
            holder.messageBubble.setOnClickListener(null)
            holder.messageBubble.setOnLongClickListener(null)

            // Enable download button in normal mode
            holder.downloadButton.isEnabled = true
            holder.downloadButton.setOnClickListener {
                holder.downloadButton.visibility = View.GONE
                holder.downloadingText.visibility = View.VISIBLE
                onDownloadClick?.invoke(pingInbox.pingId) // Pass specific ping ID
            }
        }

        // Setup swipe gesture (only in normal mode)
        if (!isSelectionMode) {
            setupSwipeGesture(holder.messageBubble, holder.swipeRevealedTime, null, position, isSent = false)
        }
    }

    private fun bindVoiceSentMessage(holder: VoiceSentMessageViewHolder, message: Message, position: Int) {
        val duration = message.voiceDuration ?: 0
        holder.durationText.text = formatDuration(duration)
        holder.timestampText.text = formatTime(message.timestamp)

        // Set status icon (same as text messages - circle system)
        holder.statusIcon.setImageResource(getStatusIcon(message))

        // Set play/pause icon based on current playback state
        val isPlaying = currentlyPlayingMessageId == message.messageId
        holder.playButton.setImageResource(
            if (isPlaying) R.drawable.ic_pause_blue else R.drawable.ic_play_blue
        )

        // Handle selection mode
        if (isSelectionMode) {
            holder.messageCheckbox.visibility = View.VISIBLE
            val messageIdStr = message.id.toString()
            holder.messageCheckbox.isChecked = selectedMessages.contains(messageIdStr)
            holder.messageCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(messageIdStr)
                } else {
                    selectedMessages.remove(messageIdStr)
                }
            }

            // Allow tapping voice bubble to toggle selection
            holder.voiceBubble.setOnClickListener {
                val messageIdStr = message.id.toString()
                val isSelected = selectedMessages.contains(messageIdStr)
                if (isSelected) {
                    selectedMessages.remove(messageIdStr)
                    holder.messageCheckbox.isChecked = false
                } else {
                    selectedMessages.add(messageIdStr)
                    holder.messageCheckbox.isChecked = true
                }
            }

            // Disable play button in selection mode
            holder.playButton.setOnClickListener(null)
            holder.playButton.isEnabled = false
        } else {
            holder.messageCheckbox.visibility = View.GONE
            holder.messageCheckbox.setOnCheckedChangeListener(null)
            holder.voiceBubble.setOnClickListener(null)

            // Enable play button in normal mode
            holder.playButton.isEnabled = true
            holder.playButton.setOnClickListener {
                onVoicePlayClick?.invoke(message)
            }

            // Enable long-press to show popup menu
            holder.voiceBubble.setOnLongClickListener {
                showMessagePopupMenu(it, message)
                true
            }
        }

        // Reset progress
        holder.progressBar.progress = 0
        holder.waveformProgress.scaleX = 0f
        holder.waveformProgress.pivotX = 0f
    }

    private fun bindVoiceReceivedMessage(holder: VoiceReceivedMessageViewHolder, message: Message, position: Int) {
        val duration = message.voiceDuration ?: 0
        holder.durationText.text = formatDuration(duration)
        holder.timestampText.text = formatTime(message.timestamp)

        // Set play/pause icon based on current playback state
        val isPlaying = currentlyPlayingMessageId == message.messageId
        holder.playButton.setImageResource(
            if (isPlaying) R.drawable.ic_pause_blue else R.drawable.ic_play_blue
        )

        // Handle selection mode
        if (isSelectionMode) {
            holder.messageCheckbox.visibility = View.VISIBLE
            val messageIdStr = message.id.toString()
            holder.messageCheckbox.isChecked = selectedMessages.contains(messageIdStr)
            holder.messageCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(messageIdStr)
                } else {
                    selectedMessages.remove(messageIdStr)
                }
            }

            // Allow tapping voice bubble to toggle selection
            holder.voiceBubble.setOnClickListener {
                val messageIdStr = message.id.toString()
                val isSelected = selectedMessages.contains(messageIdStr)
                if (isSelected) {
                    selectedMessages.remove(messageIdStr)
                    holder.messageCheckbox.isChecked = false
                } else {
                    selectedMessages.add(messageIdStr)
                    holder.messageCheckbox.isChecked = true
                }
            }

            // Disable play button in selection mode
            holder.playButton.setOnClickListener(null)
            holder.playButton.isEnabled = false
        } else {
            holder.messageCheckbox.visibility = View.GONE
            holder.messageCheckbox.setOnCheckedChangeListener(null)
            holder.voiceBubble.setOnClickListener(null)

            // Enable play button in normal mode
            holder.playButton.isEnabled = true
            holder.playButton.setOnClickListener {
                onVoicePlayClick?.invoke(message)
            }

            // Enable long-press to show popup menu
            holder.voiceBubble.setOnLongClickListener {
                showMessagePopupMenu(it, message)
                true
            }
        }

        // Reset progress
        holder.progressBar.progress = 0
        holder.waveformProgress.scaleX = 0f
        holder.waveformProgress.pivotX = 0f
    }

    private fun bindImageSentMessage(holder: ImageSentMessageViewHolder, message: Message, position: Int) {
        // Load image from attachmentData (Base64 encoded)
        loadImageIntoView(holder.messageImage, message.attachmentData)

        // Add click listener to open full screen image
        holder.messageImage.setOnClickListener {
            message.attachmentData?.let { imageData ->
                onImageClick?.invoke(imageData)
            }
        }

        holder.messageStatus.setImageResource(getStatusIcon(message))

        // Show timestamp header if this is the first message or date changed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Set swipe-revealed time
        holder.swipeRevealedTime.text = formatTime(message.timestamp)
        holder.swipeRevealedTime.visibility = if (position == currentSwipeRevealedPosition) View.VISIBLE else View.GONE

        // Handle selection mode
        if (isSelectionMode) {
            holder.messageCheckbox.visibility = View.VISIBLE
            val messageIdStr = message.id.toString()
            holder.messageCheckbox.isChecked = selectedMessages.contains(messageIdStr)
            holder.messageCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(messageIdStr)
                } else {
                    selectedMessages.remove(messageIdStr)
                }
            }

            // Allow tapping image bubble to toggle selection
            holder.messageBubble.setOnClickListener {
                val isSelected = selectedMessages.contains(messageIdStr)
                if (isSelected) {
                    selectedMessages.remove(messageIdStr)
                    holder.messageCheckbox.isChecked = false
                } else {
                    selectedMessages.add(messageIdStr)
                    holder.messageCheckbox.isChecked = true
                }
            }
        } else {
            holder.messageCheckbox.visibility = View.GONE
            holder.messageCheckbox.setOnCheckedChangeListener(null)

            // Click to view full image
            holder.messageBubble.setOnClickListener {
                onImageClick?.invoke(message.attachmentData ?: "")
            }

            // Add long-press listener to show popup menu with Delete option
            holder.messageBubble.setOnLongClickListener {
                showMessagePopupMenu(it, message)
                true
            }
        }

        // Setup swipe gesture (disabled in selection mode)
        if (!isSelectionMode) {
            setupSwipeGestureForCard(holder.messageBubble, holder.swipeRevealedTime, holder.messageStatus, position, isSent = true)
        }
    }

    private fun bindImageReceivedMessage(holder: ImageReceivedMessageViewHolder, message: Message, position: Int) {
        // Load image from attachmentData (Base64 encoded)
        loadImageIntoView(holder.messageImage, message.attachmentData)

        // Add click listener to open full screen image
        holder.messageImage.setOnClickListener {
            message.attachmentData?.let { imageData ->
                onImageClick?.invoke(imageData)
            }
        }

        // Show timestamp header if this is the first message or date changed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Set swipe-revealed time
        holder.swipeRevealedTime.text = formatTime(message.timestamp)
        holder.swipeRevealedTime.visibility = if (position == currentSwipeRevealedPosition) View.VISIBLE else View.GONE

        // Handle selection mode
        if (isSelectionMode) {
            holder.messageCheckbox.visibility = View.VISIBLE
            val messageIdStr = message.id.toString()
            holder.messageCheckbox.isChecked = selectedMessages.contains(messageIdStr)
            holder.messageCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(messageIdStr)
                } else {
                    selectedMessages.remove(messageIdStr)
                }
            }

            // Allow tapping image bubble to toggle selection
            holder.messageBubble.setOnClickListener {
                val isSelected = selectedMessages.contains(messageIdStr)
                if (isSelected) {
                    selectedMessages.remove(messageIdStr)
                    holder.messageCheckbox.isChecked = false
                } else {
                    selectedMessages.add(messageIdStr)
                    holder.messageCheckbox.isChecked = true
                }
            }
        } else {
            holder.messageCheckbox.visibility = View.GONE
            holder.messageCheckbox.setOnCheckedChangeListener(null)

            // Click to view full image
            holder.messageBubble.setOnClickListener {
                onImageClick?.invoke(message.attachmentData ?: "")
            }

            // Add long-press listener to show popup menu with Delete option
            holder.messageBubble.setOnLongClickListener {
                showMessagePopupMenu(it, message)
                true
            }
        }

        // Setup swipe gesture (disabled in selection mode)
        if (!isSelectionMode) {
            setupSwipeGestureForCard(holder.messageBubble, holder.swipeRevealedTime, null, position, isSent = false)
        }
    }

    // ==================== PAYMENT CARD BINDING FUNCTIONS ====================

    private fun bindPaymentRequestSent(holder: PaymentRequestSentViewHolder, message: Message, position: Int) {
        holder.paymentAmount.text = getUsdAmount(message)
        holder.paymentAmountUsd.text = getCryptoAmount(message)

        // Click to refresh price
        holder.paymentAmountUsd.setOnClickListener {
            onPriceRefreshClick?.invoke(message, holder.paymentAmount, holder.paymentAmountUsd)
        }

        // Set status based on payment status
        val status = message.paymentStatus ?: Message.PAYMENT_STATUS_PENDING
        holder.paymentStatus.text = when (status) {
            Message.PAYMENT_STATUS_PAID -> "Paid"
            Message.PAYMENT_STATUS_EXPIRED -> "Expired"
            Message.PAYMENT_STATUS_CANCELLED -> "Cancelled"
            else -> "Pending"
        }

        // Update status color
        val ctx = holder.itemView.context
        val statusColor = when (status) {
            Message.PAYMENT_STATUS_PAID -> ContextCompat.getColor(ctx, R.color.success_green)
            Message.PAYMENT_STATUS_EXPIRED -> com.google.android.material.color.MaterialColors.getColor(holder.itemView, com.google.android.material.R.attr.colorOnSurfaceVariant)
            Message.PAYMENT_STATUS_CANCELLED -> ContextCompat.getColor(ctx, R.color.warning_red)
            else -> ContextCompat.getColor(ctx, R.color.warning_yellow)
        }
        holder.paymentStatus.setTextColor(statusColor)

        // Set message status icon (circle with checkmarks) based on ACK flags
        holder.messageStatus.setImageResource(getStatusIcon(message))

        // Show timestamp header if needed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Handle selection mode
        handlePaymentSelectionMode(holder.messageCheckbox, holder.messageBubble, message)

        // Click to view details
        if (!isSelectionMode) {
            holder.messageBubble.setOnClickListener {
                onPaymentDetailsClick?.invoke(message)
            }
        }
    }

    private fun bindPaymentRequestReceived(holder: PaymentRequestReceivedViewHolder, message: Message, position: Int) {
        holder.paymentAmount.text = getUsdAmount(message)
        holder.paymentAmountUsd.text = getCryptoAmount(message)

        // Click to refresh price
        holder.paymentAmountUsd.setOnClickListener {
            onPriceRefreshClick?.invoke(message, holder.paymentAmount, holder.paymentAmountUsd)
        }

        // Check if this is a "Send Money" offer (empty recipient) or "Request Money" (has recipient)
        val isSendMoneyOffer = try {
            val quote = NLx402Manager.PaymentQuote.fromJson(message.paymentQuoteJson ?: "")
            quote?.recipient.isNullOrEmpty()
        } catch (e: Exception) {
            false
        }

        // Update button text and label based on flow type
        if (isSendMoneyOffer) {
            holder.payButton.text = "Accept"
            holder.paymentLabel.text = "Wants to send you"
        } else {
            holder.payButton.text = "Pay"
            holder.paymentLabel.text = "Payment Request"
        }

        val status = message.paymentStatus ?: Message.PAYMENT_STATUS_PENDING
        val isPending = status == Message.PAYMENT_STATUS_PENDING

        // Show/hide Pay/Accept button vs status text
        if (isPending) {
            holder.payButton.visibility = View.VISIBLE
            holder.paymentStatus.visibility = View.GONE

            // Handle button click
            if (!isSelectionMode) {
                holder.payButton.setOnClickListener {
                    onPaymentRequestClick?.invoke(message)
                }
            }
        } else {
            holder.payButton.visibility = View.GONE
            holder.paymentStatus.visibility = View.VISIBLE
            holder.paymentStatus.text = when (status) {
                Message.PAYMENT_STATUS_PAID -> if (isSendMoneyOffer) "Received" else "Paid"
                Message.PAYMENT_STATUS_EXPIRED -> "Expired"
                Message.PAYMENT_STATUS_CANCELLED -> "Cancelled"
                else -> status
            }
        }

        // Show timestamp header if needed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Handle selection mode
        handlePaymentSelectionMode(holder.messageCheckbox, holder.messageBubble, message)

        // Remove long press listener
        holder.messageBubble.setOnLongClickListener(null)
    }

    private fun bindPaymentSent(holder: PaymentSentViewHolder, message: Message, position: Int) {
        holder.paymentAmount.text = getUsdAmount(message)
        holder.paymentAmountUsd.text = getCryptoAmount(message)

        // Click to refresh price
        holder.paymentAmountUsd.setOnClickListener {
            onPriceRefreshClick?.invoke(message, holder.paymentAmount, holder.paymentAmountUsd)
        }

        // Show timestamp header if needed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Handle selection mode
        handlePaymentSelectionMode(holder.messageCheckbox, holder.messageBubble, message)

        // Click to view details
        if (!isSelectionMode) {
            holder.messageBubble.setOnClickListener {
                onPaymentDetailsClick?.invoke(message)
            }
        }
    }

    private fun bindPaymentReceived(holder: PaymentReceivedViewHolder, message: Message, position: Int) {
        holder.paymentAmount.text = getUsdAmount(message)
        holder.paymentAmountUsd.text = getCryptoAmount(message)

        // Click to refresh price
        holder.paymentAmountUsd.setOnClickListener {
            onPriceRefreshClick?.invoke(message, holder.paymentAmount, holder.paymentAmountUsd)
        }

        // Show timestamp header if needed
        if (shouldShowTimestampHeader(position)) {
            holder.timestampHeader.visibility = View.VISIBLE
            holder.timestampHeader.text = formatDateHeaderWithTime(message.timestamp)
        } else {
            holder.timestampHeader.visibility = View.GONE
        }

        // Handle selection mode
        handlePaymentSelectionMode(holder.messageCheckbox, holder.messageBubble, message)

        // Click to view details
        if (!isSelectionMode) {
            holder.messageBubble.setOnClickListener {
                onPaymentDetailsClick?.invoke(message)
            }
        }
    }

    private fun handlePaymentSelectionMode(checkbox: CheckBox, bubble: CardView, message: Message) {
        val messageIdStr = message.id.toString()

        if (isSelectionMode) {
            checkbox.visibility = View.VISIBLE
            checkbox.isChecked = selectedMessages.contains(messageIdStr)
            checkbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedMessages.add(messageIdStr)
                } else {
                    selectedMessages.remove(messageIdStr)
                }
            }

            bubble.setOnClickListener {
                val isSelected = selectedMessages.contains(messageIdStr)
                if (isSelected) {
                    selectedMessages.remove(messageIdStr)
                    checkbox.isChecked = false
                } else {
                    selectedMessages.add(messageIdStr)
                    checkbox.isChecked = true
                }
            }

            bubble.setOnLongClickListener(null)
        } else {
            checkbox.visibility = View.GONE
            checkbox.setOnCheckedChangeListener(null)
            bubble.setOnLongClickListener(null)
        }
    }

    /**
     * Get USD amount as the main display
     * Uses cached live prices from API
     */
    private fun getUsdAmount(message: Message): String {
        val amount = message.paymentAmount ?: 0L
        val token = message.paymentToken ?: "SOL"

        val decimals = when (token.uppercase()) {
            "SOL" -> 9
            "ZEC" -> 8
            "USDC", "USDT" -> 6
            else -> 9
        }
        val divisor = java.math.BigDecimal.TEN.pow(decimals)
        val cryptoAmount = java.math.BigDecimal(amount).divide(divisor).toDouble()

        // Use cached live price, fallback to estimates
        val usdPrice = when (token.uppercase()) {
            "SOL" -> if (cachedSolPrice > 0) cachedSolPrice else 150.0
            "ZEC" -> if (cachedZecPrice > 0) cachedZecPrice else 35.0
            "USDC", "USDT" -> 1.0
            else -> 0.0
        }

        val usdValue = cryptoAmount * usdPrice
        return String.format("$%.2f", usdValue)
    }

    /**
     * Get crypto amount with clean formatting (no excessive zeros)
     */
    private fun getCryptoAmount(message: Message): String {
        val amount = message.paymentAmount ?: 0L
        val token = message.paymentToken ?: "SOL"

        val decimals = when (token.uppercase()) {
            "SOL" -> 9
            "ZEC" -> 8
            "USDC", "USDT" -> 6
            else -> 9
        }
        val divisor = java.math.BigDecimal.TEN.pow(decimals)
        val cryptoAmount = java.math.BigDecimal(amount).divide(divisor).toDouble()

        // Smart formatting - show appropriate precision
        val formatted = when {
            cryptoAmount >= 1.0 -> String.format("%.2f", cryptoAmount)
            cryptoAmount >= 0.01 -> String.format("%.4f", cryptoAmount).trimEnd('0').trimEnd('.')
            cryptoAmount > 0.0 -> String.format("%.6f", cryptoAmount).trimEnd('0').trimEnd('.')
            else -> "0"
        }

        return "$formatted $token"
    }

    private fun loadImageIntoView(imageView: ImageView, base64Data: String?) {
        if (base64Data.isNullOrEmpty()) {
            imageView.setImageResource(R.drawable.ic_image_placeholder)
            return
        }

        try {
            val imageBytes = Base64.decode(base64Data, Base64.DEFAULT)
            val bitmap = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size)
            if (bitmap != null) {
                imageView.setImageBitmap(bitmap)
            } else {
                imageView.setImageResource(R.drawable.ic_image_placeholder)
            }
        } catch (e: Exception) {
            imageView.setImageResource(R.drawable.ic_image_placeholder)
        }
    }

    private fun setupSwipeGestureForCard(
        bubble: CardView,
        timeView: TextView,
        statusView: ImageView?,
        position: Int,
        isSent: Boolean
    ) {
        val gestureDetector = GestureDetector(bubble.context, object : GestureDetector.SimpleOnGestureListener() {
            override fun onDown(e: MotionEvent): Boolean = true

            override fun onScroll(
                e1: MotionEvent?,
                e2: MotionEvent,
                distanceX: Float,
                distanceY: Float
            ): Boolean {
                val swipeThreshold = 50f
                val delta = (e2.x - (e1?.x ?: 0f))

                if (!isSent && delta > swipeThreshold) {
                    revealTimestamp(position)
                    return true
                } else if (isSent && delta < -swipeThreshold) {
                    revealTimestamp(position)
                    return true
                }
                return false
            }

            override fun onSingleTapUp(e: MotionEvent): Boolean {
                if (position == currentSwipeRevealedPosition) {
                    hideTimestamp(position)
                }
                return true
            }
        })

        bubble.setOnTouchListener { _, event ->
            gestureDetector.onTouchEvent(event)
            false
        }
    }

    private fun formatDuration(seconds: Int): String {
        val minutes = seconds / 60
        val secs = seconds % 60
        return String.format("%d:%02d", minutes, secs)
    }

    private fun setupSwipeGesture(
        bubble: View,
        timeView: TextView,
        statusView: ImageView?,
        position: Int,
        isSent: Boolean
    ) {
        val gestureDetector = GestureDetector(bubble.context, object : GestureDetector.SimpleOnGestureListener() {
            override fun onDown(e: MotionEvent): Boolean = true

            override fun onScroll(
                e1: MotionEvent?,
                e2: MotionEvent,
                distanceX: Float,
                distanceY: Float
            ): Boolean {
                // Swipe right for received (left-aligned) messages
                // Swipe left for sent (right-aligned) messages
                val swipeThreshold = 50f
                val delta = (e2.x - (e1?.x ?: 0f))

                if (!isSent && delta > swipeThreshold) {
                    // Received message: swipe right to reveal time on left
                    revealTimestamp(position)
                    return true
                } else if (isSent && delta < -swipeThreshold) {
                    // Sent message: swipe left to reveal time on right
                    revealTimestamp(position)
                    return true
                }
                return false
            }

            override fun onSingleTapUp(e: MotionEvent): Boolean {
                // Tap to hide revealed timestamp
                if (position == currentSwipeRevealedPosition) {
                    hideTimestamp(position)
                }
                return true
            }
        })

        bubble.setOnTouchListener { _, event ->
            gestureDetector.onTouchEvent(event)
            false // Don't consume touch events - allow RecyclerView scrolling
        }
    }

    private fun revealTimestamp(position: Int) {
        val oldPosition = currentSwipeRevealedPosition
        currentSwipeRevealedPosition = position

        // Hide old one
        if (oldPosition != -1 && oldPosition != position) {
            notifyItemChanged(oldPosition)
        }

        // Show new one
        notifyItemChanged(position)
    }

    private fun hideTimestamp(position: Int) {
        currentSwipeRevealedPosition = -1
        notifyItemChanged(position)
    }

    private fun shouldShowTimestampHeader(position: Int): Boolean {
        if (position == 0) return true

        val currentItem = getItem(position)
        val currentTimestamp = when (currentItem) {
            is ChatListItem.MessageItem -> currentItem.message.timestamp
            is ChatListItem.PendingPingItem -> currentItem.pingInbox.firstSeenAt
        }

        val previousItem = getItem(position - 1)
        val previousTimestamp = when (previousItem) {
            is ChatListItem.MessageItem -> previousItem.message.timestamp
            is ChatListItem.PendingPingItem -> previousItem.pingInbox.firstSeenAt
        }

        // Show header if date changed
        return !isSameDay(currentTimestamp, previousTimestamp)
    }

    private fun isSameDay(timestamp1: Long, timestamp2: Long): Boolean {
        val cal1 = Calendar.getInstance().apply { timeInMillis = timestamp1 }
        val cal2 = Calendar.getInstance().apply { timeInMillis = timestamp2 }

        return cal1.get(Calendar.YEAR) == cal2.get(Calendar.YEAR) &&
               cal1.get(Calendar.DAY_OF_YEAR) == cal2.get(Calendar.DAY_OF_YEAR)
    }

    private fun formatDateHeader(timestamp: Long): String {
        val messageDate = Calendar.getInstance().apply { timeInMillis = timestamp }
        val today = Calendar.getInstance()
        val yesterday = Calendar.getInstance().apply { add(Calendar.DAY_OF_YEAR, -1) }

        return when {
            isSameDay(timestamp, today.timeInMillis) -> "Today"
            isSameDay(timestamp, yesterday.timeInMillis) -> "Yesterday"
            else -> {
                // Check if within the last week
                val weekAgo = Calendar.getInstance().apply { add(Calendar.DAY_OF_YEAR, -7) }
                if (messageDate.after(weekAgo)) {
                    // Show day of week (e.g., "Monday")
                    SimpleDateFormat("EEEE", Locale.getDefault()).format(Date(timestamp))
                } else {
                    // Show full date (e.g., "Jan 15, 2025")
                    SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(timestamp))
                }
            }
        }
    }

    private fun formatDateHeaderWithTime(timestamp: Long): String {
        val dateHeader = formatDateHeader(timestamp)
        val time = formatTime(timestamp)
        return "$dateHeader $time"
    }

    private fun formatTime(timestamp: Long): String {
        val sdf = SimpleDateFormat("h:mm a", Locale.getDefault())
        return sdf.format(Date(timestamp))
    }

    private fun getStatusIcon(message: Message): Int {
        // Check ACK flags instead of status to show accurate delivery state
        return when {
            message.status == Message.STATUS_FAILED -> R.drawable.status_failed // Red circle with X
            message.messageDelivered -> R.drawable.status_delivered // Solid circle with 2 checkmarks (message downloaded by receiver)
            message.pingDelivered -> R.drawable.status_sent // Circle with 1 checkmark (PING_ACK received, receiver notified)
            else -> {
                // No ACK yet — check if Tor is available
                val gate = com.securelegion.services.TorService.getTransportGate()
                if (gate == null || !gate.isOpenNow()) {
                    R.drawable.status_queued // Clock icon (queued, Tor offline)
                } else {
                    R.drawable.status_pending // Empty circle (sending, Tor online)
                }
            }
        }
    }

    override fun onViewRecycled(holder: RecyclerView.ViewHolder) {
        super.onViewRecycled(holder)

        // Stop any running animations when view is recycled to prevent crashes
        if (holder is PendingMessageViewHolder) {
            Log.d(TAG, "View recycled - stopping typing animation")
            stopTypingAnimation(holder.typingDot1, holder.typingDot2, holder.typingDot3)
            stopEllipsisAnimation(holder.downloadingText)
        }
    }

    fun setCurrentlyPlayingMessageId(messageId: String?) {
        currentlyPlayingMessageId = messageId
        // Update all items to refresh voice message play/pause icons
        if (itemCount > 0) {
            notifyItemRangeChanged(0, itemCount)
        }
    }

    /**
     * Stop all running animations (call this in onDestroy to prevent memory leaks)
     */
    fun stopAllAnimations() {
        Log.d(TAG, "Stopping all animations in adapter")
        // Stop all ellipsis animations
        ellipsisAnimations.keys.toList().forEach { textView ->
            ellipsisAnimations[textView]?.let { runnable ->
                ellipsisHandler.removeCallbacks(runnable)
            }
        }
        ellipsisAnimations.clear()

        // Remove all pending messages from handler
        ellipsisHandler.removeCallbacksAndMessages(null)
        Log.d(TAG, "All animations stopped")
    }

    fun resetSwipeState() {
        if (currentSwipeRevealedPosition != -1) {
            val oldPosition = currentSwipeRevealedPosition
            currentSwipeRevealedPosition = -1
            notifyItemChanged(oldPosition)
        }
    }

    fun updateMessages(
        newMessages: List<Message>,
        newPendingPings: List<com.securelegion.database.entities.PingInbox> = emptyList(),
        newDownloadingPingIds: Set<String> = emptySet(),
        newAutoPongPingIds: Set<String> = emptySet()
    ) {
        Log.d(TAG, "updateMessages() called: messages=${newMessages.size}, pending=${newPendingPings.size}")

        // Stop all running ellipsis animations
        ellipsisAnimations.keys.toList().forEach { textView ->
            stopEllipsisAnimation(textView)
        }

        // Update state variables
        downloadingPingIds = newDownloadingPingIds
        autoPongPingIds = newAutoPongPingIds

        // Build combined list of ChatListItem objects for DiffUtil to process atomically
        val combinedList = mutableListOf<ChatListItem>()

        // Add all messages
        combinedList.addAll(newMessages.map { ChatListItem.MessageItem(it) })

        // Add all pending pings with their download states (from ping_inbox DB)
        combinedList.addAll(newPendingPings.map { pingInbox ->
            ChatListItem.PendingPingItem(
                pingInbox = pingInbox,
                isDownloading = pingInbox.pingId in newDownloadingPingIds,
                isAutoDownloading = pingInbox.pingId in newAutoPongPingIds
            )
        })

        Log.d(TAG, "Submitting combined list with ${combinedList.size} total items to DiffUtil")

        // Let DiffUtil compute the optimal changes atomically
        submitList(combinedList)
    }

    /**
     * Show popup menu on message long-press with Copy, Delete, and Resend options
     */
    private fun showMessagePopupMenu(view: View, message: Message) {
        val popup = PopupMenu(view.context, view)
        popup.inflate(R.menu.message_actions_menu)

        // Only show "Resend" for failed/pending messages sent by us
        val canResend = message.isSentByMe && (
            message.status == Message.STATUS_FAILED ||
            message.status == Message.STATUS_PENDING ||
            message.status == Message.STATUS_PING_SENT
        )
        popup.menu.findItem(R.id.action_resend)?.isVisible = canResend

        // Hide "Copy" option for image messages (copying base64 string isn't useful)
        if (message.messageType == Message.MESSAGE_TYPE_IMAGE) {
            popup.menu.findItem(R.id.action_copy)?.isVisible = false
        }

        popup.setOnMenuItemClickListener { menuItem ->
            when (menuItem.itemId) {
                R.id.action_resend -> {
                    // Resend failed message
                    onResendMessage?.invoke(message)
                    ThemedToast.show(view.context, "Resending message...")
                    true
                }
                R.id.action_copy -> {
                    // Copy message text
                    val clipboard = view.context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("Message", message.encryptedContent)
                    clipboard.setPrimaryClip(clip)
                    ThemedToast.show(view.context, "Message copied")
                    true
                }
                R.id.action_delete -> {
                    // Delete message
                    onDeleteMessage?.invoke(message)
                    true
                }
                else -> false
            }
        }

        popup.show()
    }

    /**
     * Update voice message playback progress
     * @param messageId The ID of the currently playing message
     * @param currentTime Current playback time in milliseconds
     * @param totalDuration Total duration in milliseconds
     */
    fun updateVoiceProgress(messageId: String, currentTime: Int, totalDuration: Int) {
        val progress = if (totalDuration > 0) {
            ((currentTime.toFloat() / totalDuration.toFloat()) * 100).toInt().coerceIn(0, 100)
        } else {
            0
        }

        // Find the position of this message
        val position = currentList.indexOfFirst { item ->
            (item as? ChatListItem.MessageItem)?.message?.messageId == messageId
        }
        if (position == -1) return

        // Get the ViewHolder for this position
        val holder = recyclerView?.findViewHolderForAdapterPosition(position)

        when (holder) {
            is VoiceSentMessageViewHolder -> {
                // Update progress bar
                holder.progressBar.progress = progress

                // Clip waveform progress using scaleX
                val scale = progress / 100f
                holder.waveformProgress.scaleX = scale
                holder.waveformProgress.pivotX = 0f // Scale from left

                // Update time display
                holder.durationText.text = formatDuration(currentTime / 1000)
            }
            is VoiceReceivedMessageViewHolder -> {
                // Update progress bar
                holder.progressBar.progress = progress

                // Clip waveform progress using scaleX
                val scale = progress / 100f
                holder.waveformProgress.scaleX = scale
                holder.waveformProgress.pivotX = 0f // Scale from left

                // Update time display
                holder.durationText.text = formatDuration(currentTime / 1000)
            }
        }
    }

    /**
     * Reset voice message progress when playback stops
     */
    fun resetVoiceProgress(messageId: String) {
        // Find position in current list
        val position = currentList.indexOfFirst { item ->
            (item as? ChatListItem.MessageItem)?.message?.messageId == messageId
        }
        if (position == -1) return

        val item = getItem(position)
        val message = (item as ChatListItem.MessageItem).message
        val holder = recyclerView?.findViewHolderForAdapterPosition(position)

        when (holder) {
            is VoiceSentMessageViewHolder -> {
                holder.progressBar.progress = 0
                holder.waveformProgress.scaleX = 0f
                holder.waveformProgress.pivotX = 0f
                holder.durationText.text = formatDuration(message.voiceDuration ?: 0)
            }
            is VoiceReceivedMessageViewHolder -> {
                holder.progressBar.progress = 0
                holder.waveformProgress.scaleX = 0f
                holder.waveformProgress.pivotX = 0f
                holder.durationText.text = formatDuration(message.voiceDuration ?: 0)
            }
        }
    }

    private var recyclerView: RecyclerView? = null

    override fun onAttachedToRecyclerView(recyclerView: RecyclerView) {
        super.onAttachedToRecyclerView(recyclerView)
        this.recyclerView = recyclerView
    }

    override fun onDetachedFromRecyclerView(recyclerView: RecyclerView) {
        super.onDetachedFromRecyclerView(recyclerView)
        this.recyclerView = null
    }
}
