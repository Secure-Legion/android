package com.securelegion.adapters

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.BitmapFactory
import android.util.Base64
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

class MessageAdapter(
    private var messages: List<Message> = emptyList(),
    private var pendingPings: List<com.securelegion.models.PendingPing> = emptyList(),
    private var downloadingPingIds: Set<String> = emptySet(),  // Track which pings are being downloaded
    private val onDownloadClick: ((String) -> Unit)? = null,  // Now passes ping ID
    private val onVoicePlayClick: ((Message) -> Unit)? = null,
    private var currentlyPlayingMessageId: String? = null,
    private val onMessageLongClick: (() -> Unit)? = null,
    private val onImageClick: ((String) -> Unit)? = null,  // Base64 image data
    private val onPaymentRequestClick: ((Message) -> Unit)? = null,  // Click on payment request (to pay)
    private val onPaymentDetailsClick: ((Message) -> Unit)? = null,  // Click on completed payment (for details)
    private val onPriceRefreshClick: ((Message, TextView, TextView) -> Unit)? = null,  // Refresh price callback
    private val onDeleteMessage: ((Message) -> Unit)? = null  // Delete single message callback
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    companion object {
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
    private val selectedMessages = mutableSetOf<String>()  // Use String to support both message IDs and ping IDs

    fun setSelectionMode(enabled: Boolean) {
        isSelectionMode = enabled
        if (!enabled) {
            selectedMessages.clear()
        }
        notifyDataSetChanged()
    }

    fun getSelectedMessageIds(): Set<String> = selectedMessages.toSet()

    fun clearSelection() {
        selectedMessages.clear()
        notifyDataSetChanged()
    }

    class SentMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: LinearLayout = view.findViewById(R.id.messageBubble)
        val messageText: TextView = view.findViewById(R.id.messageText)
        val messageStatus: TextView = view.findViewById(R.id.messageStatus)
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
    }

    class VoiceSentMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val voiceBubble: LinearLayout = view.findViewById(R.id.voiceBubble)
        val playButton: ImageView = view.findViewById(R.id.playButton)
        val progressBar: android.widget.ProgressBar = view.findViewById(R.id.progressBar)
        val durationText: TextView = view.findViewById(R.id.durationText)
        val timestampText: TextView = view.findViewById(R.id.timestampText)
        val statusIcon: ImageView = view.findViewById(R.id.statusIcon)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    class VoiceReceivedMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val voiceBubble: LinearLayout = view.findViewById(R.id.voiceBubble)
        val playButton: ImageView = view.findViewById(R.id.playButton)
        val progressBar: android.widget.ProgressBar = view.findViewById(R.id.progressBar)
        val durationText: TextView = view.findViewById(R.id.durationText)
        val timestampText: TextView = view.findViewById(R.id.timestampText)
        val messageCheckbox: CheckBox = view.findViewById(R.id.messageCheckbox)
    }

    class ImageSentMessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val timestampHeader: TextView = view.findViewById(R.id.timestampHeader)
        val messageBubble: CardView = view.findViewById(R.id.messageBubble)
        val messageImage: ImageView = view.findViewById(R.id.messageImage)
        val messageStatus: TextView = view.findViewById(R.id.messageStatus)
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
        val messageStatus: TextView = view.findViewById(R.id.messageStatus)
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
        // Check if this is in the pending messages range (after regular messages)
        if (position >= messages.size) {
            return VIEW_TYPE_PENDING
        }

        val message = messages[position]

        return when {
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
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        return when (viewType) {
            VIEW_TYPE_SENT -> {
                val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_message_sent, parent, false)
                SentMessageViewHolder(view)
            }
            VIEW_TYPE_PENDING -> {
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
        when (holder) {
            is SentMessageViewHolder -> {
                val message = messages[position]
                bindSentMessage(holder, message, position)
            }
            is ReceivedMessageViewHolder -> {
                val message = messages[position]
                bindReceivedMessage(holder, message, position)
            }
            is VoiceSentMessageViewHolder -> {
                val message = messages[position]
                bindVoiceSentMessage(holder, message, position)
            }
            is VoiceReceivedMessageViewHolder -> {
                val message = messages[position]
                bindVoiceReceivedMessage(holder, message, position)
            }
            is ImageSentMessageViewHolder -> {
                val message = messages[position]
                bindImageSentMessage(holder, message, position)
            }
            is ImageReceivedMessageViewHolder -> {
                val message = messages[position]
                bindImageReceivedMessage(holder, message, position)
            }
            is PaymentRequestSentViewHolder -> {
                val message = messages[position]
                bindPaymentRequestSent(holder, message, position)
            }
            is PaymentRequestReceivedViewHolder -> {
                val message = messages[position]
                bindPaymentRequestReceived(holder, message, position)
            }
            is PaymentSentViewHolder -> {
                val message = messages[position]
                bindPaymentSent(holder, message, position)
            }
            is PaymentReceivedViewHolder -> {
                val message = messages[position]
                bindPaymentReceived(holder, message, position)
            }
            is PendingMessageViewHolder -> {
                bindPendingMessage(holder, position)
            }
        }
    }

    private fun bindSentMessage(holder: SentMessageViewHolder, message: Message, position: Int) {
        holder.messageText.text = message.encryptedContent
        holder.messageStatus.text = getStatusIcon(message.status)

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
        val pendingIndex = position - messages.size
        val pendingPing = pendingPings[pendingIndex]
        val timestamp = pendingPing.timestamp

        // Update UI based on ping state
        when (pendingPing.state) {
            com.securelegion.models.PingState.PENDING -> {
                // Show "Download" button
                holder.downloadButton.visibility = View.VISIBLE
                holder.downloadingText.visibility = View.GONE
            }
            com.securelegion.models.PingState.DOWNLOADING -> {
                // Show "Downloading..." text
                holder.downloadButton.visibility = View.GONE
                holder.downloadingText.visibility = View.VISIBLE
                holder.downloadingText.text = "Downloading..."
            }
            com.securelegion.models.PingState.DECRYPTING -> {
                // Show "Decrypting..." text
                holder.downloadButton.visibility = View.GONE
                holder.downloadingText.visibility = View.VISIBLE
                holder.downloadingText.text = "Decrypting..."
            }
            com.securelegion.models.PingState.READY -> {
                // Message is ready to show - this ping should be removed atomically
                // Hide this pending ping entirely (ChatActivity will remove it next refresh)
                holder.itemView.visibility = View.GONE
                holder.itemView.layoutParams?.height = 0
                return
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
            // Use pingId directly as identifier (much simpler and more reliable!)
            val pingIdStr = "ping:" + pendingPing.pingId  // Prefix to distinguish from message IDs
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
                onDownloadClick?.invoke(pendingPing.pingId)  // Pass specific ping ID
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

        // Set status icon
        val statusDrawable = when (message.status) {
            Message.STATUS_PENDING, Message.STATUS_PING_SENT -> R.drawable.ic_timer
            Message.STATUS_SENT, Message.STATUS_DELIVERED -> R.drawable.ic_check
            Message.STATUS_FAILED -> R.drawable.ic_delete
            else -> R.drawable.ic_check
        }
        holder.statusIcon.setImageResource(statusDrawable)

        // Set play/pause icon based on current playback state
        val isPlaying = currentlyPlayingMessageId == message.messageId
        holder.playButton.setImageResource(
            if (isPlaying) R.drawable.ic_pause else R.drawable.ic_play
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
            holder.voiceBubble.setOnLongClickListener(null)

            // Enable play button in normal mode
            holder.playButton.isEnabled = true
            holder.playButton.setOnClickListener {
                onVoicePlayClick?.invoke(message)
            }
        }

        // Reset progress
        holder.progressBar.progress = 0
    }

    private fun bindVoiceReceivedMessage(holder: VoiceReceivedMessageViewHolder, message: Message, position: Int) {
        val duration = message.voiceDuration ?: 0
        holder.durationText.text = formatDuration(duration)
        holder.timestampText.text = formatTime(message.timestamp)

        // Set play/pause icon based on current playback state
        val isPlaying = currentlyPlayingMessageId == message.messageId
        holder.playButton.setImageResource(
            if (isPlaying) R.drawable.ic_pause else R.drawable.ic_play
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
            holder.voiceBubble.setOnLongClickListener(null)

            // Enable play button in normal mode
            holder.playButton.isEnabled = true
            holder.playButton.setOnClickListener {
                onVoicePlayClick?.invoke(message)
            }
        }

        // Reset progress
        holder.progressBar.progress = 0
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

        holder.messageStatus.text = getStatusIcon(message.status)

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
            holder.messageBubble.setOnLongClickListener(null)
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
            holder.messageBubble.setOnLongClickListener(null)
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
        val statusColor = when (status) {
            Message.PAYMENT_STATUS_PAID -> 0xFF00D4AA.toInt()     // Green
            Message.PAYMENT_STATUS_EXPIRED -> 0xFF888888.toInt()  // Gray
            Message.PAYMENT_STATUS_CANCELLED -> 0xFFFF4444.toInt() // Red
            else -> 0xFFFFD93D.toInt()                            // Yellow (pending)
        }
        holder.paymentStatus.setTextColor(statusColor)

        // Set message status
        holder.messageStatus.text = getStatusIcon(message.status)

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
        statusView: TextView?,
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
        statusView: TextView?,
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
            false  // Don't consume touch events - allow RecyclerView scrolling
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

        val currentTimestamp = if (position >= messages.size) {
            // This is a pending ping
            val pendingIndex = position - messages.size
            pendingPings[pendingIndex].timestamp
        } else {
            messages[position].timestamp
        }

        val previousTimestamp = if (position - 1 >= messages.size) {
            // Previous was also a pending ping
            val pendingIndex = position - 1 - messages.size
            pendingPings[pendingIndex].timestamp
        } else {
            messages[position - 1].timestamp
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

    private fun getStatusIcon(status: Int): String {
        return when (status) {
            Message.STATUS_PENDING -> "○"  // Pending
            Message.STATUS_PING_SENT -> "✓"     // Ping sent (1 checkmark)
            Message.STATUS_SENT -> "✓"     // Sent (1 checkmark)
            Message.STATUS_DELIVERED -> "✓✓" // Delivered (2 checkmarks)
            Message.STATUS_READ -> "✓✓"    // Read (2 checkmarks)
            Message.STATUS_FAILED -> "✗"   // Failed
            else -> "✓"  // Default to single checkmark
        }
    }

    override fun getItemCount(): Int {
        return messages.size + pendingPings.size
    }

    fun setCurrentlyPlayingMessageId(messageId: String?) {
        currentlyPlayingMessageId = messageId
        notifyDataSetChanged() // Update all voice message icons
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
        newPendingPings: List<com.securelegion.models.PendingPing> = emptyList(),
        newDownloadingPingIds: Set<String> = emptySet()
    ) {
        // Track old state
        val oldMessageCount = messages.size
        val oldPendingCount = pendingPings.size
        val oldTotalCount = oldMessageCount + oldPendingCount

        // Update state
        messages = newMessages
        pendingPings = newPendingPings
        downloadingPingIds = newDownloadingPingIds

        // Track new state
        val newMessageCount = newMessages.size
        val newPendingCount = newPendingPings.size
        val newTotalCount = newMessageCount + newPendingCount

        // Reset swipe state
        currentSwipeRevealedPosition = -1

        // Notify RecyclerView about specific changes to avoid crashes
        when {
            // Pending pings removed (after downloads or deletions)
            oldPendingCount > 0 && newPendingCount == 0 -> {
                // Notify about message changes if any
                if (newMessageCount != oldMessageCount) {
                    notifyItemRangeChanged(0, newMessageCount)
                }
                // Remove all pending items
                notifyItemRangeRemoved(oldMessageCount, oldPendingCount)
            }
            // Pending pings added
            oldPendingCount == 0 && newPendingCount > 0 -> {
                // Notify about message changes if any
                if (newMessageCount != oldMessageCount) {
                    notifyItemRangeChanged(0, oldMessageCount)
                }
                // Insert new pending items at the end
                notifyItemRangeInserted(newMessageCount, newPendingCount)
            }
            // Pending count changed
            newPendingCount != oldPendingCount -> {
                // Update messages if count changed
                if (newMessageCount != oldMessageCount) {
                    notifyItemRangeChanged(0, kotlin.math.min(newMessageCount, oldMessageCount))
                }
                // Handle pending changes
                if (newPendingCount > oldPendingCount) {
                    notifyItemRangeInserted(oldMessageCount + oldPendingCount, newPendingCount - oldPendingCount)
                } else {
                    notifyItemRangeRemoved(oldMessageCount + newPendingCount, oldPendingCount - newPendingCount)
                }
            }
            // Just messages changed
            newMessageCount > oldMessageCount -> {
                notifyItemRangeInserted(oldMessageCount, newMessageCount - oldMessageCount)
            }
            newMessageCount < oldMessageCount -> {
                notifyItemRangeRemoved(newMessageCount, oldMessageCount - newMessageCount)
            }
            else -> {
                // Same count, just update all
                notifyItemRangeChanged(0, newTotalCount)
            }
        }
    }

    /**
     * Show popup menu on message long-press with Copy and Delete options
     */
    private fun showMessagePopupMenu(view: View, message: Message) {
        val popup = PopupMenu(view.context, view)
        popup.inflate(R.menu.message_actions_menu)

        popup.setOnMenuItemClickListener { menuItem ->
            when (menuItem.itemId) {
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
}
