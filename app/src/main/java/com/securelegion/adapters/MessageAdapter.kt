package com.securelegion.adapters

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.view.GestureDetector
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.database.entities.Message
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
    private val onMessageLongClick: (() -> Unit)? = null
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    companion object {
        private const val VIEW_TYPE_SENT = 1
        private const val VIEW_TYPE_RECEIVED = 2
        private const val VIEW_TYPE_PENDING = 3
        private const val VIEW_TYPE_VOICE_SENT = 4
        private const val VIEW_TYPE_VOICE_RECEIVED = 5
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

    override fun getItemViewType(position: Int): Int {
        // Check if this is in the pending messages range (after regular messages)
        if (position >= messages.size) {
            return VIEW_TYPE_PENDING
        }

        val message = messages[position]

        return when {
            message.messageType == Message.MESSAGE_TYPE_VOICE && message.isSentByMe -> VIEW_TYPE_VOICE_SENT
            message.messageType == Message.MESSAGE_TYPE_VOICE && !message.isSentByMe -> VIEW_TYPE_VOICE_RECEIVED
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

            // Add long-press listener to enter selection mode
            holder.messageBubble.setOnLongClickListener {
                onMessageLongClick?.invoke()
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

            // Add long-press listener to enter selection mode
            holder.messageBubble.setOnLongClickListener {
                onMessageLongClick?.invoke()
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

        // Reset visibility states for recycled views
        // Check if this ping is currently being downloaded
        val isDownloading = pendingPing.pingId in downloadingPingIds
        if (isDownloading) {
            holder.downloadButton.visibility = View.GONE
            holder.downloadingText.visibility = View.VISIBLE
        } else {
            holder.downloadButton.visibility = View.VISIBLE
            holder.downloadingText.visibility = View.GONE
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

            // Add long-press listener to enter selection mode
            holder.messageBubble.setOnLongClickListener {
                onMessageLongClick?.invoke()
                true
            }

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

            // Add long-press listener to enter selection mode
            holder.voiceBubble.setOnLongClickListener {
                onMessageLongClick?.invoke()
                true
            }

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

            // Add long-press listener to enter selection mode
            holder.voiceBubble.setOnLongClickListener {
                onMessageLongClick?.invoke()
                true
            }

            // Enable play button in normal mode
            holder.playButton.isEnabled = true
            holder.playButton.setOnClickListener {
                onVoicePlayClick?.invoke(message)
            }
        }

        // Reset progress
        holder.progressBar.progress = 0
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
}
