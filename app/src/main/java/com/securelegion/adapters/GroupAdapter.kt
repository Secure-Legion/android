package com.securelegion.adapters

import android.content.Context
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.database.entities.Group
import com.securelegion.views.AvatarView
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit
import kotlin.math.abs

/**
 * RecyclerView adapter for displaying groups list with swipe actions (Mute, Leave, Pin).
 * Swipe gesture pattern matches ChatAdapter exactly.
 */
class GroupAdapter(
    private var groups: List<GroupWithMemberCount>,
    private val onGroupClick: (Group) -> Unit,
    private val onMuteClick: ((Group) -> Unit)? = null,
    private val onLeaveClick: ((Group) -> Unit)? = null,
    private val onPinClick: ((Group) -> Unit)? = null
) : RecyclerView.Adapter<GroupAdapter.GroupViewHolder>() {

    data class GroupWithMemberCount(
        val group: Group,
        val memberCount: Int,
        val lastMessagePreview: String? = null
    )

    // Track which item is currently swiped open (-1 = none)
    private var openPosition = -1

    class GroupViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val groupAvatar: AvatarView = view.findViewById(R.id.groupAvatar)
        val groupName: TextView = view.findViewById(R.id.groupName)
        val lastMessagePreview: TextView = view.findViewById(R.id.lastMessagePreview)
        val lastMessageTime: TextView = view.findViewById(R.id.lastMessageTime)
        val unreadBadge: TextView = view.findViewById(R.id.unreadBadge)
        val pinIcon: ImageView = view.findViewById(R.id.pinIcon)
        val foreground: View = view.findViewById(R.id.groupItemForeground)
        val actionMute: View = view.findViewById(R.id.actionMute)
        val actionLeave: View = view.findViewById(R.id.actionLeave)
        val actionPin: View = view.findViewById(R.id.actionPin)
        val muteIcon: ImageView = view.findViewById(R.id.muteIcon)
        val muteLabel: TextView = view.findViewById(R.id.muteLabel)
        val pinLabel: TextView = view.findViewById(R.id.pinLabel)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): GroupViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_group, parent, false)
        return GroupViewHolder(view)
    }

    override fun onBindViewHolder(holder: GroupViewHolder, position: Int) {
        val item = groups[position]
        val group = item.group

        // Set group avatar
        holder.groupAvatar.setName(group.name)
        if (!group.groupIcon.isNullOrEmpty()) {
            holder.groupAvatar.setPhotoBase64(group.groupIcon)
        } else {
            holder.groupAvatar.clearPhoto()
        }

        // Set group name
        holder.groupName.text = group.name

        // Set last message preview or member count
        if (!item.lastMessagePreview.isNullOrEmpty()) {
            holder.lastMessagePreview.text = item.lastMessagePreview
        } else {
            val memberText = if (item.memberCount == 1) "1 member" else "${item.memberCount} members"
            holder.lastMessagePreview.text = memberText
        }

        // Set last activity time
        holder.lastMessageTime.text = formatTimestamp(group.lastActivityTimestamp)

        // Show invite badge for pending groups
        if (group.isPendingInvite) {
            holder.unreadBadge.text = "!"
            holder.unreadBadge.visibility = View.VISIBLE
        } else {
            holder.unreadBadge.visibility = View.GONE
        }

        // Show/hide pin icon
        holder.pinIcon.visibility = if (group.isPinned) View.VISIBLE else View.GONE

        // Update mute button label based on current state
        if (group.isMuted) {
            holder.muteLabel.text = "Unmute"
        } else {
            holder.muteLabel.text = "Mute"
        }

        // Update pin button label based on current state
        if (group.isPinned) {
            holder.pinLabel.text = "Unpin"
        } else {
            holder.pinLabel.text = "Pin"
        }

        // Reset foreground position
        holder.foreground.translationX = if (position == openPosition) ACTION_WIDTH else 0f

        // Action button click handlers
        holder.actionMute.setOnClickListener {
            closeItem(holder)
            onMuteClick?.invoke(group)
        }

        holder.actionLeave.setOnClickListener {
            closeItem(holder)
            onLeaveClick?.invoke(group)
        }

        holder.actionPin.setOnClickListener {
            closeItem(holder)
            onPinClick?.invoke(group)
        }

        // Swipe gesture handling (same pattern as ChatAdapter)
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

                    v.parent?.requestDisallowInterceptTouchEvent(false)
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val deltaX = event.rawX - startX

                    if (abs(deltaX) > touchSlop && !isSwiping) {
                        isSwiping = true
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
                            onGroupClick(group)
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

    private fun closeItem(holder: GroupViewHolder) {
        holder.foreground.animate()
            .translationX(0f)
            .setDuration(200)
            .start()
    }

    override fun getItemCount() = groups.size

    fun updateGroups(newGroups: List<GroupWithMemberCount>) {
        groups = newGroups
        notifyDataSetChanged()
    }

    private fun formatTimestamp(timestamp: Long): String {
        val now = System.currentTimeMillis()
        val diff = now - timestamp

        return when {
            diff < TimeUnit.MINUTES.toMillis(1) -> "now"
            diff < TimeUnit.HOURS.toMillis(1) -> {
                val minutes = TimeUnit.MILLISECONDS.toMinutes(diff)
                "${minutes}m"
            }
            diff < TimeUnit.DAYS.toMillis(1) -> {
                val hours = TimeUnit.MILLISECONDS.toHours(diff)
                "${hours}h"
            }
            diff < TimeUnit.DAYS.toMillis(2) -> "Yesterday"
            diff < TimeUnit.DAYS.toMillis(7) -> {
                val days = TimeUnit.MILLISECONDS.toDays(diff)
                "${days}d"
            }
            else -> {
                val sdf = SimpleDateFormat("MMM d", Locale.getDefault())
                sdf.format(Date(timestamp))
            }
        }
    }

    companion object {
        // Width of all 3 action buttons combined (80dp * 3 = 240dp)
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
