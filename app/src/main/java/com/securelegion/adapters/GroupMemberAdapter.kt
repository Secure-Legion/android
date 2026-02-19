package com.securelegion.adapters

import android.content.Context
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.views.AvatarView
import kotlin.math.abs

/**
 * Data class for a group member displayed in the members list.
 */
data class GroupMemberItem(
    val pubkeyHex: String,
    val displayName: String,
    val role: String,       // "Admin", "Member", "Pending"
    val isMe: Boolean,
    val profilePhotoBase64: String? = null
)

class GroupMemberAdapter(
    private var members: List<GroupMemberItem>,
    private val onMemberClick: (GroupMemberItem) -> Unit,
    private val onMuteClick: (GroupMemberItem) -> Unit,
    private val onRemoveClick: (GroupMemberItem) -> Unit,
    private val onPromoteClick: (GroupMemberItem) -> Unit
) : RecyclerView.Adapter<GroupMemberAdapter.MemberViewHolder>() {

    private var openPosition = -1

    class MemberViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val memberAvatar: AvatarView = view.findViewById(R.id.memberAvatar)
        val memberName: TextView = view.findViewById(R.id.memberName)
        val memberRole: TextView = view.findViewById(R.id.memberRole)
        val foreground: View = view.findViewById(R.id.memberForeground)
        val actionMute: View = view.findViewById(R.id.actionMute)
        val actionRemove: View = view.findViewById(R.id.actionRemove)
        val actionPromote: View = view.findViewById(R.id.actionPromote)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MemberViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_group_member, parent, false)
        return MemberViewHolder(view)
    }

    override fun onBindViewHolder(holder: MemberViewHolder, position: Int) {
        val member = members[position]

        // Avatar
        holder.memberAvatar.setName(member.displayName)
        if (!member.profilePhotoBase64.isNullOrEmpty()) {
            holder.memberAvatar.setPhotoBase64(member.profilePhotoBase64)
        } else {
            holder.memberAvatar.clearPhoto()
        }

        // Name + role
        holder.memberName.text = member.displayName
        holder.memberRole.text = member.role

        // Reset foreground position
        holder.foreground.translationX = if (position == openPosition) ACTION_WIDTH else 0f

        // Disable swipe actions for self
        if (member.isMe) {
            holder.foreground.setOnTouchListener(null)
            holder.foreground.setOnClickListener { onMemberClick(member) }
            return
        }

        // Action button clicks
        holder.actionMute.setOnClickListener {
            closeItem(holder)
            onMuteClick(member)
        }

        holder.actionRemove.setOnClickListener {
            closeItem(holder)
            onRemoveClick(member)
        }

        holder.actionPromote.setOnClickListener {
            closeItem(holder)
            onPromoteClick(member)
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
                        holder.foreground.translationX = newTranslation.coerceIn(0f, ACTION_WIDTH)
                    }
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    v.parent?.requestDisallowInterceptTouchEvent(false)

                    if (!isSwiping) {
                        if (holder.foreground.translationX > 0f) {
                            closeItem(holder)
                            openPosition = -1
                        } else {
                            onMemberClick(member)
                        }
                    } else {
                        val currentTranslation = holder.foreground.translationX
                        val threshold = ACTION_WIDTH * 0.35f

                        if (currentTranslation > threshold) {
                            holder.foreground.animate()
                                .translationX(ACTION_WIDTH)
                                .setDuration(200)
                                .start()
                            openPosition = holder.adapterPosition
                        } else {
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

    private fun closeItem(holder: MemberViewHolder) {
        holder.foreground.animate()
            .translationX(0f)
            .setDuration(200)
            .start()
    }

    override fun getItemCount() = members.size

    fun updateMembers(newMembers: List<GroupMemberItem>) {
        openPosition = -1
        members = newMembers
        notifyDataSetChanged()
    }

    companion object {
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
