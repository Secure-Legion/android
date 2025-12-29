package com.securelegion.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.securelegion.database.entities.Group
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * RecyclerView adapter for displaying groups list
 * Shows group name, member count, and last activity time
 */
class GroupAdapter(
    private var groups: List<GroupWithMemberCount>,
    private val onGroupClick: (Group) -> Unit
) : RecyclerView.Adapter<GroupAdapter.GroupViewHolder>() {

    /**
     * Data class to hold group with its member count
     */
    data class GroupWithMemberCount(
        val group: Group,
        val memberCount: Int,
        val lastMessagePreview: String? = null
    )

    class GroupViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val groupName: TextView = view.findViewById(R.id.groupName)
        val memberCount: TextView = view.findViewById(R.id.memberCount)
        val lastMessageTime: TextView = view.findViewById(R.id.lastMessageTime)
        val unreadBadge: TextView = view.findViewById(R.id.unreadBadge)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): GroupViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_group, parent, false)
        return GroupViewHolder(view)
    }

    override fun onBindViewHolder(holder: GroupViewHolder, position: Int) {
        val item = groups[position]
        val group = item.group

        // Set group name
        holder.groupName.text = group.name

        // Set member count
        val memberText = if (item.memberCount == 1) {
            "1 member"
        } else {
            "${item.memberCount} members"
        }
        holder.memberCount.text = memberText

        // Set last activity time
        holder.lastMessageTime.text = formatTimestamp(group.lastActivityTimestamp)

        // Hide unread badge for now (TODO: Implement unread message tracking)
        holder.unreadBadge.visibility = View.GONE

        // Set click listener
        holder.itemView.setOnClickListener {
            onGroupClick(group)
        }
    }

    override fun getItemCount() = groups.size

    /**
     * Update the groups list
     */
    fun updateGroups(newGroups: List<GroupWithMemberCount>) {
        groups = newGroups
        notifyDataSetChanged()
    }

    /**
     * Format timestamp to relative time (e.g., "2m", "1h", "Yesterday")
     */
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
                // Show date (e.g., "Jan 15")
                val sdf = SimpleDateFormat("MMM d", Locale.getDefault())
                sdf.format(Date(timestamp))
            }
        }
    }
}
