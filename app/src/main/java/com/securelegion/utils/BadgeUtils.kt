package com.securelegion.utils

import android.content.Context
import android.view.View
import android.widget.TextView
import com.securelegion.R

object BadgeUtils {

    /**
     * Update the friend request badge count on the Contacts navigation icon
     */
    fun updateFriendRequestBadge(context: Context, rootView: View) {
        try {
            val count = getPendingFriendRequestCount(context)

            setBadge(rootView.findViewById(R.id.friendRequestBadge), count)

        } catch (e: Exception) {
            android.util.Log.e("BadgeUtils", "Failed to update friend request badge", e)
        }
    }

    /**
     * Update the compose/add-friend button badge on the contacts tab
     */
    fun updateComposeBadge(rootView: View, count: Int) {
        try {
            setBadge(rootView.findViewById(R.id.composeBadge), count)
        } catch (e: Exception) {
            android.util.Log.e("BadgeUtils", "Failed to update compose badge", e)
        }
    }

    /**
     * Update the unread messages badge on the Chats navigation icon
     */
    fun updateUnreadMessagesBadge(rootView: View, count: Int) {
        try {
            setBadge(rootView.findViewById(R.id.unreadMessagesBadge), count)
        } catch (e: Exception) {
            android.util.Log.e("BadgeUtils", "Failed to update unread messages badge", e)
        }
    }

    /**
     * Get the pending friend request count from SharedPreferences
     */
    fun getPendingFriendRequestCount(context: Context): Int {
        val prefs = context.getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
        val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()
        return pendingRequestsSet.size
    }

    private fun setBadge(badge: TextView?, count: Int) {
        if (badge != null) {
            if (count > 0) {
                badge.text = if (count > 99) "99+" else count.toString()
                badge.visibility = View.VISIBLE
            } else {
                badge.visibility = View.GONE
            }
        }
    }
}
