package com.securelegion.utils

import android.content.Context
import android.view.View
import com.securelegion.R

object BadgeUtils {
    
    /**
     * Update the friend request badge count on the Add Friend navigation icon
     * Call this from onResume() in activities that include bottom_navigation
     */
    fun updateFriendRequestBadge(context: Context, rootView: View) {
        try {
            val prefs = context.getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()
            val count = pendingRequestsSet.size

            android.util.Log.d("BadgeUtils", "Updating friend request badge - count: $count")

            val badge = rootView.findViewById<android.widget.TextView>(R.id.friendRequestBadge)
            if (badge != null) {
                android.util.Log.d("BadgeUtils", "Badge view found")
                if (count > 0) {
                    badge.text = count.toString()
                    badge.visibility = View.VISIBLE
                    android.util.Log.d("BadgeUtils", "Badge set to VISIBLE with count: $count")
                } else {
                    badge.visibility = View.GONE
                    android.util.Log.d("BadgeUtils", "Badge set to GONE (no pending requests)")
                }
            } else {
                android.util.Log.w("BadgeUtils", "Badge view not found in layout!")
            }

        } catch (e: Exception) {
            android.util.Log.e("BadgeUtils", "Failed to update friend request badge", e)
        }
    }
}
