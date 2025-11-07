package com.example.securelegion

import android.app.Activity
import android.content.Intent
import android.view.View

object BottomNavigationHelper {

    fun setupBottomNavigation(activity: Activity) {
        activity.findViewById<View>(R.id.navMessages)?.setOnClickListener {
            if (activity !is MainActivity) {
                val intent = Intent(activity, MainActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
                activity.startActivity(intent)
                activity.finish()
            }
        }

        activity.findViewById<View>(R.id.navWallet)?.setOnClickListener {
            if (activity is MainActivity) {
                // Show wallet tab if we're in MainActivity
                (activity as? MainActivity)?.let {
                    // MainActivity will handle showing wallet tab
                }
            } else {
                // Navigate to MainActivity and show wallet
                val intent = Intent(activity, MainActivity::class.java)
                intent.putExtra("SHOW_WALLET", true)
                intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
                activity.startActivity(intent)
                activity.finish()
            }
        }

        activity.findViewById<View>(R.id.navAddFriend)?.setOnClickListener {
            if (activity !is AddFriendActivity) {
                val intent = Intent(activity, AddFriendActivity::class.java)
                activity.startActivity(intent)
            }
        }

        activity.findViewById<View>(R.id.navLock)?.setOnClickListener {
            val intent = Intent(activity, LockActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            activity.startActivity(intent)
            activity.finish()
        }
    }
}
