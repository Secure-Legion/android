package com.securelegion

import android.app.Activity
import android.content.Intent
import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.securelegion.utils.BadgeUtils

object BottomNavigationHelper {

    fun setupBottomNavigation(activity: Activity) {
        // Apply system bar insets to bottom nav so gesture bar doesn't overlap
        val bottomNav = activity.findViewById<View>(R.id.bottomNav)
        if (bottomNav != null) {
            WindowCompat.setDecorFitsSystemWindows(activity.window, false)
            val rootView = activity.findViewById<View>(android.R.id.content)
            ViewCompat.setOnApplyWindowInsetsListener(rootView) { _, windowInsets ->
                val insets = windowInsets.getInsets(
                    WindowInsetsCompat.Type.systemBars() or
                    WindowInsetsCompat.Type.displayCutout()
                )
                // Move bottom nav pill ABOVE system bars (margin, not padding)
                // Padding squishes icons inside the fixed-height pill;
                // margin moves the entire pill up while keeping content centered
                val params = bottomNav.layoutParams as android.view.ViewGroup.MarginLayoutParams
                val baseMargin = (20 * activity.resources.displayMetrics.density).toInt()
                params.bottomMargin = baseMargin + insets.bottom
                bottomNav.layoutParams = params
                windowInsets
            }
        }

        // Update badges on the shared nav
        val rootView = activity.findViewById<View>(android.R.id.content)
        BadgeUtils.updateFriendRequestBadge(activity, rootView)

        activity.findViewById<View>(R.id.navMessages)?.setOnClickListener {
            if (activity !is MainActivity) {
                val intent = Intent(activity, MainActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
                activity.startActivity(intent)
                activity.finish()
            }
        }

        activity.findViewById<View>(R.id.navContacts)?.setOnClickListener {
            if (activity is MainActivity) {
                // MainActivity will handle showing contacts tab
            } else {
                val intent = Intent(activity, MainActivity::class.java)
                intent.putExtra("SHOW_CONTACTS", true)
                intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
                activity.startActivity(intent)
                activity.finish()
            }
        }

        activity.findViewById<View>(R.id.navProfile)?.setOnClickListener {
            val intent = Intent(activity, WalletIdentityActivity::class.java)
            activity.startActivity(intent)
        }
    }
}
