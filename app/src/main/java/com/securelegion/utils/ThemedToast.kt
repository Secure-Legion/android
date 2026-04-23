package com.securelegion.utils

import android.content.Context
import android.view.Gravity
import android.view.LayoutInflater
import android.widget.TextView
import android.widget.Toast
import com.securelegion.R

object ThemedToast {

    // Bottom nav = 80dp height + 20dp bottom margin → 100dp total. We lift the
    // toast to ~140dp so it clears the nav with ~40dp breathing room. Using dp
    // (density-scaled) keeps this consistent across phones of different densities;
    // the old hardcoded 150px sat INSIDE the nav on any device >1.5x density.
    private const val Y_OFFSET_DP = 140

    fun show(context: Context, message: String, duration: Int = Toast.LENGTH_SHORT) {
        val inflater = LayoutInflater.from(context)
        val layout = inflater.inflate(R.layout.custom_toast, null)

        val textView = layout.findViewById<TextView>(R.id.toastMessage)
        textView.text = message

        val toast = Toast(context)
        toast.duration = duration
        @Suppress("DEPRECATION") // Toast.view removed in API 30+; Snackbar migration pending
        run { toast.view = layout }
        val yOffsetPx = (Y_OFFSET_DP * context.resources.displayMetrics.density).toInt()
        toast.setGravity(Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL, 0, yOffsetPx)

        toast.show()
    }

    fun showLong(context: Context, message: String) {
        show(context, message, Toast.LENGTH_LONG)
    }
}
