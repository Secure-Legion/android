package com.securelegion.utils

import android.content.Context
import android.view.Gravity
import android.view.LayoutInflater
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import com.securelegion.R

object ToastUtils {

    @Suppress("DEPRECATION")
    fun showCustomToast(context: Context, message: String, duration: Int = Toast.LENGTH_SHORT) {
        val inflater = LayoutInflater.from(context)
        val layout = inflater.inflate(R.layout.custom_toast, null)

        val toastText = layout.findViewById<TextView>(R.id.toastText)
        val toastIcon = layout.findViewById<ImageView>(R.id.toastIcon)

        toastText.text = message
        toastIcon.setImageResource(R.drawable.ic_check)

        val toast = Toast(context)
        toast.duration = duration
        toast.view = layout
        toast.setGravity(Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL, 0, 120)
        toast.show()
    }
}
