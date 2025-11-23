package com.securelegion.utils

import android.content.Context
import android.view.Gravity
import android.view.LayoutInflater
import android.widget.TextView
import android.widget.Toast
import com.securelegion.R

object ThemedToast {
    
    fun show(context: Context, message: String, duration: Int = Toast.LENGTH_SHORT) {
        val inflater = LayoutInflater.from(context)
        val layout = inflater.inflate(R.layout.custom_toast, null)
        
        val textView = layout.findViewById<TextView>(R.id.toastMessage)
        textView.text = message
        
        val toast = Toast(context)
        toast.duration = duration
        toast.view = layout
        toast.setGravity(Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL, 0, 150)
        toast.show()
    }
    
    fun showLong(context: Context, message: String) {
        show(context, message, Toast.LENGTH_LONG)
    }
}
