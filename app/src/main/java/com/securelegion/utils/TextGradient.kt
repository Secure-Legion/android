package com.securelegion.utils

import android.content.res.Configuration
import android.graphics.LinearGradient
import android.graphics.Shader
import android.widget.TextView

/**
 * Applies the silver/metallic gradient to a TextView.
 * Dark mode: white metallic gradient.
 * Light mode: solid black (no gradient — user preference).
 */
object TextGradient {
    fun apply(textView: TextView) {
        val isNightMode = (textView.resources.configuration.uiMode and
            Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES

        if (!isNightMode) {
            // Light mode: solid black, no gradient
            textView.paint.shader = null
            textView.setTextColor(0xFF000000.toInt())
            return
        }

        // Apply gradient synchronously to avoid one-frame flicker during RecyclerView bind.
        // measureText() works here because the text is already set before apply() is called.
        val width = textView.paint.measureText(textView.text.toString())
        if (width > 0) {
            val shader = LinearGradient(
                0f, 0f, width, 0f,
                intArrayOf(
                    0x4DFFFFFF.toInt(), // 30% white
                    0xE6FFFFFF.toInt(), // 90% white
                    0x4DFFFFFF.toInt()
                ),
                floatArrayOf(0f, 0.49f, 1f),
                Shader.TileMode.CLAMP
            )
            textView.paint.shader = shader
        }
    }
}
