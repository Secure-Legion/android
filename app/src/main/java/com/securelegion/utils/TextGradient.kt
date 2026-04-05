package com.securelegion.utils

import android.content.res.Configuration
import android.graphics.LinearGradient
import android.graphics.Shader
import android.widget.TextView

/**
 * Applies the silver/metallic gradient to a TextView.
 * Uses white gradient in dark mode, black gradient in light mode.
 */
object TextGradient {
    fun apply(textView: TextView) {
        textView.post {
            val width = textView.paint.measureText(textView.text.toString())
            if (width > 0) {
                val isNightMode = (textView.resources.configuration.uiMode and
                    Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
                val colors = if (isNightMode) {
                    intArrayOf(
                        0x4DFFFFFF.toInt(), // 30% white
                        0xE6FFFFFF.toInt(), // 90% white
                        0x4DFFFFFF.toInt()
                    )
                } else {
                    intArrayOf(
                        0x4D000000.toInt(), // 30% black
                        0xE6000000.toInt(), // 90% black
                        0x4D000000.toInt()
                    )
                }
                val shader = LinearGradient(
                    0f, 0f, width, 0f,
                    colors,
                    floatArrayOf(0f, 0.49f, 1f),
                    Shader.TileMode.CLAMP
                )
                textView.paint.shader = shader
                textView.invalidate()
            }
        }
    }
}
