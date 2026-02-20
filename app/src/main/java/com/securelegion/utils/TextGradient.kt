package com.securelegion.utils

import android.graphics.LinearGradient
import android.graphics.Shader
import android.widget.TextView

/**
 * Applies the silver/metallic gradient to a TextView.
 * Fades from 30% white → full white (center) → 30% white.
 */
object TextGradient {
    fun apply(textView: TextView) {
        textView.post {
            val width = textView.paint.measureText(textView.text.toString())
            if (width > 0) {
                val shader = LinearGradient(
                    0f, 0f, width, 0f,
                    intArrayOf(
                        0x4DFFFFFF.toInt(), // 30% white at edges
                        0xE6FFFFFF.toInt(), // 90% white at center
                        0x4DFFFFFF.toInt()
                    ),
                    floatArrayOf(0f, 0.49f, 1f),
                    Shader.TileMode.CLAMP
                )
                textView.paint.shader = shader
                textView.invalidate()
            }
        }
    }
}
