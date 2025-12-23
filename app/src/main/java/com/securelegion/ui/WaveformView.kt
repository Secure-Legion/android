package com.securelegion.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import kotlin.math.min
import kotlin.math.sin

/**
 * Circular waveform visualization for voice calls
 * Shows animated bars in a circular pattern representing audio levels
 */
class WaveformView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        strokeWidth = 3f
        strokeCap = Paint.Cap.ROUND
    }

    private val barCount = 60  // Number of bars around the circle
    private val barHeights = FloatArray(barCount) { 0.2f }  // Height of each bar (0.0 to 1.0)
    private var animationPhase = 0f

    // Colors for the waveform (gradient from blue to green)
    private val barColors = intArrayOf(
        0xFF4A9EFF.toInt(),  // Blue
        0xFF58ACF7.toInt(),
        0xFF1BC88B.toInt(),  // Green
        0xFF58ADF9.toInt()
    )

    private val animationRunnable = object : Runnable {
        override fun run() {
            // Update animation phase
            animationPhase += 0.1f
            if (animationPhase > 2 * Math.PI) {
                animationPhase -= (2 * Math.PI).toFloat()
            }

            // Update bar heights with wave pattern
            for (i in barHeights.indices) {
                val angle = (i.toFloat() / barCount) * 2 * Math.PI
                val wave = sin(angle + animationPhase).toFloat()
                barHeights[i] = 0.3f + (wave * 0.4f)  // Range: 0.3 to 0.7
            }

            invalidate()
            postDelayed(this, 50)  // 20 FPS
        }
    }

    init {
        // Start animation
        post(animationRunnable)
    }

    /**
     * Update waveform with audio amplitude (0.0 to 1.0)
     */
    fun updateAmplitude(amplitude: Float) {
        // Scale all bars based on audio amplitude
        val scaledAmplitude = amplitude.coerceIn(0f, 1f)
        for (i in barHeights.indices) {
            val angle = (i.toFloat() / barCount) * 2 * Math.PI
            val wave = sin(angle + animationPhase).toFloat()
            barHeights[i] = (0.2f + (wave * 0.3f)) * (0.5f + scaledAmplitude * 0.5f)
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val centerX = width / 2f
        val centerY = height / 2f
        val radius = min(width, height) / 2f * 0.7f  // 70% of available radius

        // Draw bars in a circle
        for (i in 0 until barCount) {
            val angle = (i.toFloat() / barCount) * 2 * Math.PI - Math.PI / 2
            val barHeight = barHeights[i] * radius * 0.5f  // Bar extends from circle

            // Calculate start and end points
            val startX = centerX + (radius * kotlin.math.cos(angle)).toFloat()
            val startY = centerY + (radius * kotlin.math.sin(angle)).toFloat()
            val endX = centerX + ((radius + barHeight) * kotlin.math.cos(angle)).toFloat()
            val endY = centerY + ((radius + barHeight) * kotlin.math.sin(angle)).toFloat()

            // Color based on position (gradient effect)
            val colorIndex = (i.toFloat() / barCount * (barColors.size - 1)).toInt()
            paint.color = barColors[colorIndex.coerceIn(0, barColors.size - 1)]

            // Draw the bar
            canvas.drawLine(startX, startY, endX, endY, paint)
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        // Stop animation when view is removed
        removeCallbacks(animationRunnable)
    }
}
