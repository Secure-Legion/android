package com.example.securelegion.utils

import android.view.View
import android.view.animation.AnimationUtils
import com.example.securelegion.R

fun View.applyButtonPressEffect() {
    setOnTouchListener { v, event ->
        when (event.action) {
            android.view.MotionEvent.ACTION_DOWN -> {
                val scaleDown = AnimationUtils.loadAnimation(context, R.anim.button_scale_down)
                v.startAnimation(scaleDown)
            }
            android.view.MotionEvent.ACTION_UP, android.view.MotionEvent.ACTION_CANCEL -> {
                val scaleUp = AnimationUtils.loadAnimation(context, R.anim.button_scale_up)
                v.startAnimation(scaleUp)
            }
        }
        false // Return false so click listeners still work
    }
}

fun View.scaleInAnimation() {
    alpha = 0f
    scaleX = 0.8f
    scaleY = 0.8f
    animate()
        .alpha(1f)
        .scaleX(1f)
        .scaleY(1f)
        .setDuration(300)
        .setInterpolator(android.view.animation.OvershootInterpolator())
        .start()
}

fun View.fadeInAnimation(duration: Long = 300) {
    alpha = 0f
    animate()
        .alpha(1f)
        .setDuration(duration)
        .start()
}

fun View.slideInFromRight() {
    translationX = width.toFloat()
    alpha = 0f
    animate()
        .translationX(0f)
        .alpha(1f)
        .setDuration(300)
        .setInterpolator(android.view.animation.DecelerateInterpolator())
        .start()
}

fun View.slideInFromBottom() {
    translationY = height.toFloat()
    alpha = 0f
    animate()
        .translationY(0f)
        .alpha(1f)
        .setDuration(300)
        .setInterpolator(android.view.animation.DecelerateInterpolator())
        .start()
}
