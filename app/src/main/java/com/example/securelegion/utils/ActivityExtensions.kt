package com.example.securelegion.utils

import android.app.Activity
import android.content.Intent
import com.example.securelegion.R

fun Activity.startActivityWithSlideAnimation(intent: Intent) {
    startActivity(intent)
    overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left)
}

fun Activity.finishWithSlideAnimation() {
    finish()
    overridePendingTransition(R.anim.slide_in_left, R.anim.slide_out_right)
}

fun Activity.startActivityWithFadeAnimation(intent: Intent) {
    startActivity(intent)
    overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
}

fun Activity.finishWithFadeAnimation() {
    finish()
    overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
}
