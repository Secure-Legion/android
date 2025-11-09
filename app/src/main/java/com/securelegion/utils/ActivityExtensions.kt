package com.securelegion.utils

import android.app.Activity
import android.content.Intent

fun Activity.startActivityWithSlideAnimation(intent: Intent) {
    startActivity(intent)
}

fun Activity.finishWithSlideAnimation() {
    finish()
}
