package com.securelegion.utils

import android.app.Activity
import android.content.Intent
import android.os.Build

fun Activity.startActivityWithSlideAnimation(intent: Intent) {
    startActivity(intent)
}

fun Activity.finishWithSlideAnimation() {
    finish()
}

/**
 * Version-safe slide-in-right-out-left open transition. Uses the newer
 * `overrideActivityTransition` API on 34+ and falls back to the deprecated
 * `overridePendingTransition` on older devices.
 */
fun Activity.applySlideInTransition(enterRes: Int, exitRes: Int) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, enterRes, exitRes)
    } else {
        @Suppress("DEPRECATION")
        overridePendingTransition(enterRes, exitRes)
    }
}
