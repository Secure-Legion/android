package com.securelegion.utils

import android.os.Build
import android.view.Window
import android.view.WindowManager
import com.google.android.material.bottomsheet.BottomSheetDialog

/**
 * Applies glassmorphic blur effects to windows (dialogs, bottom sheets).
 * Uses native window blur on API 31+ with graceful fallback on older APIs.
 */
object GlassEffect {

    private const val BLUR_RADIUS = 20
    private const val DIM_AMOUNT = 0.4f
    private const val DIM_AMOUNT_FALLBACK = 0.6f

    /**
     * Apply glass blur to a BottomSheetDialog.
     * Call after show() for the window to exist.
     */
    fun applyToBottomSheet(dialog: BottomSheetDialog) {
        dialog.window?.let { applyToWindow(it) }
    }

    /**
     * Apply glass blur to any dialog window.
     */
    fun applyToWindow(window: Window) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.addFlags(WindowManager.LayoutParams.FLAG_BLUR_BEHIND)
            window.attributes = window.attributes.apply {
                blurBehindRadius = BLUR_RADIUS
            }
            window.setDimAmount(DIM_AMOUNT)
        } else {
            // Fallback: slightly darker dim to compensate for no blur
            window.setDimAmount(DIM_AMOUNT_FALLBACK)
        }
    }
}
