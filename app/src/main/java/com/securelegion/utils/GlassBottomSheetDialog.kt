package com.securelegion.utils

import android.content.Context
import com.google.android.material.bottomsheet.BottomSheetDialog

/**
 * BottomSheetDialog with glassmorphic blur behind.
 * Automatically applies window blur on API 31+ via GlassEffect.
 */
class GlassBottomSheetDialog(context: Context) : BottomSheetDialog(context) {

    override fun onStart() {
        super.onStart()
        GlassEffect.applyToBottomSheet(this)
    }
}
