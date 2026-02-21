package com.securelegion.utils

import android.content.Context
import android.view.ViewGroup
import android.widget.Button
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.securelegion.R

/**
 * Factory for creating dialogs with the glass background style.
 *
 * Usage:
 *   GlassDialog.builder(context)
 *       .setTitle("Title")
 *       .setMessage("Body")
 *       .setPositiveButton("OK") { _, _ -> ... }
 *       .show()   // or .create() then .show()
 *
 * Calling show() or create() on the returned builder sets the glass background.
 * After show(), internal panel backgrounds are stripped so only glass_dialog_bg is visible.
 */
object GlassDialog {

    /**
     * Returns a MaterialAlertDialogBuilder pre-configured with the glass background.
     */
    fun builder(context: Context): MaterialAlertDialogBuilder {
        return MaterialAlertDialogBuilder(context)
            .setBackground(ContextCompat.getDrawable(context, R.drawable.glass_dialog_bg))
    }

    /**
     * Takes an already-created AlertDialog, attaches the strip listener, and shows it.
     * Use when you need to call create() first (e.g., to hold a reference before show).
     */
    fun show(dialog: AlertDialog) {
        dialog.setOnShowListener {
            (dialog.window?.decorView as? ViewGroup)?.let { decor ->
                stripChildBackgrounds(decor)
            }
        }
        dialog.show()
    }

    /**
     * Recursively strips backgrounds from all child views inside the dialog's DecorView.
     * Preserves Button backgrounds (ripple/touch feedback).
     * This eliminates the Material3 internal panel outlines.
     */
    private fun stripChildBackgrounds(parent: ViewGroup) {
        for (i in 0 until parent.childCount) {
            val child = parent.getChildAt(i)
            if (child !is Button) {
                child.background = null
            }
            if (child is ViewGroup) {
                stripChildBackgrounds(child)
            }
        }
    }
}
