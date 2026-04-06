package com.securelegion

import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.TextPaint
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

/**
 * Welcome screen for new users (no wallet exists)
 * Provides options to create a new account or import an existing one
 *
 * Security: This activity is separate from LockActivity to maintain
 * clear separation between authentication and onboarding flows
 */
class WelcomeActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Black status bar with light icons (matches iOS)
        @Suppress("DEPRECATION") // edge-to-edge refactor pending
        run { window.statusBarColor = Color.BLACK }

        setContentView(R.layout.activity_welcome)

        setupClickListeners()
        setupImportText()
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.newAccountButton).setOnClickListener {
            Log.d("WelcomeActivity", "User selected 'Create New Account'")
            val intent = Intent(this, CreateAccountActivity::class.java)
            startActivity(intent)
        }
    }

    private fun setupImportText() {
        val importTextView = findViewById<TextView>(R.id.importText)
        val fullText = "Transferring to a new device? Import"
        val spannableString = SpannableString(fullText)

        // Find the "Import" part and make it clickable
        val importStartIndex = fullText.indexOf("Import")
        if (importStartIndex != -1) {
            val clickableSpan = object : ClickableSpan() {
                override fun onClick(widget: View) {
                    Log.d("WelcomeActivity", "User selected 'Import'")
                    val intent = Intent(this@WelcomeActivity, RestoreAccountActivity::class.java)
                    startActivity(intent)
                }

                override fun updateDrawState(ds: TextPaint) {
                    super.updateDrawState(ds)
                    ds.color = ContextCompat.getColor(this@WelcomeActivity, R.color.text_primary)
                    ds.isUnderlineText = false
                }
            }

            spannableString.setSpan(
                clickableSpan,
                importStartIndex,
                fullText.length,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        // Set the color for the first part
        importTextView.text = spannableString
        importTextView.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
        importTextView.movementMethod = LinkMovementMethod.getInstance()
        importTextView.highlightColor = Color.TRANSPARENT // Remove highlight on click
    }
}
