package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.UnderlineSpan
import android.util.Log
import android.view.View
import android.widget.CheckBox
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.ThemedToast

/**
 * AccountCreatedActivity - Shows recovery seed phrase after successful creation
 * User must confirm they have written down the 12-word seed before continuing.
 */
class AccountCreatedActivity : AppCompatActivity() {

    private val wordViews = mutableListOf<TextView>()
    private lateinit var confirmCheckbox: CheckBox
    private lateinit var continueButton: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            setContentView(R.layout.activity_account_created)

            // Disable back button - user must click Continue
            onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    ThemedToast.show(this@AccountCreatedActivity, "Please write down your keys and tap the button")
                }
            })

            initializeWordViews()
            setupStyledText()
            loadAccountInfo()
            setupClickListeners()
        } catch (e: Exception) {
            Log.e("AccountCreated", "FATAL: Failed to initialize AccountCreatedActivity", e)

            // Show error dialog that won't disappear immediately
            val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("Error Loading Account Info")
                .setMessage("Failed to display account information:\n\n${e.message}\n\n${e.stackTraceToString()}")
                .setPositiveButton("OK") { _, _ ->
                    finish()
                }
                .setCancelable(false)
                .create()
            dialog.show()
        }
    }

    private fun setupStyledText() {
        // Setup warning text with "NOT" in white
        val warningText = "These backup seeds are required to restore your account and will NOT be shown again."
        val spannable = SpannableString(warningText)

        // Find "NOT" and make it white
        val notStart = warningText.indexOf("NOT")
        if (notStart != -1) {
            spannable.setSpan(
                ForegroundColorSpan(0xFFFFFFFF.toInt()),
                notStart,
                notStart + 3,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        // Set gray color for the rest of the text
        spannable.setSpan(
            ForegroundColorSpan(0xFF5C5C5C.toInt()),
            0,
            warningText.length,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )

        // Re-apply white to "NOT" (to override gray)
        if (notStart != -1) {
            spannable.setSpan(
                ForegroundColorSpan(0xFFFFFFFF.toInt()),
                notStart,
                notStart + 3,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        findViewById<TextView>(R.id.warningText).text = spannable

        // Setup checkbox text with underlined "12-word recovery seed phrase"
        val checkboxText = "I have written down my 12-word recovery seed phrase."
        val checkboxSpannable = SpannableString(checkboxText)

        // Find and underline "12-word recovery seed phrase"
        val underlineStart = checkboxText.indexOf("12-word recovery seed phrase")
        if (underlineStart != -1) {
            checkboxSpannable.setSpan(
                UnderlineSpan(),
                underlineStart,
                underlineStart + "12-word recovery seed phrase".length,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        confirmCheckbox.text = checkboxSpannable
    }

    private fun initializeWordViews() {
        wordViews.add(findViewById(R.id.word1))
        wordViews.add(findViewById(R.id.word2))
        wordViews.add(findViewById(R.id.word3))
        wordViews.add(findViewById(R.id.word4))
        wordViews.add(findViewById(R.id.word5))
        wordViews.add(findViewById(R.id.word6))
        wordViews.add(findViewById(R.id.word7))
        wordViews.add(findViewById(R.id.word8))
        wordViews.add(findViewById(R.id.word9))
        wordViews.add(findViewById(R.id.word10))
        wordViews.add(findViewById(R.id.word11))
        wordViews.add(findViewById(R.id.word12))

        confirmCheckbox = findViewById(R.id.confirmCheckbox)
        continueButton = findViewById(R.id.continueButton)

        // Enable button only when checkbox is checked
        confirmCheckbox.setOnCheckedChangeListener { _, isChecked ->
            continueButton.isEnabled = isChecked
            continueButton.alpha = if (isChecked) 1.0f else 0.5f
        }
    }

    private fun loadAccountInfo() {
        try {
            val keyManager = KeyManager.getInstance(this)

            // Load seed phrase
            val seedPhrase = keyManager.getSeedPhrase()
            if (seedPhrase != null) {
                val words = seedPhrase.split(" ")
                if (words.size == 12) {
                    for (i in 0 until 12) {
                        wordViews[i].text = "${i + 1}. ${words[i]}"
                    }
                    Log.i("AccountCreated", "Loaded 12-word seed phrase")
                } else {
                    Log.e("AccountCreated", "Invalid seed phrase word count: ${words.size}")
                }
            } else {
                Log.w("AccountCreated", "Seed phrase not available")
            }

        } catch (e: Exception) {
            Log.e("AccountCreated", "Failed to load account info", e)
            ThemedToast.showLong(this, "Error loading account info")
        }
    }

    private fun setupClickListeners() {
        // Continue button - navigate to MainActivity
        findViewById<View>(R.id.continueButton).setOnClickListener {
            Log.i("AccountCreated", "User confirmed they have written down the keys")

            // Mark seed phrase as confirmed
            val prefs = getSharedPreferences("account_setup", MODE_PRIVATE)
            prefs.edit().putBoolean("seed_phrase_confirmed", true).apply()

            // Clear the seed phrase backup from storage (security)
            val keyManager = KeyManager.getInstance(this)
            keyManager.clearSeedPhraseBackup()

            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
        }
    }

}
