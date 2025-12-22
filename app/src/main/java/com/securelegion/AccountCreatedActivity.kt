package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
 * AccountCreatedActivity - Shows account info after successful creation
 * Displays:
 * - Contact card CID
 * - Contact card PIN
 * - Account recovery seed phrase (12 words)
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

            // Load account info
            val friendRequestOnion = keyManager.getFriendRequestOnion()
            val pin = keyManager.getContactPin()

            // Display friend request .onion address (instead of CID)
            if (friendRequestOnion != null) {
                findViewById<TextView>(R.id.contactCardCid).text = friendRequestOnion
                Log.i("AccountCreated", "Friend Request .onion: $friendRequestOnion")
            } else {
                Log.w("AccountCreated", "Friend request .onion not available")
            }

            // Display 10-digit PIN
            if (pin != null) {
                if (pin.length == 10) {
                    // Display all 10 digits
                    findViewById<TextView>(R.id.pinDigit1).text = pin[0].toString()
                    findViewById<TextView>(R.id.pinDigit2).text = pin[1].toString()
                    findViewById<TextView>(R.id.pinDigit3).text = pin[2].toString()
                    findViewById<TextView>(R.id.pinDigit4).text = pin[3].toString()
                    findViewById<TextView>(R.id.pinDigit5).text = pin[4].toString()
                    findViewById<TextView>(R.id.pinDigit6).text = pin[5].toString()
                    findViewById<TextView>(R.id.pinDigit7).text = pin[6].toString()
                    findViewById<TextView>(R.id.pinDigit8).text = pin[7].toString()
                    findViewById<TextView>(R.id.pinDigit9).text = pin[8].toString()
                    findViewById<TextView>(R.id.pinDigit10).text = pin[9].toString()
                    Log.i("AccountCreated", "10-digit PIN: $pin")
                } else {
                    Log.e("AccountCreated", "Invalid PIN length: ${pin.length} (expected 10)")
                }
            } else {
                Log.w("AccountCreated", "PIN not available")
            }

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
        // Make CID clickable to copy
        findViewById<TextView>(R.id.contactCardCid).setOnClickListener {
            val cid = (it as TextView).text.toString()
            copyToClipboard(cid, "CID")
        }

        // Make PIN boxes clickable to copy the full PIN
        val pinClickListener = View.OnClickListener {
            val keyManager = KeyManager.getInstance(this)
            val pin = keyManager.getContactPin()
            if (pin != null) {
                copyToClipboard(pin, "PIN")
            }
        }

        findViewById<View>(R.id.pinDigit1).setOnClickListener(pinClickListener)
        findViewById<View>(R.id.pinDigit2).setOnClickListener(pinClickListener)
        findViewById<View>(R.id.pinDigit3).setOnClickListener(pinClickListener)
        findViewById<View>(R.id.pinDigit4).setOnClickListener(pinClickListener)
        findViewById<View>(R.id.pinDigit5).setOnClickListener(pinClickListener)
        findViewById<View>(R.id.pinDigit6).setOnClickListener(pinClickListener)

        // Also make the PIN container clickable
        findViewById<View>(R.id.pinBoxesContainer).setOnClickListener(pinClickListener)

        // Continue button - navigate to MainActivity
        findViewById<View>(R.id.continueButton).setOnClickListener {
            Log.i("AccountCreated", "User confirmed they have written down the keys")

            // Clear the seed phrase backup from storage (security)
            val keyManager = KeyManager.getInstance(this)
            keyManager.clearSeedPhraseBackup()

            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
        }
    }

    private fun copyToClipboard(text: String, label: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clipboard.setPrimaryClip(clip)
        ThemedToast.show(this, "$label copied to clipboard")
        Log.i("AccountCreated", "$label copied to clipboard")
    }

}
