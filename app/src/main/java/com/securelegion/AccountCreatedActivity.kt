package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.UnderlineSpan
import android.util.Log
import android.view.View
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast

/**
 * AccountCreatedActivity - Shows recovery seed phrase after successful creation
 * User must confirm they have written down the 12-word seed before continuing.
 */
class AccountCreatedActivity : AppCompatActivity() {

    private lateinit var seedPhraseBox: TextView
    private lateinit var confirmCheckbox: CheckBox
    private lateinit var continueButton: TextView
    private var seedPhrase: String? = null

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

            initializeViews()
            setupStyledText()
            loadAccountInfo()
            setupClickListeners()
        } catch (e: Exception) {
            Log.e("AccountCreated", "FATAL: Failed to initialize AccountCreatedActivity", e)

            val errorDialog = GlassDialog.builder(this)
                .setTitle("Error Loading Account Info")
                .setMessage("Failed to display account information:\n\n${e.message}\n\n${e.stackTraceToString()}")
                .setPositiveButton("OK") { _, _ ->
                    finish()
                }
                .setCancelable(false)
                .create()
            GlassDialog.show(errorDialog)
        }
    }

    private fun setupStyledText() {
        // Checkbox text with underlined "12-word recovery seed phrase"
        val checkboxText = "I have written down my 12-word recovery seed phrase."
        val checkboxSpannable = SpannableString(checkboxText)
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

    private fun initializeViews() {
        seedPhraseBox = findViewById(R.id.seedPhraseBox)
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

            seedPhrase = keyManager.getSeedPhrase()
            if (seedPhrase != null) {
                val words = seedPhrase!!.split(" ")
                if (words.size == 12) {
                    // Display all words in the single box, centered
                    seedPhraseBox.text = words.joinToString("  ")
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
        // Copy button
        findViewById<View>(R.id.copyButton).setOnClickListener {
            seedPhrase?.let { phrase ->
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Recovery Seed", phrase))
                ThemedToast.show(this, "Seed phrase copied")
            }
        }

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

    private fun showQrDialog(data: String) {
        try {
            val size = 512
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(data, BarcodeFormat.QR_CODE, size, size)
            val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
            for (x in 0 until size) {
                for (y in 0 until size) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
                }
            }

            val imageView = ImageView(this).apply {
                setImageBitmap(bitmap)
                setPadding(48, 48, 48, 48)
                setBackgroundColor(0xFF1C1C1C.toInt())
            }

            val qrDialog = GlassDialog.builder(this)
                .setView(imageView)
                .setPositiveButton("Done", null)
                .create()
            GlassDialog.show(qrDialog)
        } catch (e: Exception) {
            Log.e("AccountCreated", "Failed to generate QR code", e)
            ThemedToast.show(this, "Failed to generate QR code")
        }
    }
}
