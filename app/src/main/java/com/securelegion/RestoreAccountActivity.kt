package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import com.securelegion.utils.ThemedToast
import org.web3j.crypto.MnemonicUtils

class RestoreAccountActivity : AppCompatActivity() {

    private val seedWords = mutableListOf<EditText>()
    private lateinit var importButton: TextView

    // BIP39 word list for per-word validation (2048 standard English words)
    private val bip39Words: Set<String> by lazy {
        MnemonicUtils.getWords().toSet()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        // TODO: Re-enable FLAG_SECURE after demo recording
        // window.setFlags(
        // WindowManager.LayoutParams.FLAG_SECURE,
        // WindowManager.LayoutParams.FLAG_SECURE
        // )

        // Make status bar transparent with light icons (matches dark theme)
        window.statusBarColor = android.graphics.Color.TRANSPARENT

        setContentView(R.layout.activity_restore_account)

        // Enable edge-to-edge display
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // Handle window insets for proper keyboard behavior
        val rootView = findViewById<View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(rootView) { view, windowInsets ->
            val systemInsets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout()
            )

            // Get IME (keyboard) insets
            val imeInsets = windowInsets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = windowInsets.isVisible(WindowInsetsCompat.Type.ime())

            // Apply bottom inset to root ScrollView
            // Use IME insets when keyboard is visible, otherwise use system insets
            view.setPadding(
                systemInsets.left,
                systemInsets.top,
                systemInsets.right,
                if (imeVisible) imeInsets.bottom else systemInsets.bottom
            )

            windowInsets
        }

        initializeViews()
        setupClickListeners()
    }

    private fun initializeViews() {
        // Initialize all 12 seed word EditTexts
        seedWords.add(findViewById(R.id.word1))
        seedWords.add(findViewById(R.id.word2))
        seedWords.add(findViewById(R.id.word3))
        seedWords.add(findViewById(R.id.word4))
        seedWords.add(findViewById(R.id.word5))
        seedWords.add(findViewById(R.id.word6))
        seedWords.add(findViewById(R.id.word7))
        seedWords.add(findViewById(R.id.word8))
        seedWords.add(findViewById(R.id.word9))
        seedWords.add(findViewById(R.id.word10))
        seedWords.add(findViewById(R.id.word11))
        seedWords.add(findViewById(R.id.word12))

        importButton = findViewById(R.id.importButton)

        // Add per-word BIP39 validation as user types
        val defaultBg = seedWords[0].background
        for (editText in seedWords) {
            editText.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    val word = s.toString().trim().lowercase()
                    if (word.isEmpty()) {
                        // Reset to default
                        editText.setTextColor(0xFFFFFFFF.toInt())
                    } else if (bip39Words.contains(word)) {
                        // Valid BIP39 word — green
                        editText.setTextColor(0xFF00CC66.toInt())
                    } else {
                        // Invalid word — red
                        editText.setTextColor(0xFFFF6666.toInt())
                    }
                }
            })
        }
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Import button — validate seed, then go to CreateAccountActivity
        importButton.setOnClickListener {
            val seedPhrase = collectSeedPhrase()

            if (seedPhrase.isEmpty()) {
                ThemedToast.show(this, "Please enter all 12 seed words")
                return@setOnClickListener
            }

            // Check each word individually and report which are invalid
            val invalidWords = mutableListOf<Int>()
            for (i in seedWords.indices) {
                val word = seedWords[i].text.toString().trim().lowercase()
                if (!bip39Words.contains(word)) {
                    invalidWords.add(i + 1)
                }
            }
            if (invalidWords.isNotEmpty()) {
                val wordNums = invalidWords.joinToString(", ") { "#$it" }
                ThemedToast.show(this, "Invalid word $wordNums — check spelling")
                return@setOnClickListener
            }

            // Validate full seed phrase checksum
            if (!MnemonicUtils.validateMnemonic(seedPhrase)) {
                ThemedToast.show(this, "Invalid seed phrase — checksum failed")
                return@setOnClickListener
            }

            // Store seed temporarily and go to CreateAccountActivity
            val prefs = getSharedPreferences("restore_temp", MODE_PRIVATE)
            prefs.edit().putString("seed_phrase", seedPhrase).apply()

            val intent = Intent(this, CreateAccountActivity::class.java)
            intent.putExtra("is_restore", true)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
        }
    }

    private fun collectSeedPhrase(): String {
        val words = mutableListOf<String>()
        for (editText in seedWords) {
            val word = editText.text.toString().trim()
            if (word.isEmpty()) {
                return ""
            }
            words.add(word)
        }
        return words.joinToString(" ")
    }

}
