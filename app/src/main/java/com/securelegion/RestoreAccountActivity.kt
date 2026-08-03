package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import com.securelegion.utils.RestoreSeedSession
import com.securelegion.utils.ThemedToast
import org.web3j.crypto.MnemonicUtils

class RestoreAccountActivity : AppCompatActivity() {

    private lateinit var seedPhraseInput: EditText
    private lateinit var importButton: TextView
    private var handoffStarted = false

    // BIP39 word list for per-word validation (2048 standard English words)
    private val bip39Words: Set<String> by lazy {
        MnemonicUtils.getWords().toSet()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Make status bar transparent with light icons (matches dark theme)
        @Suppress("DEPRECATION") // edge-to-edge refactor pending
        run { window.statusBarColor = android.graphics.Color.TRANSPARENT }

        setContentView(R.layout.activity_restore_account)

        RestoreSeedSession.clear()
        RestoreSeedSession.clearLegacyDiskCopy(this)

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
        seedPhraseInput = findViewById(R.id.seedPhraseInput)
        importButton = findViewById(R.id.importButton)
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            RestoreSeedSession.clear()
            finish()
        }

        // Import button — validate seed, then go to CreateAccountActivity
        importButton.setOnClickListener {
            val seedPhrase = collectSeedPhrase()

            if (seedPhrase.isEmpty()) {
                ThemedToast.show(this, "Please enter all 12 seed words")
                return@setOnClickListener
            }

            val words = seedPhrase.split(" ")
            if (words.size != 12) {
                ThemedToast.show(this, "Need exactly 12 words (got ${words.size})")
                return@setOnClickListener
            }

            // Check each word individually and report which are invalid
            val invalidWords = mutableListOf<Int>()
            for (i in words.indices) {
                if (!bip39Words.contains(words[i])) {
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

            // Keep the phrase only in this process. If Android kills the process,
            // the user must re-enter it instead of leaving a disk residue.
            RestoreSeedSession.put(seedPhrase)
            seedPhraseInput.text.clear()
            handoffStarted = true

            val intent = Intent(this, CreateAccountActivity::class.java)
            intent.putExtra("is_restore", true)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
        }
    }

    private fun collectSeedPhrase(): String {
        val raw = seedPhraseInput.text.toString().trim().lowercase()
        if (raw.isEmpty()) return ""
        // Normalize whitespace (handles newlines, tabs, multiple spaces)
        val words = raw.split("\\s+".toRegex()).filter { it.isNotEmpty() }
        return words.joinToString(" ")
    }

    override fun onDestroy() {
        if (isFinishing && !handoffStarted) {
            RestoreSeedSession.clear()
        }
        super.onDestroy()
    }

}
