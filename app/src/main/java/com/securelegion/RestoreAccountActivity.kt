package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import com.securelegion.utils.ThemedToast

class RestoreAccountActivity : AppCompatActivity() {

    private val seedWords = mutableListOf<EditText>()
    private lateinit var newPasswordInput: EditText
    private lateinit var confirmPasswordInput: EditText
    private lateinit var togglePassword: ImageView
    private lateinit var toggleConfirmPassword: ImageView
    private lateinit var importButton: TextView

    private var isPasswordVisible = false
    private var isConfirmPasswordVisible = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Make status bar white with dark icons
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            @Suppress("DEPRECATION")
            window.statusBarColor = android.graphics.Color.WHITE
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
        }

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
                0,
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

        newPasswordInput = findViewById(R.id.newPasswordInput)
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput)
        togglePassword = findViewById(R.id.togglePassword)
        toggleConfirmPassword = findViewById(R.id.toggleConfirmPassword)
        importButton = findViewById(R.id.importButton)
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Password visibility toggles
        togglePassword.setOnClickListener {
            isPasswordVisible = !isPasswordVisible
            if (isPasswordVisible) {
                newPasswordInput.inputType = InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                newPasswordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            newPasswordInput.setSelection(newPasswordInput.text.length)
        }

        toggleConfirmPassword.setOnClickListener {
            isConfirmPasswordVisible = !isConfirmPasswordVisible
            if (isConfirmPasswordVisible) {
                confirmPasswordInput.inputType = InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                confirmPasswordInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            confirmPasswordInput.setSelection(confirmPasswordInput.text.length)
        }

        // Import button
        importButton.setOnClickListener {
            val seedPhrase = collectSeedPhrase()
            val newPassword = newPasswordInput.text.toString()
            val confirmPassword = confirmPasswordInput.text.toString()

            if (seedPhrase.isEmpty()) {
                ThemedToast.show(this, "Please enter all 12 seed words")
                return@setOnClickListener
            }

            if (newPassword.isEmpty()) {
                ThemedToast.show(this, "Please enter a new password")
                return@setOnClickListener
            }

            if (newPassword != confirmPassword) {
                ThemedToast.show(this, "Passwords do not match")
                return@setOnClickListener
            }

            // Validate password requirements
            if (newPassword.length < 9) {
                ThemedToast.show(this, "Password must be at least 9 characters")
                return@setOnClickListener
            }

            if (!newPassword.any { it.isUpperCase() }) {
                ThemedToast.show(this, "Password must contain an uppercase letter")
                return@setOnClickListener
            }

            if (!newPassword.any { it.isLowerCase() }) {
                ThemedToast.show(this, "Password must contain a lowercase letter")
                return@setOnClickListener
            }

            if (!newPassword.any { it.isDigit() }) {
                ThemedToast.show(this, "Password must contain a number")
                return@setOnClickListener
            }

            if (!newPassword.any { it in "!@#$%^&*" }) {
                ThemedToast.show(this, "Password must contain a special character (!@#$%^&*)")
                return@setOnClickListener
            }

            restoreAccount(seedPhrase, newPassword)
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

    private fun restoreAccount(seedPhrase: String, password: String) {
        // TODO: Implement actual account restoration with seed phrase
        // This should:
        // 1. Validate the seed phrase using BIP39
        // 2. Derive the private key from the seed phrase
        // 3. Encrypt and store the private key with the new password
        // 4. Import contacts and CID only (as per the UI text)

        ThemedToast.show(this, "Account restored successfully!")

        // Clear inputs
        for (editText in seedWords) {
            editText.text.clear()
        }
        newPasswordInput.text.clear()
        confirmPasswordInput.text.clear()

        // Navigate to MainActivity
        val intent = Intent(this, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}
