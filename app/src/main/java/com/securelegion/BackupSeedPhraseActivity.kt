package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.utils.ThemedToast

class BackupSeedPhraseActivity : AppCompatActivity() {

    private lateinit var seedPhrase: String
    private lateinit var wordViews: List<TextView>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_backup_seed_phrase)

        // Get seed phrase from intent
        seedPhrase = intent.getStringExtra(EXTRA_SEED_PHRASE) ?: ""
        if (seedPhrase.isEmpty()) {
            Log.e(TAG, "No seed phrase provided")
            finish()
            return
        }

        initializeViews()
        displaySeedPhrase()
        setupClickListeners()
    }

    private fun initializeViews() {
        wordViews = listOf(
            findViewById(R.id.word1),
            findViewById(R.id.word2),
            findViewById(R.id.word3),
            findViewById(R.id.word4),
            findViewById(R.id.word5),
            findViewById(R.id.word6),
            findViewById(R.id.word7),
            findViewById(R.id.word8),
            findViewById(R.id.word9),
            findViewById(R.id.word10),
            findViewById(R.id.word11),
            findViewById(R.id.word12)
        )
    }

    private fun displaySeedPhrase() {
        val words = seedPhrase.trim().split("\\s+".toRegex())
        if (words.size != 12) {
            Log.e(TAG, "Invalid seed phrase word count: ${words.size}")
            ThemedToast.showLong(this, "Invalid seed phrase format")
            finish()
            return
        }

        words.forEachIndexed { index, word ->
            if (index < wordViews.size) {
                wordViews[index].text = "${index + 1}. $word"
            }
        }
    }

    private fun setupClickListeners() {
        // Continue button
        findViewById<View>(R.id.continueButton).setOnClickListener {
            Log.d(TAG, "User confirmed seed phrase backup")
            // Go back to CreateAccountActivity to continue with username setup
            finish()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Prevent going back without acknowledging
        ThemedToast.show(
            this,
            "Please write down your seed phrase before continuing"
        )
    }

    companion object {
        private const val TAG = "BackupSeedPhrase"
        const val EXTRA_SEED_PHRASE = "extra_seed_phrase"
    }
}
