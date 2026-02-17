package com.securelegion

import android.os.Bundle
import android.view.View
import android.widget.RadioButton
import android.widget.RadioGroup
import androidx.appcompat.app.AppCompatActivity

/**
 * Activity for configuring auto-lock timer
 * User can select how long before the app automatically locks after inactivity
 */
class AutoLockActivity : BaseActivity() {

    companion object {
        const val PREF_AUTO_LOCK_TIMEOUT = "auto_lock_timeout_ms"

        // Timeout values in milliseconds
        const val TIMEOUT_30_SECONDS = 30_000L
        const val TIMEOUT_1_MINUTE = 60_000L
        const val TIMEOUT_5_MINUTES = 300_000L
        const val TIMEOUT_15_MINUTES = 900_000L
        const val TIMEOUT_30_MINUTES = 1_800_000L
        const val TIMEOUT_NEVER = -1L

        // Default is 5 minutes
        const val DEFAULT_TIMEOUT = TIMEOUT_5_MINUTES
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auto_lock)

        setupClickListeners()
        BottomNavigationHelper.setupBottomNavigation(this)

        val timerGroup = findViewById<RadioGroup>(R.id.autoLockTimerGroup)
        val timer30s = findViewById<RadioButton>(R.id.timer30Seconds)
        val timer1m = findViewById<RadioButton>(R.id.timer1Minute)
        val timer5m = findViewById<RadioButton>(R.id.timer5Minutes)
        val timer15m = findViewById<RadioButton>(R.id.timer15Minutes)
        val timer30m = findViewById<RadioButton>(R.id.timer30Minutes)
        val timerNever = findViewById<RadioButton>(R.id.timerNever)

        // Load current setting
        val prefs = getSharedPreferences("security", MODE_PRIVATE)
        val currentTimeout = prefs.getLong(PREF_AUTO_LOCK_TIMEOUT, DEFAULT_TIMEOUT)

        // Select current option
        when (currentTimeout) {
            TIMEOUT_30_SECONDS -> timer30s.isChecked = true
            TIMEOUT_1_MINUTE -> timer1m.isChecked = true
            TIMEOUT_5_MINUTES -> timer5m.isChecked = true
            TIMEOUT_15_MINUTES -> timer15m.isChecked = true
            TIMEOUT_30_MINUTES -> timer30m.isChecked = true
            TIMEOUT_NEVER -> timerNever.isChecked = true
            else -> timer5m.isChecked = true // Default
        }

        // Handle selection changes
        timerGroup.setOnCheckedChangeListener { _, checkedId ->
            val selectedTimeout = when (checkedId) {
                R.id.timer30Seconds -> TIMEOUT_30_SECONDS
                R.id.timer1Minute -> TIMEOUT_1_MINUTE
                R.id.timer5Minutes -> TIMEOUT_5_MINUTES
                R.id.timer15Minutes -> TIMEOUT_15_MINUTES
                R.id.timer30Minutes -> TIMEOUT_30_MINUTES
                R.id.timerNever -> TIMEOUT_NEVER
                else -> DEFAULT_TIMEOUT
            }

            // Save selection
            prefs.edit().apply {
                putLong(PREF_AUTO_LOCK_TIMEOUT, selectedTimeout)
                apply()
            }

            // Show confirmation
            val timeoutText = when (selectedTimeout) {
                TIMEOUT_30_SECONDS -> "30 seconds"
                TIMEOUT_1_MINUTE -> "1 minute"
                TIMEOUT_5_MINUTES -> "5 minutes"
                TIMEOUT_15_MINUTES -> "15 minutes"
                TIMEOUT_30_MINUTES -> "30 minutes"
                TIMEOUT_NEVER -> "Never"
                else -> "Unknown"
            }

            com.securelegion.utils.ThemedToast.show(this, "Auto-lock set to $timeoutText")

            // Close activity after selection
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                finish()
            }, 500)
        }
    }

    private fun setupClickListeners() {
        // Back Button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }
}
