package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.RadioButton
import androidx.appcompat.app.AppCompatDelegate

class AppearanceActivity : BaseActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_appearance)

        val prefs = getSharedPreferences("app_settings", MODE_PRIVATE)
        val currentMode = prefs.getString("app_theme_mode", "system") ?: "system"
        Log.d("Appearance", "Current theme mode: $currentMode, night mode: ${AppCompatDelegate.getDefaultNightMode()}")

        val radioDark = findViewById<RadioButton>(R.id.radioDark)
        val radioLight = findViewById<RadioButton>(R.id.radioLight)
        val radioSystem = findViewById<RadioButton>(R.id.radioSystem)

        // Set current selection (mutually exclusive)
        fun selectRadio(mode: String) {
            radioDark.isChecked = mode == "dark"
            radioLight.isChecked = mode == "light"
            radioSystem.isChecked = mode == "system"
        }
        selectRadio(currentMode)

        fun applyTheme(mode: String) {
            val current = prefs.getString("app_theme_mode", "system") ?: "system"
            if (current == mode) return
            Log.d("Appearance", "Switching to $mode")
            selectRadio(mode)
            prefs.edit().putString("app_theme_mode", mode).commit()

            val target = when (mode) {
                "light" -> AppCompatDelegate.MODE_NIGHT_NO
                "system" -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
                else -> AppCompatDelegate.MODE_NIGHT_YES
            }
            AppCompatDelegate.setDefaultNightMode(target)
        }

        findViewById<View>(R.id.optionDark).setOnClickListener { applyTheme("dark") }
        findViewById<View>(R.id.optionLight).setOnClickListener { applyTheme("light") }
        findViewById<View>(R.id.optionSystem).setOnClickListener { applyTheme("system") }

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
    }
}
