package com.securelegion

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import com.google.android.material.slider.Slider

class QrSettingsActivity : BaseActivity() {

    private val expiryLabels = arrayOf("15 min", "1 hour", "6 hours", "24 hours", "48 hours", "3 days", "5 days", "7 days")
    private val expiryValuesMs = longArrayOf(
        15 * 60 * 1000L,
        60 * 60 * 1000L,
        6 * 60 * 60 * 1000L,
        24 * 60 * 60 * 1000L,
        48 * 60 * 60 * 1000L,
        3 * 24 * 60 * 60 * 1000L,
        5 * 24 * 60 * 60 * 1000L,
        7 * 24 * 60 * 60 * 1000L
    )

    private val usesLabels = arrayOf("1 use", "3 uses", "5 uses", "10 uses", "25 uses", "50 uses", "Unlimited")
    private val usesValues = intArrayOf(1, 3, 5, 10, 25, 50, 0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_settings)

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }

        setupExpirySlider()
        setupMaxUsesSlider()
    }

    private fun setupExpirySlider() {
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)
        val slider = findViewById<Slider>(R.id.expirySlider)
        val valueText = findViewById<TextView>(R.id.expiryValueText)

        val savedInterval = prefs.getLong("pin_rotation_interval_ms", 24 * 60 * 60 * 1000L)
        val index = expiryValuesMs.indexOf(savedInterval).let { if (it < 0) 3 else it }
        slider.value = index.toFloat()
        valueText.text = expiryLabels[index]

        slider.addOnChangeListener { _, value, fromUser ->
            val i = value.toInt()
            valueText.text = expiryLabels[i]
            if (fromUser) {
                prefs.edit().putLong("pin_rotation_interval_ms", expiryValuesMs[i]).apply()
            }
        }
    }

    private fun setupMaxUsesSlider() {
        val prefs = getSharedPreferences("security_prefs", MODE_PRIVATE)
        val slider = findViewById<Slider>(R.id.maxUsesSlider)
        val valueText = findViewById<TextView>(R.id.maxUsesValueText)

        val savedMaxUses = prefs.getInt("pin_max_uses", 5)
        val index = usesValues.indexOf(savedMaxUses).let { if (it < 0) 2 else it }
        slider.value = index.toFloat()
        valueText.text = usesLabels[index]

        slider.addOnChangeListener { _, value, fromUser ->
            val i = value.toInt()
            valueText.text = usesLabels[i]
            if (fromUser) {
                prefs.edit().putInt("pin_max_uses", usesValues[i]).apply()
            }
        }
    }

}
