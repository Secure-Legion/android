package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity

class AboutActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        // setupBottomNavigation() // REMOVED: This layout doesn't have bottom nav
        setupClickListeners()
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }
}
