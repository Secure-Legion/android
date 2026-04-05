package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View

class AboutActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        setupClickListeners()
    }

    private fun setupClickListeners() {
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        findViewById<View>(R.id.termsOfServiceItem).setOnClickListener {
            startActivity(Intent(this, TermsOfServiceActivity::class.java))
        }

        findViewById<View>(R.id.privacyPolicyItem).setOnClickListener {
            startActivity(Intent(this, PrivacyPolicyActivity::class.java))
        }
    }
}
