package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView

class AboutActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        // Single source of truth for the displayed version — pulls from
        // BuildConfig so a versionName bump in build.gradle.kts auto-updates
        // this screen without a separate XML edit.
        findViewById<TextView>(R.id.aboutVersionText)?.text =
            "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"

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
