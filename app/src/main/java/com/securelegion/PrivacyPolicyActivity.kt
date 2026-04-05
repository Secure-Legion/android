package com.securelegion

import android.os.Bundle
import android.view.View

class PrivacyPolicyActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_privacy_policy)

        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }
}
