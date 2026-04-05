package com.securelegion

import android.os.Bundle
import android.view.View

class TermsOfServiceActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_terms_of_service)

        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }
}
