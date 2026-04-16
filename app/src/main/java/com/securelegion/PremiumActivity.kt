package com.securelegion

import android.os.Bundle
import android.view.View

class PremiumActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_premium)

        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }
}
