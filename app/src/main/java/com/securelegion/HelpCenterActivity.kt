package com.securelegion

import android.os.Bundle
import android.view.View
import com.securelegion.utils.ThemedToast

class HelpCenterActivity : BaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_help_center)

        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        findViewById<View>(R.id.startHelpChatButton).setOnClickListener {
            ThemedToast.show(this, "Help Chat coming soon")
        }
    }
}
