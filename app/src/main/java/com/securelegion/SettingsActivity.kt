package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        BottomNavigationHelper.setupBottomNavigation(this)
        setupClickListeners()
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Duress PIN
        findViewById<View>(R.id.duressPinItem).setOnClickListener {
            startActivity(Intent(this, DuressPinActivity::class.java))
        }

        // Wallet Identity
        findViewById<View>(R.id.walletIdentityItem).setOnClickListener {
            startActivity(Intent(this, WalletIdentityActivity::class.java))
        }

        // Device Password
        findViewById<View>(R.id.devicePasswordItem).setOnClickListener {
            startActivity(Intent(this, DevicePasswordActivity::class.java))
        }

        // Notifications
        findViewById<View>(R.id.notificationsItem).setOnClickListener {
            startActivity(Intent(this, NotificationsActivity::class.java))
        }

        // About
        findViewById<View>(R.id.aboutItem).setOnClickListener {
            startActivity(Intent(this, AboutActivity::class.java))
        }

        // Wipe Account
        findViewById<View>(R.id.wipeAccountButton).setOnClickListener {
            startActivity(Intent(this, WipeAccountActivity::class.java))
        }
    }
}
