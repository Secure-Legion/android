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

        // Security Mode
        findViewById<View>(R.id.securityModeItem).setOnClickListener {
            startActivity(Intent(this, SecurityModeActivity::class.java))
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

        // Wipe Account
        findViewById<View>(R.id.wipeAccountButton).setOnClickListener {
            startActivity(Intent(this, WipeAccountActivity::class.java))
        }
    }
}
