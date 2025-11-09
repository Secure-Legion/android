package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class NotificationsActivity : AppCompatActivity() {

    private var notificationsEnabled = true
    private var messageContentEnabled = false
    private var soundEnabled = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_notifications)

        setupBottomNavigation()
        setupToggleSwitches()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }

    private fun setupToggleSwitches() {
        // Toggle Notifications
        findViewById<View>(R.id.toggleNotifications).setOnClickListener {
            notificationsEnabled = !notificationsEnabled
            updateToggleBackground(R.id.toggleNotifications, notificationsEnabled)
            Toast.makeText(this, if (notificationsEnabled) "Notifications enabled" else "Notifications disabled", Toast.LENGTH_SHORT).show()
        }

        // Toggle Message Content
        findViewById<View>(R.id.toggleMessageContent).setOnClickListener {
            messageContentEnabled = !messageContentEnabled
            updateToggleBackground(R.id.toggleMessageContent, messageContentEnabled)
            Toast.makeText(this, if (messageContentEnabled) "Message content enabled" else "Message content disabled", Toast.LENGTH_SHORT).show()
        }

        // Toggle Sound
        findViewById<View>(R.id.toggleSound).setOnClickListener {
            soundEnabled = !soundEnabled
            updateToggleBackground(R.id.toggleSound, soundEnabled)
            Toast.makeText(this, if (soundEnabled) "Sound enabled" else "Sound disabled", Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateToggleBackground(viewId: Int, isActive: Boolean) {
        val toggle = findViewById<View>(viewId)
        toggle.setBackgroundResource(
            if (isActive) R.drawable.toggle_switch_active else R.drawable.toggle_switch_inactive
        )
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
