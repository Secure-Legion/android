package com.securelegion

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class NotificationsActivity : AppCompatActivity() {

    private var notificationsEnabled = false
    private var messageContentEnabled = false
    private var soundEnabled = true

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) {
            Log.i("Notifications", "POST_NOTIFICATIONS permission granted")
            notificationsEnabled = true
            saveSettings()
            updateToggleBackground(R.id.toggleNotifications, true)
        } else {
            Log.w("Notifications", "POST_NOTIFICATIONS permission denied")
            notificationsEnabled = false
            saveSettings()
            updateToggleBackground(R.id.toggleNotifications, false)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_notifications)

        loadSettings()
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
            if (!notificationsEnabled) {
                // Trying to enable notifications
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    // Android 13+ requires permission
                    when {
                        ContextCompat.checkSelfPermission(
                            this,
                            Manifest.permission.POST_NOTIFICATIONS
                        ) == PackageManager.PERMISSION_GRANTED -> {
                            // Permission already granted
                            notificationsEnabled = true
                            saveSettings()
                            updateToggleBackground(R.id.toggleNotifications, true)
                        }
                        else -> {
                            // Request permission
                            requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                    }
                } else {
                    // Android 12 and below - no permission needed
                    notificationsEnabled = true
                    saveSettings()
                    updateToggleBackground(R.id.toggleNotifications, true)
                }
            } else {
                // Disabling notifications
                notificationsEnabled = false
                saveSettings()
                updateToggleBackground(R.id.toggleNotifications, false)
            }
        }

        // Toggle Message Content
        findViewById<View>(R.id.toggleMessageContent).setOnClickListener {
            messageContentEnabled = !messageContentEnabled
            saveSettings()
            updateToggleBackground(R.id.toggleMessageContent, messageContentEnabled)
        }

        // Toggle Sound
        findViewById<View>(R.id.toggleSound).setOnClickListener {
            soundEnabled = !soundEnabled
            saveSettings()
            updateToggleBackground(R.id.toggleSound, soundEnabled)
        }
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences("notifications_prefs", Context.MODE_PRIVATE)

        // Check if permission is granted for Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasPermission = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            notificationsEnabled = prefs.getBoolean("notifications_enabled", false) && hasPermission
        } else {
            notificationsEnabled = prefs.getBoolean("notifications_enabled", false)
        }

        messageContentEnabled = prefs.getBoolean("message_content_enabled", false)
        soundEnabled = prefs.getBoolean("sound_enabled", true)

        // Update UI to reflect loaded settings
        updateToggleBackground(R.id.toggleNotifications, notificationsEnabled)
        updateToggleBackground(R.id.toggleMessageContent, messageContentEnabled)
        updateToggleBackground(R.id.toggleSound, soundEnabled)

        Log.i("Notifications", "Loaded settings - Notifications: $notificationsEnabled, Content: $messageContentEnabled, Sound: $soundEnabled")
    }

    private fun saveSettings() {
        val prefs = getSharedPreferences("notifications_prefs", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putBoolean("notifications_enabled", notificationsEnabled)
            putBoolean("message_content_enabled", messageContentEnabled)
            putBoolean("sound_enabled", soundEnabled)
            apply()
        }
        Log.i("Notifications", "Saved settings - Notifications: $notificationsEnabled, Content: $messageContentEnabled, Sound: $soundEnabled")
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
