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
import androidx.appcompat.widget.SwitchCompat
import androidx.core.content.ContextCompat

class NotificationsActivity : AppCompatActivity() {

    private lateinit var toggleNotifications: SwitchCompat
    private lateinit var toggleMessageContent: SwitchCompat
    private lateinit var toggleSound: SwitchCompat

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) {
            Log.i("Notifications", "POST_NOTIFICATIONS permission granted")
            toggleNotifications.isChecked = true
            saveSettings()
        } else {
            Log.w("Notifications", "POST_NOTIFICATIONS permission denied")
            toggleNotifications.isChecked = false
            saveSettings()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_notifications)

        toggleNotifications = findViewById(R.id.toggleNotifications)
        toggleMessageContent = findViewById(R.id.toggleMessageContent)
        toggleSound = findViewById(R.id.toggleSound)

        setupBackButton()
        loadSettings()
        // setupBottomNavigation() // REMOVED: This layout doesn't have bottom nav
        setupToggleSwitches()
    }

    private fun setupBackButton() {
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }

    private fun setupToggleSwitches() {
        // Toggle Notifications
        toggleNotifications.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                // Trying to enable notifications
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    // Android 13+ requires permission
                    when {
                        ContextCompat.checkSelfPermission(
                            this,
                            Manifest.permission.POST_NOTIFICATIONS
                        ) == PackageManager.PERMISSION_GRANTED -> {
                            // Permission already granted
                            saveSettings()
                        }
                        else -> {
                            // Request permission
                            toggleNotifications.isChecked = false
                            requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                    }
                } else {
                    // Android 12 and below - no permission needed
                    saveSettings()
                }
            } else {
                // Disabling notifications
                saveSettings()
            }
        }

        // Toggle Message Content
        toggleMessageContent.setOnCheckedChangeListener { _, _ ->
            saveSettings()
        }

        // Toggle Sound
        toggleSound.setOnCheckedChangeListener { _, _ ->
            saveSettings()
        }
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences("notifications_prefs", Context.MODE_PRIVATE)

        // Check if permission is granted for Android 13+
        val notificationsEnabled = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasPermission = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            prefs.getBoolean("notifications_enabled", false) && hasPermission
        } else {
            prefs.getBoolean("notifications_enabled", false)
        }

        val messageContentEnabled = prefs.getBoolean("message_content_enabled", false)
        val soundEnabled = prefs.getBoolean("sound_enabled", true)

        // Update UI to reflect loaded settings
        toggleNotifications.isChecked = notificationsEnabled
        toggleMessageContent.isChecked = messageContentEnabled
        toggleSound.isChecked = soundEnabled

        Log.i("Notifications", "Loaded settings - Notifications: $notificationsEnabled, Content: $messageContentEnabled, Sound: $soundEnabled")
    }

    private fun saveSettings() {
        val prefs = getSharedPreferences("notifications_prefs", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putBoolean("notifications_enabled", toggleNotifications.isChecked)
            putBoolean("message_content_enabled", toggleMessageContent.isChecked)
            putBoolean("sound_enabled", toggleSound.isChecked)
            apply()
        }
        Log.i("Notifications", "Saved settings - Notifications: ${toggleNotifications.isChecked}, Content: ${toggleMessageContent.isChecked}, Sound: ${toggleSound.isChecked}")
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
