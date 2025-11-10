package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.View
import android.view.animation.Animation
import android.view.animation.AnimationUtils
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.crypto.TorManager
import com.securelegion.services.TorService

class SplashActivity : AppCompatActivity() {

    private val SPLASH_DELAY = 2000L // 2 seconds

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        // Animate logo
        val logo = findViewById<View>(R.id.splashLogo)
        val appName = findViewById<View>(R.id.appName)

        // Scale and fade in animation for logo
        logo.alpha = 0f
        logo.scaleX = 0.5f
        logo.scaleY = 0.5f
        logo.animate()
            .alpha(1f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(800)
            .setInterpolator(android.view.animation.OvershootInterpolator())
            .start()

        // Fade in app name
        appName.alpha = 0f
        appName.animate()
            .alpha(1f)
            .setDuration(600)
            .setStartDelay(400)
            .start()

        // Start Tor foreground service for persistent connection (if not already running)
        Log.i("SplashActivity", "Starting Tor foreground service...")
        TorService.start(this)

        // Check Tor status without re-initializing
        Handler(Looper.getMainLooper()).postDelayed({
            checkTorStatus()
        }, SPLASH_DELAY)
    }

    private fun checkTorStatus() {
        Log.d("SplashActivity", "Checking Tor status...")

        try {
            val torManager = TorManager.getInstance(this)

            // Check if already initialized (don't re-initialize)
            if (torManager.isInitialized()) {
                val onionAddress = torManager.getOnionAddress()
                Log.i("SplashActivity", "Tor already running: $onionAddress")
                updateStatus("Connected to Tor network!")
            } else {
                Log.d("SplashActivity", "Tor initializing in background service...")
                updateStatus("Connecting to Tor...")
            }
        } catch (e: Exception) {
            Log.e("SplashActivity", "Error checking Tor status", e)
            updateStatus("Checking connection...")
        }

        // Navigate to main screen (TorService will continue in background)
        navigateToMain()
    }

    private fun updateStatus(status: String) {
        runOnUiThread {
            findViewById<TextView>(R.id.torStatusText).text = status
        }
    }

    private fun navigateToMain() {
        Handler(Looper.getMainLooper()).postDelayed({
            // Always go to lock screen first for authentication
            Log.d("SplashActivity", "Tor connected, navigating to LockActivity")
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }, 500) // Small delay to allow Toast to be visible
    }
}
