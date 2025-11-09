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

        // Start Tor foreground service for persistent connection
        Log.i("SplashActivity", "Starting Tor foreground service...")
        TorService.start(this)

        // Test Tor initialization
        Handler(Looper.getMainLooper()).postDelayed({
            testTorInitialization()
        }, SPLASH_DELAY)
    }

    private fun testTorInitialization() {
        Log.d("SplashActivity", "Testing Tor initialization...")
        val statusText = findViewById<TextView>(R.id.torStatusText)

        try {
            updateStatus("Initializing Tor client...")
            val torManager = TorManager.getInstance(this)
            torManager.initializeAsync { success, onionAddress ->
                runOnUiThread {
                    if (success && onionAddress != null) {
                        val message = "Tor initialized! .onion: $onionAddress"
                        Log.i("SplashActivity", message)
                        updateStatus("Connected to Tor network!")
                        Toast.makeText(this, "Tor connected", Toast.LENGTH_SHORT).show()
                    } else {
                        val message = "Tor initialization failed"
                        Log.e("SplashActivity", message)
                        updateStatus("Connection failed")
                        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
                    }

                    // Navigate to MainActivity after initialization (success or failure)
                    navigateToMain()
                }
            }
        } catch (e: Exception) {
            Log.e("SplashActivity", "Error testing Tor", e)
            updateStatus("Error: ${e.message}")
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_SHORT).show()

            // Navigate to main even if there's an error
            navigateToMain()
        }
    }

    private fun updateStatus(status: String) {
        runOnUiThread {
            findViewById<TextView>(R.id.torStatusText).text = status
        }
    }

    private fun navigateToMain() {
        Handler(Looper.getMainLooper()).postDelayed({
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }, 500) // Small delay to allow Toast to be visible
    }
}
