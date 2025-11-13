package com.securelegion

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
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
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.crypto.TorManager
import com.securelegion.services.TorService

class SplashActivity : AppCompatActivity() {

    private val BOOTSTRAP_DELAY = 2000L // 2 seconds for Tor bootstrap (first time only)
    private val NOTIFICATION_PERMISSION_REQUEST_CODE = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                Log.i("SplashActivity", "Requesting notification permission")
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST_CODE)
                // Continue with app initialization after permission request
            }
        }

        // Start Tor foreground service for persistent connection (if not already running)
        Log.i("SplashActivity", "Starting Tor foreground service...")
        TorService.start(this)

        // Check if Tor is already connected
        try {
            val torManager = TorManager.getInstance(this)

            // Check if TorService is running and connected
            val torConnected = TorService.isTorConnected()

            if (torConnected && torManager.isInitialized()) {
                // Tor already connected - skip splash screen entirely
                Log.i("SplashActivity", "Tor already connected - skipping splash")
                navigateToLock()
                return
            } else if (TorService.isRunning() && !torConnected) {
                // TorService running but reconnecting - show splash with reconnection status
                Log.i("SplashActivity", "Tor reconnecting - showing splash with status")
                setContentView(R.layout.activity_splash)

                // Animate logo
                val logo = findViewById<View>(R.id.splashLogo)
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

                updateStatus("Reconnecting to Tor network...")

                // Poll for reconnection status
                pollReconnectionStatus()
            } else {
                // First time or phone was off - show splash while bootstrapping
                Log.i("SplashActivity", "Tor not connected - showing splash while bootstrapping")
                setContentView(R.layout.activity_splash)

                // Animate logo
                val logo = findViewById<View>(R.id.splashLogo)
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

                updateStatus("Connecting to Tor network...")

                // Wait for Tor to bootstrap
                Handler(Looper.getMainLooper()).postDelayed({
                    checkTorStatus()
                }, BOOTSTRAP_DELAY)
            }
        } catch (e: Exception) {
            Log.e("SplashActivity", "Error checking Tor status", e)
            // On error, show splash screen
            setContentView(R.layout.activity_splash)
            updateStatus("Initializing...")
            Handler(Looper.getMainLooper()).postDelayed({
                navigateToLock()
            }, 1000)
        }
    }

    private fun checkTorStatus() {
        Log.d("SplashActivity", "Checking Tor status after bootstrap delay...")

        try {
            val torManager = TorManager.getInstance(this)

            if (torManager.isInitialized()) {
                val onionAddress = torManager.getOnionAddress()
                Log.i("SplashActivity", "Tor bootstrapped: $onionAddress")
                updateStatus("Connected to Tor network!")
            } else {
                Log.d("SplashActivity", "Tor still bootstrapping in background...")
                updateStatus("Still connecting...")
            }
        } catch (e: Exception) {
            Log.e("SplashActivity", "Error checking Tor status", e)
            updateStatus("Connection error")
        }

        // Navigate to lock screen (TorService will continue in background if needed)
        navigateToLock()
    }

    private fun updateStatus(status: String) {
        runOnUiThread {
            findViewById<TextView>(R.id.torStatusText)?.text = status
        }
    }

    private fun navigateToLock() {
        Log.d("SplashActivity", "Navigating to LockActivity")
        val intent = Intent(this, LockActivity::class.java)
        startActivity(intent)
        finish()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        if (requestCode == NOTIFICATION_PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.i("SplashActivity", "Notification permission granted")
            } else {
                Log.w("SplashActivity", "Notification permission denied - notifications won't be shown")
            }
        }
    }

    private fun pollReconnectionStatus() {
        // Poll every 500ms to check if Tor has reconnected
        val pollHandler = Handler(Looper.getMainLooper())
        var pollCount = 0
        val maxPolls = 60 // Poll for up to 30 seconds (60 * 500ms)

        val pollRunnable = object : Runnable {
            override fun run() {
                pollCount++

                val torConnected = TorService.isTorConnected()

                if (torConnected) {
                    // Tor reconnected - navigate to lock screen
                    Log.i("SplashActivity", "Tor reconnected successfully")
                    updateStatus("Connected!")
                    Handler(Looper.getMainLooper()).postDelayed({
                        navigateToLock()
                    }, 500)
                } else if (pollCount >= maxPolls) {
                    // Timed out - navigate anyway, TorService will continue trying
                    Log.w("SplashActivity", "Tor reconnection timeout - continuing to app")
                    updateStatus("Still reconnecting...")
                    Handler(Looper.getMainLooper()).postDelayed({
                        navigateToLock()
                    }, 500)
                } else {
                    // Continue polling
                    pollHandler.postDelayed(this, 500)
                }
            }
        }

        // Start polling
        pollHandler.postDelayed(pollRunnable, 500)
    }
}
