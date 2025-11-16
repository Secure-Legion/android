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

        // TorManager will start TorService internally when initialized
        Log.i("SplashActivity", "TorManager will handle Tor initialization...")

        // Check if Tor is already initialized
        try {
            val torManager = TorManager.getInstance(this)

            // Check if Tor is already initialized
            if (torManager.isInitialized()) {
                // Tor already connected - skip splash screen entirely
                Log.i("SplashActivity", "Tor already initialized - skipping splash")
                navigateToLock()
                return
            } else {
                // First time or Tor not initialized yet - start Tor and show splash while bootstrapping
                Log.i("SplashActivity", "Tor not initialized - starting Tor...")
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

                // Initialize Tor and wait for it to fully bootstrap
                torManager.initializeAsync { success, onionAddress ->
                    runOnUiThread {
                        if (success) {
                            Log.i("SplashActivity", "Tor fully bootstrapped: $onionAddress")
                            updateStatus("Connected to Tor!")
                            // Small delay to show success message
                            Handler(Looper.getMainLooper()).postDelayed({
                                navigateToLock()
                            }, 500)
                        } else {
                            Log.e("SplashActivity", "Tor initialization failed")
                            updateStatus("Connection failed")
                            // Navigate anyway after a delay
                            Handler(Looper.getMainLooper()).postDelayed({
                                navigateToLock()
                            }, 2000)
                        }
                    }
                }
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

}
