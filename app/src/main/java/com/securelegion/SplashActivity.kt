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
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import com.securelegion.crypto.KeyManager

class SplashActivity : AppCompatActivity() {

    private val NOTIFICATION_PERMISSION_REQUEST_CODE = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        // Install Android 12+ splash screen before super.onCreate()
        installSplashScreen()

        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        // TODO: Re-enable FLAG_SECURE after demo recording
        // window.setFlags(
        // WindowManager.LayoutParams.FLAG_SECURE,
        // WindowManager.LayoutParams.FLAG_SECURE
        // )

        // Keep status bar dark gray (matches splash screen theme)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            window.statusBarColor = android.graphics.Color.parseColor("#1C1C1C")
        }

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                Log.i("SplashActivity", "Requesting notification permission")
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST_CODE)
                // Wait for permission result before continuing - initialization will happen in onRequestPermissionsResult
                return
            }
        }

        // Permission already granted or not needed - continue with initialization
        initializeApp()
    }

    private fun initializeApp() {
        // Skip the old splash layout — Android 12+ splash screen is enough
        navigateToNextScreen()
    }

    private fun navigateToNextScreen() {
        try {
            val keyManager = KeyManager.getInstance(this)
            val hasAccount = keyManager.isInitialized()

            if (!hasAccount) {
                // No account - go to WelcomeActivity
                Log.i("SplashActivity", "No account found, navigating to WelcomeActivity")
                val intent = Intent(this, WelcomeActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                startActivity(intent)
            } else {
                // Account exists - go to LockActivity (Tor bootstraps in background via TorService)
                Log.i("SplashActivity", "Account found, navigating to LockActivity")
                val intent = Intent(this, LockActivity::class.java)
                startActivity(intent)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(OVERRIDE_TRANSITION_OPEN, android.R.anim.fade_in, android.R.anim.fade_out)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
            }
            finish()
        } catch (e: Exception) {
            Log.e("SplashActivity", "Error checking account status - going to WelcomeActivity", e)
            val intent = Intent(this, WelcomeActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(OVERRIDE_TRANSITION_OPEN, android.R.anim.fade_in, android.R.anim.fade_out)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
            }
            finish()
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        if (requestCode == NOTIFICATION_PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.i("SplashActivity", "Notification permission granted")
            } else {
                Log.w("SplashActivity", "Notification permission denied - notifications won't be shown")
            }
            // Continue with app initialization after permission is handled
            initializeApp()
        }
    }

}
