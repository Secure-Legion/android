package com.securelegion

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.view.WindowManager
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import com.securelegion.crypto.KeyManager

class SplashActivity : AppCompatActivity() {

    private val NOTIFICATION_PERMISSION_REQUEST_CODE = 1001
    private val BATTERY_OPTIMIZATION_REQUEST_CODE = 1002

    override fun onCreate(savedInstanceState: Bundle?) {
        // Install Android 12+ splash screen before super.onCreate()
        installSplashScreen()

        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Black status bar (matches splash screen)
        @Suppress("DEPRECATION") // edge-to-edge refactor pending
        run { window.statusBarColor = android.graphics.Color.BLACK }

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
        // Request battery optimization exemption (keeps Tor alive in background)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                Log.i("SplashActivity", "Requesting battery optimization exemption")
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                @Suppress("DEPRECATION")
                startActivityForResult(intent, BATTERY_OPTIMIZATION_REQUEST_CODE)
                return
            }
        }
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
                // Account exists - check if we can skip the lock screen
                val hasUserPassword = keyManager.hasUserDefinedPassword()
                val biometricHelper = com.securelegion.utils.BiometricAuthHelper(this)
                val hasBiometric = biometricHelper.isBiometricEnabled()

                if (!hasUserPassword && !hasBiometric) {
                    // Passwordless account — auto-unlock with system password
                    val systemPassword = keyManager.getSystemPassword()
                    if (systemPassword != null && keyManager.unlockSeed(systemPassword)) {
                        Log.i("SplashActivity", "Auto-unlocked passwordless account")
                        com.securelegion.utils.SessionManager.setUnlocked(this)
                        val intent = Intent(this, MainActivity::class.java)
                        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                        startActivity(intent)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                            overrideActivityTransition(OVERRIDE_TRANSITION_OPEN, android.R.anim.fade_in, android.R.anim.fade_out)
                        } else {
                            @Suppress("DEPRECATION")
                            overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
                        }
                        finish()
                        return
                    } else {
                        Log.e("SplashActivity", "Failed to auto-unlock — falling through to lock screen")
                    }
                }

                // Has password or biometric or auto-unlock failed — show lock screen
                Log.i("SplashActivity", "Navigating to LockActivity")
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

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == BATTERY_OPTIMIZATION_REQUEST_CODE) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val pm = getSystemService(POWER_SERVICE) as PowerManager
                if (pm.isIgnoringBatteryOptimizations(packageName)) {
                    Log.i("SplashActivity", "Battery optimization exemption granted")
                } else {
                    Log.w("SplashActivity", "Battery optimization exemption denied")
                }
            }
            navigateToNextScreen()
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
