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
import android.view.WindowManager
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
    private val BRIDGE_CONFIGURATION_REQUEST_CODE = 1002

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

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

        // Always show splash screen and test actual Tor connectivity
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

        updateStatus("Checking Tor connection...")

        try {
            val torManager = TorManager.getInstance(this)

            // Test actual SOCKS connectivity instead of checking persistent flag
            Thread {
                try {
                    val socksRunning = RustBridge.isSocksProxyRunning()
                    val socksConnected = if (socksRunning) {
                        RustBridge.testSocksConnectivity()
                    } else {
                        false
                    }

                    if (socksConnected) {
                        // SOCKS proxy is running - check if Tor is fully bootstrapped
                        Log.i("SplashActivity", "SOCKS proxy running - checking bootstrap status...")
                        val bootstrapStatus = RustBridge.getBootstrapStatus()

                        if (bootstrapStatus >= 100) {
                            // Tor is fully bootstrapped - run health checks
                            Log.i("SplashActivity", "✓ Tor fully bootstrapped (100%) - running health checks...")
                            runOnUiThread {
                                val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                                progressBar?.progress = 75  // Bootstrap complete = 75%
                                updateStatus("Verifying services...")
                                Handler(Looper.getMainLooper()).postDelayed({
                                    checkTorStatus()
                                }, 500)
                            }
                        } else {
                            // Tor is bootstrapping - wait for 100%
                            Log.i("SplashActivity", "Tor bootstrapping at $bootstrapStatus% - waiting...")
                            runOnUiThread {
                                updateStatus("Connecting to Tor network... ($bootstrapStatus%)")
                            }
                            waitForBootstrap()
                        }
                    } else {
                        // Tor not functional - need to initialize
                        Log.i("SplashActivity", "Tor not connected - initializing...")
                        runOnUiThread {
                            updateStatus("Connecting to Tor network...")
                        }

                        // Initialize Tor and wait for it to fully bootstrap
                        // Start polling for bootstrap progress immediately
                        waitForBootstrap()

                        torManager.initializeAsync { success, onionAddress ->
                            runOnUiThread {
                                if (success) {
                                    Log.i("SplashActivity", "Tor initialized: $onionAddress")
                                    // Bootstrap polling is already running
                                } else {
                                    Log.e("SplashActivity", "Tor initialization failed")
                                    showBridgeConfigurationUI()
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e("SplashActivity", "Error testing Tor connectivity", e)
                    // On error, try initializing Tor
                    runOnUiThread {
                        updateStatus("Connecting to Tor network...")
                    }

                    // Start polling for bootstrap progress immediately
                    waitForBootstrap()

                    torManager.initializeAsync { success, onionAddress ->
                        runOnUiThread {
                            if (success) {
                                Log.i("SplashActivity", "Tor initialized: $onionAddress")
                                // Bootstrap polling is already running
                            } else {
                                Log.e("SplashActivity", "Tor initialization failed")
                                showBridgeConfigurationUI()
                            }
                        }
                    }
                }
            }.start()
        } catch (e: Exception) {
            Log.e("SplashActivity", "Error during Tor check", e)
            updateStatus("Connection error")
            Handler(Looper.getMainLooper()).postDelayed({
                navigateToLock()
            }, 2000)
        }
    }

    private fun checkTorStatus() {
        Log.d("SplashActivity", "Checking Tor status after bootstrap...")

        try {
            val torManager = TorManager.getInstance(this)
            val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)

            // Simple check: Tor initialized and has onion address
            if (!torManager.isInitialized()) {
                Log.d("SplashActivity", "Tor still initializing...")
                updateStatus("Initializing...")
                return
            }

            val onionAddress = torManager.getOnionAddress()
            if (onionAddress == null) {
                Log.d("SplashActivity", "Hidden service not ready yet...")
                updateStatus("Starting service...")
                return
            }

            // Tor is ready! Proceed to lock screen
            Log.i("SplashActivity", "✓ Tor ready: $onionAddress")
            progressBar?.progress = 100
            updateStatus("Connected!")

            Handler(Looper.getMainLooper()).postDelayed({
                navigateToLock()
            }, 500)
        } catch (e: Exception) {
            Log.e("SplashActivity", "Error checking Tor status", e)
            updateStatus("Connection error...")
        }
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

    private fun waitForBootstrap() {
        Thread {
            val maxAttempts = 120 // 120 seconds max (allows time for descriptor uploads)
            var attempts = 0
            var bootstrapComplete = false

            // Check if this is first-time setup (no account/keys exist yet)
            val keyManager = KeyManager.getInstance(this@SplashActivity)
            val isFirstTimeSetup = !keyManager.isInitialized()

            if (isFirstTimeSetup) {
                Log.i("SplashActivity", "First-time setup detected - will skip listener check")
            }

            while (attempts < maxAttempts) {
                try {
                    val status = RustBridge.getBootstrapStatus()

                    // Check if bootstrap is complete
                    if (status >= 100 && !bootstrapComplete) {
                        bootstrapComplete = true
                        if (isFirstTimeSetup) {
                            Log.i("SplashActivity", "✓ Tor bootstrap complete (100%) - proceeding to setup")
                        } else {
                            Log.i("SplashActivity", "✓ Tor bootstrap complete (100%) - waiting for listeners...")
                        }
                    }

                    // Update status display (scale 0-100% to 0-75% for combined progress)
                    runOnUiThread {
                        val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                        if (status < 0) {
                            updateStatus("Starting Tor...")
                            progressBar?.progress = 0
                        } else {
                            // Scale bootstrap 0-100% to 0-75% (reserve 75-100% for service checks)
                            val scaledProgress = (status * 0.75).toInt()
                            updateStatus("Connecting to Tor network... ($scaledProgress%)")
                            progressBar?.progress = scaledProgress
                        }
                    }

                    // After bootstrap, either proceed (first-time) or wait for listeners (existing account)
                    if (bootstrapComplete) {
                        if (isFirstTimeSetup) {
                            // First-time setup: just proceed to lock/account screen
                            // Hidden service will be created after account creation
                            Log.i("SplashActivity", "✓ First-time setup - proceeding without listeners")
                            runOnUiThread {
                                updateStatus("Connected to Tor!")
                                Handler(Looper.getMainLooper()).postDelayed({
                                    navigateToLock()
                                }, 500)
                            }
                            return@Thread
                        } else {
                            // Existing account: wait for messaging to be ready
                            // Start TorService if not already running (ensures it's in this process)
                            if (!TorService.isRunning()) {
                                Log.i("SplashActivity", "Starting TorService...")
                                TorService.start(this@SplashActivity)
                            }

                            if (TorService.isMessagingReady()) {
                                Log.i("SplashActivity", "✓ Messaging fully ready - listeners active")
                                runOnUiThread {
                                    // Run health checks with progress updates (75-100%)
                                    checkTorStatus()
                                }
                                return@Thread
                            } else {
                                // Still waiting for listeners
                                Log.d("SplashActivity", "Waiting for listeners... (attempt $attempts)")
                            }
                        }
                    }

                    Thread.sleep(1000) // Check every second
                    attempts++
                } catch (e: Exception) {
                    Log.e("SplashActivity", "Error checking bootstrap status", e)
                    break
                }
            }

            // Timeout - show bridge configuration
            Log.e("SplashActivity", "Tor bootstrap timeout after $attempts seconds")
            runOnUiThread {
                showBridgeConfigurationUI()
            }
        }.start()
    }

    private fun showBridgeConfigurationUI() {
        Log.w("SplashActivity", "Showing bridge configuration UI due to connection failure")
        updateStatus("Connection failed - Tor may be blocked in your region")

        // Hide progress bar
        findViewById<ProgressBar>(R.id.torProgressBar).visibility = View.GONE

        // Show configure bridges button
        val configureBridgesButton = findViewById<TextView>(R.id.configureBridgesButton)
        configureBridgesButton.visibility = View.VISIBLE
        configureBridgesButton.setOnClickListener {
            Log.i("SplashActivity", "Opening bridge configuration")
            val intent = Intent(this, BridgeActivity::class.java)
            startActivityForResult(intent, BRIDGE_CONFIGURATION_REQUEST_CODE)
        }

        // Show retry button
        val retryButton = findViewById<TextView>(R.id.retryConnectionButton)
        retryButton.visibility = View.VISIBLE
        retryButton.setOnClickListener {
            Log.i("SplashActivity", "Retrying Tor connection with bridge settings")
            retryTorConnection()
        }
    }

    private fun retryTorConnection() {
        // Hide buttons and show progress
        findViewById<TextView>(R.id.configureBridgesButton).visibility = View.GONE
        findViewById<TextView>(R.id.retryConnectionButton).visibility = View.GONE
        findViewById<ProgressBar>(R.id.torProgressBar).visibility = View.VISIBLE
        updateStatus("Retrying connection with bridges...")

        // Note: Currently TorManager doesn't support restarting with new bridge config
        // For now, just retry the connection - bridge support will be added to TorManager
        val torManager = TorManager.getInstance(this)
        torManager.initializeAsync { success, onionAddress ->
            runOnUiThread {
                if (success) {
                    Log.i("SplashActivity", "Tor connected with bridges: $onionAddress")
                    updateStatus("Connected to Tor!")
                    Handler(Looper.getMainLooper()).postDelayed({
                        navigateToLock()
                    }, 500)
                } else {
                    Log.e("SplashActivity", "Tor connection failed again")
                    showBridgeConfigurationUI()
                }
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == BRIDGE_CONFIGURATION_REQUEST_CODE) {
            Log.i("SplashActivity", "Returned from bridge configuration")
            // BridgeActivity already restarted Tor with new config
            // Automatically start monitoring the connection
            updateStatus("Testing bridge connection...")

            // Hide bridge config buttons and show progress
            findViewById<TextView>(R.id.configureBridgesButton).visibility = View.GONE
            findViewById<TextView>(R.id.retryConnectionButton).visibility = View.GONE
            findViewById<ProgressBar>(R.id.torProgressBar).visibility = View.VISIBLE

            // Give Tor a moment to restart (BridgeActivity already initiated restart)
            // Then start monitoring bootstrap progress
            Handler(Looper.getMainLooper()).postDelayed({
                waitForBootstrap()
            }, 2000)
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
        }
    }

}
