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
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.crypto.TorManager
import com.securelegion.services.TorService

class SplashActivity : AppCompatActivity() {

    private val BOOTSTRAP_DELAY = 2000L // 2 seconds for Tor bootstrap (first time only)
    private val NOTIFICATION_PERMISSION_REQUEST_CODE = 1001
    private val BRIDGE_CONFIGURATION_REQUEST_CODE = 1002

    override fun onCreate(savedInstanceState: Bundle?) {
        // Install Android 12+ splash screen before super.onCreate()
        installSplashScreen()

        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots and screen recording
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Keep status bar dark gray (matches splash screen theme)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            window.statusBarColor = android.graphics.Color.parseColor("#1C1C1C")
            // Dark icons on light background (removed for dark theme)
            // window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
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
        // TorManager will start TorService internally when initialized
        Log.i("SplashActivity", "TorManager will handle Tor initialization...")

        // Always show splash screen and test actual Tor connectivity
        setContentView(R.layout.activity_splash)

        // Animate logo with subtle pulse
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
            .withEndAction {
                // Start subtle pulse animation while connecting
                logo.animate()
                    .alpha(0.7f)
                    .setDuration(1000)
                    .withEndAction {
                        logo.animate()
                            .alpha(1f)
                            .setDuration(1000)
                            .withEndAction {
                                // Repeat pulse
                                logo.postDelayed({
                                    logo.animate()
                                        .alpha(0.7f)
                                        .setDuration(1000)
                                        .withEndAction {
                                            logo.animate()
                                                .alpha(1f)
                                                .setDuration(1000)
                                                .start()
                                        }
                                        .start()
                                }, 0)
                            }
                            .start()
                    }
                    .start()
            }
            .start()

        updateStatus("Checking Tor connection...")

        try {
            val torManager = TorManager.getInstance(this)

            // Watchdog timer: if checks take >5 seconds and TorService is running, just proceed
            var checksComplete = false
            val watchdogThread = Thread {
                Thread.sleep(5000)  // 5 second timeout
                if (!checksComplete) {
                    Log.w("SplashActivity", "Tor checks taking too long - checking if we can skip...")
                    if (TorService.isRunning()) {
                        Log.i("SplashActivity", "✓ TorService is running - proceeding despite slow checks")
                        runOnUiThread {
                            val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                            progressBar?.progress = 100
                            updateStatus("Connected!")
                            Handler(Looper.getMainLooper()).postDelayed({
                                checksComplete = true  // Prevent double navigation
                                navigateToLock()
                            }, 300)
                        }
                    } else {
                        Log.w("SplashActivity", "Checks timed out and TorService not running - waiting longer")
                    }
                }
            }
            watchdogThread.start()

            // Test actual SOCKS connectivity instead of checking persistent flag
            Thread {
                try {
                    // First, verify Tor control port is actually responding
                    // This catches stale state from previous app termination
                    val controlPortAlive = try {
                        val testSocket = java.net.Socket()
                        testSocket.soTimeout = 2000
                        testSocket.connect(java.net.InetSocketAddress("127.0.0.1", 9051), 2000)
                        testSocket.close()
                        true
                    } catch (e: Exception) {
                        Log.d("SplashActivity", "Control port not responding: ${e.message}")
                        false
                    }

                    if (!controlPortAlive) {
                        // Tor process is not running - need fresh initialization
                        Log.i("SplashActivity", "Tor control port not responding - starting fresh initialization")
                        checksComplete = true  // Stop watchdog
                        runOnUiThread {
                            updateStatus("Starting Tor...")
                        }
                        startFreshTorInitialization(torManager)
                        return@Thread
                    }

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
                            // Tor is fully bootstrapped - check if services are ready
                            Log.i("SplashActivity", "✓ Tor fully bootstrapped (100%) - checking services...")

                            // Check if TorService is already running and ready
                            if (TorService.isRunning() && TorService.isMessagingReady()) {
                                // Everything is ready - skip checks and go straight to app
                                Log.i("SplashActivity", "✓ TorService already running and ready - proceeding immediately")
                                checksComplete = true  // Stop watchdog
                                runOnUiThread {
                                    val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                                    progressBar?.progress = 100
                                    updateStatus("Connected!")
                                    Handler(Looper.getMainLooper()).postDelayed({
                                        navigateToLock()
                                    }, 300)
                                }
                            } else {
                                // Services not ready, run health checks
                                Log.i("SplashActivity", "Services not ready, running health checks...")
                                checksComplete = true  // Stop watchdog (checkTorStatus will handle from here)
                                runOnUiThread {
                                    val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                                    progressBar?.progress = 75
                                    updateStatus("Starting services...")
                                    Handler(Looper.getMainLooper()).postDelayed({
                                        checkTorStatus()
                                    }, 500)
                                }
                            }
                        } else if (bootstrapStatus > 0) {
                            // Tor is bootstrapping - but this could be stale from previous session
                            // Give it a brief chance to make progress, then restart if stuck
                            Log.i("SplashActivity", "Tor bootstrapping at $bootstrapStatus% - verifying progress...")
                            checksComplete = true  // Stop watchdog (we're handling it)

                            val initialStatus = bootstrapStatus
                            Thread.sleep(5000)  // Wait 5 seconds to see if it makes progress

                            val newStatus = RustBridge.getBootstrapStatus()
                            if (newStatus == initialStatus && newStatus < 100) {
                                // No progress in 5 seconds - likely stuck from previous session
                                Log.w("SplashActivity", "Bootstrap stuck at $newStatus% (no progress) - restarting Tor")
                                runOnUiThread {
                                    updateStatus("Restarting Tor...")
                                }
                                Thread.sleep(1000)
                                startFreshTorInitialization(torManager)
                            } else {
                                // Making progress, continue waiting
                                Log.i("SplashActivity", "Bootstrap progressing: $initialStatus% → $newStatus%")
                                runOnUiThread {
                                    updateStatus("Connecting to Tor network... ($newStatus%)")
                                }
                                waitForBootstrap()
                            }
                        } else {
                            // Bootstrap status is 0 or negative - likely stale state
                            Log.w("SplashActivity", "Bootstrap status is $bootstrapStatus - reinitializing")
                            checksComplete = true  // Stop watchdog
                            startFreshTorInitialization(torManager)
                        }
                    } else {
                        // Tor not functional - need to initialize
                        Log.i("SplashActivity", "Tor not connected - initializing...")
                        checksComplete = true  // Stop watchdog
                        startFreshTorInitialization(torManager)
                    }
                } catch (e: Exception) {
                    Log.e("SplashActivity", "Error testing Tor connectivity", e)
                    checksComplete = true  // Stop watchdog
                    // On error, try initializing Tor
                    startFreshTorInitialization(torManager)
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

    private fun startFreshTorInitialization(torManager: TorManager) {
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

    private fun checkTorStatus() {
        Log.d("SplashActivity", "Checking Tor status after bootstrap...")

        Thread {
            try {
                val torManager = TorManager.getInstance(this)
                var retries = 0
                val maxRetries = 10  // Max 10 retries (5 seconds total)

                while (retries < maxRetries) {
                    runOnUiThread {
                        val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                        progressBar?.progress = 90 + retries  // 90-100%
                        updateStatus("Verifying services... (${90 + retries}%)")
                    }

                    // Check if everything is ready
                    if (torManager.isInitialized()) {
                        val onionAddress = torManager.getOnionAddress()
                        if (onionAddress != null) {
                            // All ready!
                            Log.i("SplashActivity", "✓ Tor ready: $onionAddress")
                            runOnUiThread {
                                val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                                progressBar?.progress = 100
                                updateStatus("Connected! (100%)")
                                Handler(Looper.getMainLooper()).postDelayed({
                                    navigateToLock()
                                }, 300)
                            }
                            return@Thread
                        }
                    }

                    // Not ready yet, wait and retry
                    Log.d("SplashActivity", "Services not ready, retry $retries/$maxRetries")
                    Thread.sleep(500)
                    retries++
                }

                // Timeout - proceed anyway or restart
                Log.w("SplashActivity", "Service check timeout after 5 seconds - proceeding to app")
                runOnUiThread {
                    val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                    progressBar?.progress = 100
                    updateStatus("Connected!")
                    Handler(Looper.getMainLooper()).postDelayed({
                        navigateToLock()
                    }, 300)
                }

            } catch (e: Exception) {
                Log.e("SplashActivity", "Error checking Tor status", e)
                runOnUiThread {
                    updateStatus("Connection error, proceeding...")
                    Handler(Looper.getMainLooper()).postDelayed({
                        navigateToLock()
                    }, 1000)
                }
            }
        }.start()
    }

    private fun updateStatus(status: String) {
        runOnUiThread {
            findViewById<TextView>(R.id.torStatusText)?.text = status
        }
    }

    private fun navigateToLock() {
        // Check if account exists before deciding where to go
        try {
            val keyManager = KeyManager.getInstance(this@SplashActivity)
            val hasAccount = keyManager.isInitialized()

            Log.i("SplashActivity", "Account check: hasAccount = $hasAccount")

            if (!hasAccount) {
                // No account - go directly to WelcomeActivity
                Log.i("SplashActivity", "✓ No account found, navigating to WelcomeActivity")
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
            } else {
                // Account exists - go to LockActivity
                Log.i("SplashActivity", "✓ Account found, navigating to LockActivity")
                val intent = Intent(this, LockActivity::class.java)
                startActivity(intent)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    overrideActivityTransition(OVERRIDE_TRANSITION_OPEN, android.R.anim.fade_in, android.R.anim.fade_out)
                } else {
                    @Suppress("DEPRECATION")
                    overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
                }
                finish()
            }
        } catch (e: Exception) {
            // If check fails, assume no account and go to Welcome
            // This prevents lock screen flash when there's an error
            Log.e("SplashActivity", "Error checking account status - assuming no account, going to WelcomeActivity", e)
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

    private fun waitForBootstrap() {
        Thread {
            // Bridge connections are much slower (especially on throttled networks like Iran ~500kbps)
            // Use extended timeouts when bridges are configured to avoid premature restarts
            val torSettings = getSharedPreferences("tor_settings", MODE_PRIVATE)
            val bridgeType = torSettings.getString("bridge_type", "none") ?: "none"
            val usingBridges = bridgeType != "none"
            val sdkInt = android.os.Build.VERSION.SDK_INT

            val maxAttempts = if (usingBridges) 1200 else 480 // 5 min with bridges, 120s without (at 250ms/poll)
            var attempts = 0
            var bootstrapComplete = false

            // Track progress to detect truly stuck state
            var lastProgressStatus = -999
            var stuckCounter = 0
            val maxStuckAttempts = if (usingBridges) {
                1200 // 300s (5 min) at 250ms intervals — bridges on slow networks need extended time
            } else if (sdkInt < 33) {
                48 // 12s for older Android without bridges
            } else {
                60 // 15s for newer Android without bridges
            }

            // Check if this is first-time setup (no account/keys exist yet)
            val keyManager = KeyManager.getInstance(this@SplashActivity)
            val isFirstTimeSetup = !keyManager.isInitialized()

            if (isFirstTimeSetup) {
                Log.i("SplashActivity", "First-time setup detected - will skip listener check")
            }

            while (attempts < maxAttempts) {
                try {
                    val status = RustBridge.getBootstrapStatus()

                    // Track if we're making progress
                    if (status == lastProgressStatus && status > 0 && status < 100) {
                        stuckCounter++
                        if (stuckCounter >= maxStuckAttempts) {
                            val stuckSeconds = maxStuckAttempts / 4 // 250ms * 4 = 1 second
                            Log.w("SplashActivity", "Bootstrap stuck at $status% for ${stuckSeconds}s - restarting Tor")
                            runOnUiThread {
                                updateStatus("Connection stuck, restarting...")
                            }

                            // Stop current Tor instance and restart fresh
                            try {
                                // Give a brief moment for cleanup
                                Thread.sleep(1000)

                                // Restart Tor from scratch
                                Log.i("SplashActivity", "Restarting Tor after stuck detection")
                                val torManager = TorManager.getInstance(this@SplashActivity)
                                startFreshTorInitialization(torManager)
                            } catch (e: Exception) {
                                Log.e("SplashActivity", "Error restarting stuck Tor", e)
                                runOnUiThread {
                                    updateStatus("Restart failed, retrying...")
                                }
                            }
                            return@Thread  // Exit this bootstrap loop
                        }
                    } else {
                        stuckCounter = 0
                        lastProgressStatus = status
                    }

                    // Log every 10th status value for debugging (reduce log spam)
                    if (attempts % 10 == 0) {
                        Log.d("SplashActivity", "Bootstrap status poll #$attempts: $status%")
                    }

                    // Check if bootstrap is complete
                    if (status >= 100 && !bootstrapComplete) {
                        bootstrapComplete = true
                        if (isFirstTimeSetup) {
                            Log.i("SplashActivity", "✓ Tor bootstrap complete (100%) - proceeding to setup")
                        } else {
                            Log.i("SplashActivity", "✓ Tor bootstrap complete (100%) - waiting for listeners...")
                        }
                    }

                    // Update status display (direct 1:1 mapping with bootstrap %)
                    runOnUiThread {
                        val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                        if (status < 0) {
                            Log.d("SplashActivity", "UI: Starting Tor... (status=$status)")
                            updateStatus("Starting Tor...")
                            progressBar?.progress = 0
                        } else {
                            Log.d("SplashActivity", "UI: Updating progress to $status%")
                            updateStatus("Connecting to Tor network... ($status%)")
                            progressBar?.progress = status
                        }
                    }

                    // Once bootstrap complete, proceed immediately (don't wait for listeners)
                    if (bootstrapComplete) {
                        Log.i("SplashActivity", "✓ Tor bootstrap complete - proceeding to app")

                        // Start TorService in background (it will finish initialization while user uses app)
                        if (!TorService.isRunning()) {
                            Log.i("SplashActivity", "Starting TorService in background...")
                            TorService.start(this@SplashActivity)
                        }

                        runOnUiThread {
                            val progressBar = findViewById<ProgressBar>(R.id.torProgressBar)
                            progressBar?.progress = 100
                            updateStatus("Connected!")
                            Handler(Looper.getMainLooper()).postDelayed({
                                navigateToLock()
                            }, 300)
                        }
                        return@Thread
                    }

                    Thread.sleep(250) // Check every 250ms for smoother UI updates
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
            // Continue with app initialization after permission is handled
            initializeApp()
        }
    }

}
